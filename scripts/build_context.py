"""Turn Semgrep SARIF findings into LLM-ready context packs.

For each finding we locate the enclosing Java method with tree-sitter and
extract the method body, class fields, imports, and the rule's message. The
goal is to give the verifier enough local context without sending whole files.

Usage:
  python build_context.py --sarif out/baseline_secaudit.sarif \
      --out out/contexts.jsonl
"""

import argparse
import json
import re
from pathlib import Path

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

JAVA = Language(tsjava.language())
PARSER = Parser(JAVA)

METHOD_TYPES = {"method_declaration", "constructor_declaration"}
CLASS_TYPES = {"class_declaration", "interface_declaration", "enum_declaration"}
JAVA_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "new", "super", "this",
    "throw", "try", "synchronized", "assert", "case", "do", "else", "instanceof",
}


def extract_cwes(rule: dict, result: dict) -> list[int]:
    texts: list[str] = []
    for source in (rule.get("properties", {}), result.get("properties", {})):
        if not isinstance(source, dict):
            continue
        for key in ("cwe", "tags"):
            value = source.get(key)
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, list):
                texts.extend(str(item) for item in value)

    cwes: set[int] = set()
    for text in texts:
        for match in re.finditer(r"CWE-(\d+)", text, re.IGNORECASE):
            cwes.add(int(match.group(1)))
    return sorted(cwes)


def find_enclosing_method(root, line: int):
    """Return the smallest method/constructor node containing the 1-based line."""
    best = None
    stack = [root]
    while stack:
        node = stack.pop()
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        if start <= line <= end and node.type in METHOD_TYPES:
            if best is None or (node.end_byte - node.start_byte) < (
                best.end_byte - best.start_byte
            ):
                best = node
        stack.extend(node.children)
    return best


def find_ancestor(node, types: set[str]):
    current = node.parent
    while current is not None:
        if current.type in types:
            return current
        current = current.parent
    return None


def get_name(node) -> str | None:
    name = node.child_by_field_name("name")
    return name.text.decode("utf-8", errors="replace") if name else None


def collect_imports(root) -> list[str]:
    imports = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_declaration":
            imports.append(node.text.decode("utf-8", errors="replace").strip())
        stack.extend(node.children)
    return imports


def collect_callees(root, method, max_callees: int = 3) -> list[dict]:
    """Include same-file helper methods called by the flagged method.

    Benchmark test cases often move taint through an inner-class helper such as
    ``doSomething``. Without its body the verifier can only answer "uncertain".
    """
    method_text = method.text.decode("utf-8", errors="replace")
    call_names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", method_text))
    call_names -= JAVA_KEYWORDS
    current_name = get_name(method)
    if current_name:
        call_names.discard(current_name)

    callees: list[dict] = []
    stack = [root]
    while stack and len(callees) < max_callees:
        node = stack.pop()
        if node.type == "method_declaration" and node != method:
            name = get_name(node)
            if name in call_names:
                class_node = find_ancestor(node, CLASS_TYPES)
                callees.append(
                    {
                        "class_name": get_name(class_node) if class_node else None,
                        "method_name": name,
                        "code": node.text.decode("utf-8", errors="replace"),
                        "start_line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                    }
                )
        stack.extend(node.children)
    return callees


def infer_source_root(path: Path) -> Path | None:
    parts = path.parts
    for index in range(len(parts) - 2):
        if parts[index : index + 3] == ("src", "main", "java"):
            return Path(*parts[: index + 3])
    return None


def resolve_type_file(type_name: str, imports: list[str], source_root: Path) -> Path | None:
    candidates: list[str] = []
    if "." in type_name:
        candidates.append(type_name)
    else:
        for declaration in imports:
            match = re.match(r"import\s+([\w.]+)\s*;", declaration)
            if match and match.group(1).endswith("." + type_name):
                candidates.append(match.group(1))

    for candidate in candidates:
        path = source_root / (candidate.replace(".", "/") + ".java")
        if path.exists():
            return path
    return None


def find_method(root, name: str):
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "method_declaration" and get_name(node) == name:
            return node
        stack.extend(node.children)
    return None


def collect_external_callees(
    method,
    imports: list[str],
    source_root: Path | None,
    external_cache: dict[str, bytes],
    max_callees: int = 2,
) -> list[dict]:
    """Resolve simple ``Type var = new Type(...); var.method(...)`` helpers.

    The Benchmark has cases where the taint passes through a helper in another
    class (for example SeparateClassRequest.getTheValue returns a constant).
    Without the body the verifier has to guess, which causes false positives.
    """
    if source_root is None:
        return []

    method_text = method.text.decode("utf-8", errors="replace")
    receivers: dict[str, str] = {}
    for match in re.finditer(
        r"([A-Za-z_][\w.]*)\s+([A-Za-z_]\w*)\s*=\s*new\s+([A-Za-z_][\w.]*)",
        method_text,
    ):
        _, variable, new_type = match.groups()
        receivers[variable] = new_type

    calls: list[tuple[str, str]] = []
    for variable, type_name in receivers.items():
        for match in re.finditer(
            rf"\b{re.escape(variable)}\s*\.\s*([A-Za-z_]\w*)\s*\(", method_text
        ):
            calls.append((type_name, match.group(1)))
    for match in re.finditer(
        r"new\s+([A-Za-z_][\w.]*)\s*\(\s*\)\s*\.\s*([A-Za-z_]\w*)\s*\(",
        method_text,
    ):
        calls.append((match.group(1), match.group(2)))

    callees: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for type_name, method_name in calls:
        key = (type_name, method_name)
        if key in seen:
            continue
        seen.add(key)

        path = resolve_type_file(type_name, imports, source_root)
        if path is None:
            continue
        path_key = str(path)
        if path_key not in external_cache:
            external_cache[path_key] = path.read_bytes()

        external_root = PARSER.parse(external_cache[path_key]).root_node
        target = find_method(external_root, method_name)
        if target is None:
            continue

        class_node = find_ancestor(target, CLASS_TYPES)
        code = target.text.decode("utf-8", errors="replace")
        callees.append(
            {
                "class_name": get_name(class_node) if class_node else type_name.split(".")[-1],
                "method_name": method_name,
                "code": code[:6000],
                "start_line": target.start_point[0] + 1,
                "end_line": target.end_point[0] + 1,
                "source": "external",
            }
        )
        if len(callees) >= max_callees:
            break
    return callees


def collect_class_fields(class_node) -> str:
    """Field declarations directly under the class body (no method bodies)."""
    if class_node is None:
        return ""
    body = class_node.child_by_field_name("body")
    if body is None:
        return ""
    fields = []
    for child in body.children:
        if child.type == "field_declaration":
            fields.append(child.text.decode("utf-8", errors="replace"))
    return "\n".join(fields)


def get_package(root) -> str:
    for child in root.children:
        if child.type == "package_declaration":
            text = child.text.decode("utf-8", errors="replace")
            return text.removeprefix("package").removesuffix(";").strip()
    return ""


def build_pack(
    source: bytes,
    line: int,
    max_chars: int,
    source_root: Path | None = None,
    external_cache: dict[str, bytes] | None = None,
) -> dict:
    tree = PARSER.parse(source)
    root = tree.root_node
    method = find_enclosing_method(root, line)
    imports = collect_imports(root)

    if method is None:
        lines = source.decode("utf-8", errors="replace").splitlines()
        start = max(0, line - 31)
        end = min(len(lines), line + 30)
        code = "\n".join(lines[start:end])
        return {
            "method_name": None,
            "class_name": None,
            "package": get_package(root),
            "imports": imports,
            "fields": "",
            "code": code,
            "callees": [],
            "truncated": False,
            "method_start_line": start + 1,
            "method_end_line": end,
        }

    class_node = find_ancestor(method, CLASS_TYPES)
    code = method.text.decode("utf-8", errors="replace")
    truncated = False
    if len(code) > max_chars:
        # Keep a window around the finding instead of cutting from the top.
        m_start = method.start_point[0] + 1
        rel = line - m_start
        lines = code.splitlines()
        lo = max(0, rel - 60)
        hi = min(len(lines), rel + 61)
        code = "\n".join(lines[lo:hi])
        truncated = True

    callees = collect_callees(root, method)
    callees += collect_external_callees(
        method,
        imports,
        source_root,
        external_cache if external_cache is not None else {},
    )

    return {
        "method_name": get_name(method),
        "class_name": get_name(class_node) if class_node else None,
        "package": get_package(root),
        "imports": imports,
        "fields": collect_class_fields(class_node),
        "code": code,
        "callees": callees,
        "truncated": truncated,
        "method_start_line": method.start_point[0] + 1,
        "method_end_line": method.end_point[0] + 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-chars", type=int, default=8000)
    parser.add_argument("--source-root", type=Path, default=None)
    args = parser.parse_args()

    sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    source_root = args.source_root
    if source_root is None:
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                uri = location.get("artifactLocation", {}).get("uri", "")
                if uri:
                    source_root = infer_source_root(Path(uri))
                    if source_root is not None:
                        break
            if source_root is not None:
                break
    print(f"source root: {source_root}")

    source_cache: dict[str, bytes] = {}
    external_cache: dict[str, bytes] = {}
    seen: set[tuple[str, str, int]] = set()
    total = 0
    written = 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as out:
        for run in sarif.get("runs", []):
            rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}
            for result in run.get("results", []):
                total += 1
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                uri = location.get("artifactLocation", {}).get("uri", "")
                line = location.get("region", {}).get("startLine", 1)
                match = re.search(r"(BenchmarkTest\d+)", uri)
                if not match:
                    continue

                rule_id = result.get("ruleId", "<unknown>")
                key = (match.group(1), rule_id, line)
                if key in seen:
                    continue
                seen.add(key)

                path = Path(uri)
                if not path.exists():
                    print(f"skip missing file: {uri}")
                    continue
                if uri not in source_cache:
                    source_cache[uri] = path.read_bytes()

                rule = rules.get(rule_id, {})
                pack = build_pack(
                    source_cache[uri],
                    line,
                    args.max_chars,
                    source_root,
                    external_cache,
                )
                record = {
                    "id": f"{match.group(1)}|{rule_id}|{line}",
                    "test_name": match.group(1),
                    "rule_id": rule_id,
                    "rule_message": result.get("message", {}).get("text", ""),
                    "cwes": extract_cwes(rule, result),
                    "file": uri,
                    "line": line,
                    **pack,
                }
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                written += 1

    print(f"SARIF results: {total}")
    print(f"unique context packs: {written}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()

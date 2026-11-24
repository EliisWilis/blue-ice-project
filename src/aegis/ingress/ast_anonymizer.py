"""Opt-in, AST-based identifier renaming for fenced Markdown code.

This helper is deliberately disabled by default. Code transformation can change
program semantics (including APIs, reflection, serialized names, or external
interfaces), so callers must never enable it automatically. Any replacement
map should be managed by the caller in its vault/session and must not be logged.

When enabled, only Python/JavaScript/TypeScript/Go fenced blocks are considered.
Tree-sitter and a matching grammar are optional runtime dependencies; absent or
unsupported dependencies cause an unchanged, fail-closed result. The helper
never applies textual/regular-expression substitutions to source code.

Parsing is synchronous and bounded per block. Async callers should move this
CPU work off their event loop (for example, to a worker thread) if needed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = ["anonymize_code_blocks"]

_MAX_BLOCK_BYTES = 1_048_576
_LANGUAGE_ALIASES = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "typescript": "typescript",
    "tsx": "typescript",
    "go": "go",
    "golang": "go",
}
_IDENTIFIER_NODE_TYPES = frozenset({"identifier", "type_identifier"})
_KEYWORDS = {
    "python": frozenset(
        "False None True and as assert async await break class continue def del elif "
        "else except finally for from global if import in is lambda nonlocal not or "
        "pass raise return try while with yield".split()
    ),
    "javascript": frozenset(
        "await break case catch class const continue debugger default delete do else "
        "export extends false finally for function if import in instanceof let new null "
        "return super switch this throw true try typeof var void while with yield".split()
    ),
    "typescript": frozenset(
        "abstract any as asserts await boolean break case catch class const "
        "constructor continue debugger declare default delete do else enum export "
        "extends false finally for from function get if implements import in infer "
        "instanceof interface is keyOf let module namespace never new null number "
        "object package private protected public readonly require global return set "
        "static string super switch symbol this throw true try type typeof var void "
        "while with yield".split()
    ),
    "go": frozenset(
        "break case chan const continue default defer else fallthrough for func go "
        "goto if import interface map package range return select struct switch type var".split()
    ),
}


def anonymize_code_blocks(
    text: str,
    mapping: Mapping[str, str] | None = None,
    enabled: bool = False,
) -> tuple[str, int]:
    """Rename explicitly mapped identifiers in supported Markdown code fences.

    Args:
        text: Markdown input. Non-code text and unsupported fences are preserved.
        mapping: Caller-owned ``original_identifier -> replacement_identifier``
            map, typically held in a vault/session. It is never retained or logged.
        enabled: Explicit opt-in. False (the default) returns ``(text, 0)``.

    Returns:
        A tuple of transformed Markdown and the number of identifier occurrences
        renamed. If parsing is unavailable, a block is malformed/oversized, or a
        transformed block does not parse cleanly, that block is left unchanged.

    Warning:
        Renaming can alter semantics and must not be enabled automatically.
        Callers are responsible for choosing names that preserve their intended
        behavior and for handling this synchronous, potentially CPU-bound helper.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not enabled or not mapping:
        return text, 0

    try:
        lines = text.splitlines(keepends=True)
        # splitlines() returns [] for an empty string, which is the desired result.
        output: list[str] = []
        total_renamed = 0
        index = 0
        while index < len(lines):
            opening = _fence_open(lines[index])
            if opening is None:
                output.append(lines[index])
                index += 1
                continue

            fence_char, fence_width, language = opening
            close_index = index + 1
            while close_index < len(lines) and not _is_closing_fence(
                lines[close_index], fence_char, fence_width
            ):
                close_index += 1

            if close_index == len(lines):
                # An unterminated fence is ambiguous; preserve it and the rest.
                output.extend(lines[index:])
                break

            output.append(lines[index])
            body = lines[index + 1 : close_index]
            if language is not None:
                transformed, renamed = _rename_block("".join(body), language, mapping)
                output.append(transformed)
                total_renamed += renamed
            else:
                output.extend(body)
            output.append(lines[close_index])
            index = close_index + 1

        return "".join(output), total_renamed
    except Exception:
        # Fail closed: return the original payload without exposing/logging it.
        return text, 0


def _fence_open(line: str) -> tuple[str, int, str | None] | None:
    content = _without_line_ending(line)
    indent = len(content) - len(content.lstrip(" "))
    if indent > 3 or indent == len(content):
        return None
    marker = content[indent]
    if marker not in ("`", "~"):
        return None
    end = indent
    while end < len(content) and content[end] == marker:
        end += 1
    width = end - indent
    if width < 3:
        return None

    info = content[end:].strip()
    # Per Markdown, backticks are forbidden in a backtick fence's info string.
    if marker == "`" and "`" in info:
        return None
    first_word = info.split(None, 1)[0].casefold() if info else ""
    language = _LANGUAGE_ALIASES.get(first_word)
    return marker, width, language


def _is_closing_fence(line: str, marker: str, minimum_width: int) -> bool:
    content = _without_line_ending(line)
    indent = len(content) - len(content.lstrip(" "))
    if indent > 3 or indent == len(content) or content[indent] != marker:
        return False
    end = indent
    while end < len(content) and content[end] == marker:
        end += 1
    return end - indent >= minimum_width and not content[end:].strip()


def _without_line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith(("\n", "\r")):
        return line[:-1]
    return line


def _rename_block(
    source: str,
    language: str,
    mapping: Mapping[str, str],
) -> tuple[str, int]:
    source_bytes = source.encode("utf-8")
    if len(source_bytes) > _MAX_BLOCK_BYTES:
        return source, 0

    parser = _make_parser(language)
    if parser is None:
        return source, 0

    try:
        tree = parser.parse(source_bytes)
        root = tree.root_node
        if root.has_error:
            return source, 0
        edits: list[tuple[int, int, bytes]] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in _IDENTIFIER_NODE_TYPES:
                original = source_bytes[node.start_byte : node.end_byte].decode("utf-8")
                replacement = mapping.get(original)
                if (
                    isinstance(replacement, str)
                    and replacement != original
                    and _is_safe_identifier(replacement, language)
                ):
                    edits.append((node.start_byte, node.end_byte, replacement.encode("utf-8")))
            # Iterate all children; target identifiers may appear at any depth.
            stack.extend(reversed(node.children))

        if not edits:
            return source, 0

        # Apply byte-offset edits from right to left so original spans remain valid.
        rewritten = source_bytes
        for start, end, replacement_bytes in sorted(edits, reverse=True):
            rewritten = rewritten[:start] + replacement_bytes + rewritten[end:]

        # Protect against replacements that make the language syntactically invalid.
        checked_tree = parser.parse(rewritten)
        if checked_tree.root_node.has_error:
            return source, 0
        return rewritten.decode("utf-8"), len(edits)
    except Exception:
        # Optional grammar/API mismatches and parse failures leave source untouched.
        return source, 0


def _is_safe_identifier(value: str, language: str) -> bool:
    if not value or value in _KEYWORDS[language]:
        return False
    first = value[0]
    if not ("A" <= first <= "Z" or "a" <= first <= "z" or first == "_"):
        if not (language in {"javascript", "typescript"} and first == "$"):
            return False
    for char in value[1:]:
        if not (
            "A" <= char <= "Z"
            or "a" <= char <= "z"
            or "0" <= char <= "9"
            or char == "_"
            or (language in {"javascript", "typescript"} and char == "$")
        ):
            return False
    return True


def _make_parser(language: str) -> Any | None:
    """Load a parser lazily, supporting common tree-sitter package APIs."""
    parser_names = {
        "python": "python",
        "javascript": "javascript",
        "typescript": "typescript",
        "go": "go",
    }
    try:
        from tree_sitter_languages import get_parser  # type: ignore[import-not-found]

        return get_parser(parser_names[language])
    except Exception:
        pass

    module_names = {
        "python": ("tree_sitter_python", "language"),
        "javascript": ("tree_sitter_javascript", "language"),
        "typescript": ("tree_sitter_typescript", "language_typescript"),
        "go": ("tree_sitter_go", "language"),
    }
    try:
        import importlib

        import tree_sitter

        module_name, language_function = module_names[language]
        grammar_module = importlib.import_module(module_name)
        grammar = getattr(grammar_module, language_function)()
        language_object = tree_sitter.Language(grammar)
        try:
            return tree_sitter.Parser(language_object)
        except TypeError:
            parser = tree_sitter.Parser()
            if hasattr(parser, "set_language"):
                parser.set_language(language_object)
            else:
                parser.language = language_object
            return parser
    except Exception:
        return None

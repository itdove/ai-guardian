"""Language-aware AST scanner for extracting comments and strings from source code.

Uses tree-sitter to parse source files and extract only the content that should
be scanned for prompt injection (comments, strings, docstrings). Code syntax
(function definitions, imports, assignments) is excluded to eliminate false positives.
"""

import logging
import os
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".sh": "bash",
    ".bash": "bash",
}

SCANNABLE_NODE_TYPES: Dict[str, Set[str]] = {
    "python": {"comment", "string"},
    "javascript": {"comment", "string", "template_string"},
    "typescript": {"comment", "string", "template_string"},
    "go": {"comment", "interpreted_string_literal", "raw_string_literal"},
    "rust": {"line_comment", "block_comment", "string_literal", "raw_string_literal"},
    "java": {"line_comment", "block_comment", "string_literal"},
    "ruby": {"comment", "string_content", "heredoc_body"},
    "c": {"comment", "string_literal", "string_content"},
    "cpp": {"comment", "string_literal", "string_content", "raw_string_literal"},
    "bash": {"comment", "string", "raw_string"},
}

_GRAMMAR_IMPORTS: Dict[str, str] = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "go": "tree_sitter_go",
    "rust": "tree_sitter_rust",
    "java": "tree_sitter_java",
    "ruby": "tree_sitter_ruby",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "bash": "tree_sitter_bash",
}

_parser_cache: Dict[str, Optional[Tuple["Parser", Set[str]]]] = {}


def _get_parser(language_name: str) -> Optional[Tuple["Parser", Set[str]]]:
    """Get a cached tree-sitter parser for the given language.

    Returns (Parser, scannable_node_types) or None if grammar not available.
    """
    if not HAS_TREE_SITTER:
        return None

    if language_name in _parser_cache:
        return _parser_cache[language_name]

    module_name = _GRAMMAR_IMPORTS.get(language_name)
    if not module_name:
        _parser_cache[language_name] = None
        return None

    try:
        import importlib
        grammar_module = importlib.import_module(module_name)

        if language_name == "typescript":
            lang = Language(grammar_module.language_typescript())
        else:
            lang = Language(grammar_module.language())

        parser = Parser(lang)
        scannable = SCANNABLE_NODE_TYPES.get(language_name, set())
        result = (parser, scannable)
        _parser_cache[language_name] = result
        return result
    except (ImportError, AttributeError, Exception) as e:
        logger.debug(f"tree-sitter grammar not available for {language_name}: {e}")
        _parser_cache[language_name] = None
        return None


def _collect_scannable_text(node, scannable_types: Set[str]) -> List[str]:
    """Recursively collect text from AST nodes that should be scanned.

    When a scannable node is found, its full text is collected and its children
    are NOT recursed into (avoids double-counting string -> string_content).
    """
    texts = []
    if node.type in scannable_types:
        try:
            texts.append(node.text.decode("utf8"))
        except (UnicodeDecodeError, AttributeError):
            pass  # intentionally silent — best-effort operation
    else:
        for child in node.children:
            texts.extend(_collect_scannable_text(child, scannable_types))
    return texts


def detect_language(file_path: str) -> Optional[str]:
    """Detect the programming language from a file extension.

    Returns the language name or None if unrecognized.
    """
    _, ext = os.path.splitext(file_path)
    return EXTENSION_TO_LANGUAGE.get(ext.lower())


def extract_scannable_content(content: str, file_path: str) -> Optional[str]:
    """Extract only comments and strings from source code for injection scanning.

    Args:
        content: The full file content to parse
        file_path: Path to the file (used for language detection from extension)

    Returns:
        Extracted comments and strings joined by newlines, or None if:
        - File extension is not recognized (unknown language)
        - tree-sitter is not installed
        - Grammar for the language is not installed
        - Parse error occurs (fail-open: caller should scan full content)
    """
    if not content or not file_path:
        return None

    language = detect_language(file_path)
    if language is None:
        return None

    parser_result = _get_parser(language)
    if parser_result is None:
        return None

    parser, scannable_types = parser_result

    try:
        tree = parser.parse(bytes(content, "utf8"))
        texts = _collect_scannable_text(tree.root_node, scannable_types)
        return "\n".join(texts) if texts else ""
    except Exception as e:
        logger.debug(f"AST parse error for {file_path}: {e}")
        return None

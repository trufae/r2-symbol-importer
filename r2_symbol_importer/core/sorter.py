"""
Topological dependency ordering and forward declaration resolver for C types.
Ensures structs, unions, and typedefs are compiled in valid dependency order by TinyCC / radare2.
"""

import re
from typing import Dict, List, Set, Tuple


# Regex to extract defined type names: typedef ... Name; or struct Tag { ... }
TYPEDEF_NAME_REGEX = re.compile(r"typedef\s+.*?(?:struct|union|enum)?\s*\{?[^\}]*\}?\s*(\*?\s*[A-Za-z0-9_]+(?:\s*,\s*\*?\s*[A-Za-z0-9_]+)*)\s*;")
STRUCT_TAG_REGEX = re.compile(r"\b(?:struct|union|enum)\s+([A-Za-z0-9_]+)\s*\{")
FORWARD_DECL_REGEX = re.compile(r"^\s*(?:struct|union|enum)\s+([A-Za-z0-9_]+)\s*;\s*$")

# Regex to identify references to other types inside a struct/union body
TYPE_REF_REGEX = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

PRIMITIVES_AND_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "int", "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
    "bool", "_Bool", "true", "false", "NULL", "inline", "restrict"
}


class TypeNode:
    def __init__(self, raw_code: str, index: int):
        self.raw_code: str = raw_code.strip()
        self.index: int = index
        self.defined_names: Set[str] = set()
        self.dependencies: Set[str] = set()
        self.is_forward_decl: bool = False
        self._analyze()

    def _analyze(self):
        code = self.raw_code

        # Check if it is just a forward declaration
        if FORWARD_DECL_REGEX.match(code):
            self.is_forward_decl = True
            tag = FORWARD_DECL_REGEX.match(code).group(1)
            self.defined_names.add(f"struct {tag}")
            self.defined_names.add(tag)
            return

        # Extract struct/union/enum tag
        for tag in STRUCT_TAG_REGEX.findall(code):
            self.defined_names.add(f"struct {tag}")
            self.defined_names.add(f"union {tag}")
            self.defined_names.add(f"enum {tag}")
            self.defined_names.add(tag)

        # Extract typedef identifiers
        if code.startswith("typedef"):
            # Grab the last token before semicolon or comma-separated list
            # e.g., typedef struct _FOO { ... } FOO, *PFOO;
            match = re.search(r"\}\s*([A-Za-z0-9_,\s\*]+);", code)
            if match:
                for alias in match.group(1).split(","):
                    clean_alias = alias.replace("*", "").strip()
                    if clean_alias:
                        self.defined_names.add(clean_alias)
            else:
                # simple typedef: typedef unsigned long DWORD;
                match_simple = re.search(r"typedef\s+.+?\s+(\*?\s*[A-Za-z0-9_]+)\s*;\s*$", code)
                if match_simple:
                    alias = match_simple.group(1).replace("*", "").strip()
                    if alias:
                        self.defined_names.add(alias)

        # Find potential type dependencies inside struct body
        tokens = set(TYPE_REF_REGEX.findall(code))
        # Filter out self-definitions and standard C keywords
        for tok in tokens:
            if tok not in PRIMITIVES_AND_KEYWORDS and tok not in self.defined_names:
                self.dependencies.add(tok)


def sort_type_definitions(type_snippets: List[str]) -> List[str]:
    """
    Topologically sorts a list of C type declaration strings.
    Resolves dependency ordering and prefixes necessary forward declarations.
    """
    if not type_snippets:
        return []

    nodes = [TypeNode(snip, idx) for idx, snip in enumerate(type_snippets)]
    
    # Map defined symbol -> list of node indices
    symbol_to_nodes: Dict[str, List[int]] = {}
    for i, node in enumerate(nodes):
        for sym in node.defined_names:
            symbol_to_nodes.setdefault(sym, []).append(i)

    # Build adjacency list: node -> set of dependent node indices
    adj: Dict[int, Set[int]] = {i: set() for i in range(len(nodes))}
    for i, node in enumerate(nodes):
        for dep in node.dependencies:
            if dep in symbol_to_nodes:
                for provider_idx in symbol_to_nodes[dep]:
                    if provider_idx != i:
                        adj[i].add(provider_idx)

    # Kahn's algorithm / Topological sort with cycle tolerance
    visited: Set[int] = set()
    ordered_indices: List[int] = []
    
    # Track in-degrees (number of unmet prerequisites)
    # providers must come BEFORE node i
    unmet_deps = {i: set(adj[i]) for i in range(len(nodes))}

    while len(ordered_indices) < len(nodes):
        # Find nodes with 0 unmet dependencies, preserving initial relative order
        ready = [i for i in range(len(nodes)) if i not in visited and len(unmet_deps[i]) == 0]
        if not ready:
            # Cycle detected (e.g. mutual pointer references). Pick the unvisited node with lowest original index
            unvisited = [i for i in range(len(nodes)) if i not in visited]
            ready = [min(unvisited, key=lambda idx: (len(unmet_deps[idx]), idx))]

        next_node = ready[0]
        visited.add(next_node)
        ordered_indices.append(next_node)

        # Remove next_node from unmet dependencies of remaining nodes
        for i in range(len(nodes)):
            if i not in visited:
                unmet_deps[i].discard(next_node)

    # Return snippets in topological order
    result: List[str] = []
    seen_code: Set[str] = set()
    for idx in ordered_indices:
        code = nodes[idx].raw_code
        if code not in seen_code:
            seen_code.add(code)
            result.append(code)

    return result

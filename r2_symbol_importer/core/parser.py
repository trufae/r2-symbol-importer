"""
AST-based C symbol and type extractor using Tree-sitter.
Extracts structs, unions, enums, typedefs, and function signatures with compiler-attribute sanitization.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Union


def get_c_parser():
    """Obtains a Tree-sitter parser for the C language across various packaging methods."""
    # 1. Official tree-sitter + tree-sitter-c (modern >= 0.22)
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c
        c_lang = Language(tree_sitter_c.language())
        try:
            return Parser(c_lang)
        except TypeError:
            p = Parser()
            p.language = c_lang
            return p
    except Exception:
        pass

    # 2. tree-sitter-language-pack
    try:
        from tree_sitter_language_pack import get_parser
        return get_parser("c")
    except Exception:
        pass

    raise RuntimeError(
        "Could not initialize Tree-sitter C parser. Please install 'tree-sitter' and 'tree-sitter-c', "
        "or 'tree-sitter-language-pack'."
    )


# Regex patterns for keywords, conventions, and SAL
ASM_BLOCKS = re.compile(r"__asm__(?:\s*__volatile__)?\s*\(\s*.*?\s*\)", re.DOTALL)

CALLING_CONVENTIONS = re.compile(
    r"\b(__stdcall|__fastcall|__cdecl|__pascal|__thiscall|__vectorcall|__syscall|"
    r"WINAPI|APIENTRY|CALLBACK|NTAPI|DDKAPI|FASTCALL|FORCEINLINE|__forceinline|"
    r"inline|__inline|__inline__|__restrict|__restrict__|restrict|_inline|"
    r"__unaligned|__ptr32|__ptr64|__sdecl|DRIVER_DISPATCH|DRIVER_INITIALIZE|DRIVER_UNLOAD)\b"
)

SAL_ANNOTATIONS = re.compile(
    r"\b(_In_|_In_opt_|_Out_|_Out_opt_|_Inout_|_Inout_opt_|_Must_inspect_result_|_Check_return_|"
    r"_Null_terminated_|_Printf_format_string_|_Field_size_bytes_opt_|_Field_size_opt_|"
    r"_Field_size_bytes_|_Field_size_|_In_reads_bytes_opt_|_In_reads_bytes_|_In_reads_opt_|"
    r"_In_reads_|_Out_writes_bytes_opt_|_Out_writes_bytes_|_Out_writes_opt_|_Out_writes_|"
    r"_Success_|_When_|_At_)\b(?:\s*\([^)]*\))?"
)


def strip_nested_construct(text: str, keyword: str) -> str:
    """Strips keyword(...) supporting arbitrary nested parentheses."""
    pattern = re.compile(rf"\b{re.escape(keyword)}\s*\(")
    while True:
        match = pattern.search(text)
        if not match:
            break
        start = match.start()
        open_paren_idx = match.end() - 1
        depth = 1
        i = open_paren_idx + 1
        while i < len(text) and depth > 0:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
            i += 1
        text = text[:start] + " " + text[i:]
    return text


def sanitize_c_declaration(text: str) -> str:
    """Removes compiler extensions, calling conventions, and SAL annotations from a C declaration."""
    clean = strip_nested_construct(text, "__attribute__")
    clean = strip_nested_construct(clean, "__declspec")
    clean = ASM_BLOCKS.sub("", clean)
    clean = SAL_ANNOTATIONS.sub("", clean)
    clean = CALLING_CONVENTIONS.sub("", clean)
    # Collapse multiple spaces and clean lines
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r"^[ \t]+|[ \t]+$", "", clean, flags=re.MULTILINE)
    clean = re.sub(r"\n\s*\n", "\n", clean)
    return clean.strip()


@dataclass
class FunctionPrototype:
    name: str
    return_type: str
    signature: str
    parameters: List[str] = field(default_factory=list)

    def to_r2_cmd(self) -> str:
        """Emits the radare2 `afs` command string."""
        return f'"afs {self.signature}"'


class SymbolExtractor:
    """Extracts types, structs, enums, typedefs, and function prototypes via Tree-sitter AST."""

    def __init__(self, target_path: Optional[Union[str, Path]] = None):
        self.target_path = Path(target_path) if target_path else None
        self.parser = get_c_parser()
        self.types: List[str] = []
        self.prototypes: List[FunctionPrototype] = []
        self._seen_types: Set[str] = set()
        self._seen_prototypes: Set[str] = set()

    def parse_content(self, content: str):
        """Walks AST of a single C header text content."""
        encoded = content.encode("utf-8")
        tree = self.parser.parse(encoded)
        self._walk_ast(tree.root_node, encoded)

    def parse_file(self, file_path: Union[str, Path]):
        """Parses a single file."""
        p = Path(file_path)
        content = p.read_text(encoding="utf-8", errors="ignore")
        self.parse_content(content)

    def parse_directory(self, dir_path: Union[str, Path]):
        """Recursively parses all .h and .i files in a directory."""
        d = Path(dir_path)
        header_files = sorted(list(d.rglob("*.h")) + list(d.rglob("*.i")) + list(d.rglob("*.hpp")))
        for h in header_files:
            self.parse_file(h)

    def run(self):
        """Executes extraction on `self.target_path`."""
        if not self.target_path:
            return
        if self.target_path.is_file():
            self.parse_file(self.target_path)
        elif self.target_path.is_dir():
            self.parse_directory(self.target_path)

    def _walk_ast(self, root_node, raw_bytes: bytes):
        def get_node_text(node) -> str:
            return raw_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").strip()

        def extract_function_prototype(decl_node) -> Optional[FunctionPrototype]:
            """Extracts function name, return type, and clean signature from a declaration node."""
            func_decl = None
            for child in decl_node.children:
                if child.type == "function_declarator":
                    func_decl = child
                    break
                if child.type == "pointer_declarator":
                    for sub in child.children:
                        if sub.type == "function_declarator":
                            func_decl = sub
                            break

            if not func_decl:
                return None

            func_name = None
            for child in func_decl.children:
                if child.type == "identifier":
                    func_name = get_node_text(child)
                    break
                elif child.type == "parenthesized_declarator":
                    for sub in child.children:
                        if sub.type == "identifier":
                            func_name = get_node_text(sub)
                            break

            if not func_name:
                return None

            params = []
            for child in func_decl.children:
                if child.type == "parameter_list":
                    for param in child.children:
                        if param.type == "parameter_declaration":
                            p_clean = sanitize_c_declaration(get_node_text(param))
                            if p_clean:
                                params.append(p_clean)

            raw_decl = get_node_text(decl_node).rstrip(";").strip()
            clean_sig = sanitize_c_declaration(raw_decl)

            return_type = "void"
            if "(" in clean_sig:
                before_paren = clean_sig.split("(", 1)[0].strip()
                if func_name in before_paren:
                    return_type = before_paren.rsplit(func_name, 1)[0].strip() or "void"

            return FunctionPrototype(
                name=func_name,
                return_type=return_type,
                signature=clean_sig,
                parameters=params
            )

        def add_type(type_code: str):
            clean = sanitize_c_declaration(type_code)
            if not clean.endswith(";"):
                clean += ";"
            if clean and clean not in self._seen_types:
                self._seen_types.add(clean)
                self.types.append(clean)

        def handle_typedef_struct(node):
            """
            Normalizes typedef struct/union/enum declarations by decomposing them
            into a standalone struct/union/enum and explicit single typedefs.
            """
            specifier_node = None
            type_declarators = []

            for child in node.children:
                if child.type in ("struct_specifier", "union_specifier", "enum_specifier"):
                    specifier_node = child
                elif child.type in ("type_identifier", "pointer_declarator", "type_declarator"):
                    type_declarators.append(child)

            if specifier_node and any(c.type in ("field_declaration_list", "enumerator_list") for c in specifier_node.children):
                kind = specifier_node.type.replace("_specifier", "")  # struct, union, enum
                # Find tag identifier
                tag = None
                for c in specifier_node.children:
                    if c.type == "type_identifier":
                        tag = get_node_text(c)
                        break

                spec_text = get_node_text(specifier_node)
                # If no tag was provided in typedef, use the first alias as tag
                if not tag and type_declarators:
                    first_alias = get_node_text(type_declarators[0]).replace("*", "").strip()
                    tag = f"_{first_alias}"
                    spec_text = spec_text.replace(f"{kind} {{", f"{kind} {tag} {{", 1)

                add_type(spec_text)

                # Emit individual typedefs for each declarator
                for decl in type_declarators:
                    alias_str = get_node_text(decl).strip()
                    if tag:
                        if alias_str.startswith("*"):
                            add_type(f"typedef {kind} {tag} {alias_str};")
                        else:
                            add_type(f"typedef {kind} {tag} {alias_str};")
                    else:
                        add_type(f"typedef {spec_text} {alias_str};")
            else:
                # Standard typedef
                add_type(get_node_text(node))

        def walk(node):
            node_type = node.type

            # 1. Type Definitions (typedefs)
            if node_type == "type_definition":
                handle_typedef_struct(node)
                return

            # 2. Standalone Struct, Union, and Enum declarations with bodies
            elif node_type in ("struct_specifier", "union_specifier", "enum_specifier"):
                has_body = any(c.type in ("field_declaration_list", "enumerator_list") for c in node.children)
                is_inside_typedef = node.parent and node.parent.type == "type_definition"
                if has_body and not is_inside_typedef:
                    if node.parent and node.parent.type == "declaration":
                        raw = get_node_text(node.parent)
                    else:
                        raw = get_node_text(node)
                    add_type(raw)
                    return

            # 3. Function Prototypes
            elif node_type == "declaration":
                proto = extract_function_prototype(node)
                if proto and proto.signature not in self._seen_prototypes:
                    self._seen_prototypes.add(proto.signature)
                    self.prototypes.append(proto)

            for child in node.children:
                walk(child)

        walk(root_node)

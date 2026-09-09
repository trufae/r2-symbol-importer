"""
Safe preprocessor constant and expression evaluator for C headers.
Supports arithmetic, bit shifts, bitwise operations, multi-pass symbol resolution,
and Windows / generic IOCTL CTL_CODE macros.
"""

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Standard Windows DDK / Kernel IOCTL definitions
DEFAULT_IOCTL_ENV: Dict[str, int] = {
    # Transfer Methods
    "METHOD_BUFFERED": 0,
    "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 2,
    "METHOD_NEITHER": 3,
    # Access types
    "FILE_ANY_ACCESS": 0,
    "FILE_SPECIAL_ACCESS": 0,
    "FILE_READ_ACCESS": 0x0001,
    "FILE_WRITE_ACCESS": 0x0002,
    "FILE_READ_DATA": 0x0001,
    "FILE_WRITE_DATA": 0x0002,
    # Common Device Types
    "FILE_DEVICE_BEEP": 0x00000001,
    "FILE_DEVICE_CD_ROM": 0x00000002,
    "FILE_DEVICE_CD_ROM_FILE_SYSTEM": 0x00000003,
    "FILE_DEVICE_CONTROLLER": 0x00000004,
    "FILE_DEVICE_DATALINK": 0x00000005,
    "FILE_DEVICE_DFS": 0x00000006,
    "FILE_DEVICE_DISK": 0x00000007,
    "FILE_DEVICE_DISK_FILE_SYSTEM": 0x00000008,
    "FILE_DEVICE_FILE_SYSTEM": 0x00000009,
    "FILE_DEVICE_INPORT_PORT": 0x0000000a,
    "FILE_DEVICE_KEYBOARD": 0x0000000b,
    "FILE_DEVICE_MAILSLOT": 0x0000000c,
    "FILE_DEVICE_MIDI_IN": 0x0000000d,
    "FILE_DEVICE_MIDI_OUT": 0x0000000e,
    "FILE_DEVICE_MOUSE": 0x0000000f,
    "FILE_DEVICE_MULTI_UNC_PROVIDER": 0x00000010,
    "FILE_DEVICE_NAMED_PIPE": 0x00000011,
    "FILE_DEVICE_NETWORK": 0x00000012,
    "FILE_DEVICE_NETWORK_BROWSER": 0x00000013,
    "FILE_DEVICE_NETWORK_FILE_SYSTEM": 0x00000014,
    "FILE_DEVICE_NULL": 0x00000015,
    "FILE_DEVICE_PARALLEL_PORT": 0x00000016,
    "FILE_DEVICE_PHYSICAL_NETCARD": 0x00000017,
    "FILE_DEVICE_PRINTER": 0x00000018,
    "FILE_DEVICE_SCANNER": 0x00000019,
    "FILE_DEVICE_SERIAL_MOUSE_PORT": 0x0000001a,
    "FILE_DEVICE_SERIAL_PORT": 0x0000001b,
    "FILE_DEVICE_SCREEN": 0x0000001c,
    "FILE_DEVICE_SOUND": 0x0000001d,
    "FILE_DEVICE_STREAMS": 0x0000001e,
    "FILE_DEVICE_TAPE": 0x0000001f,
    "FILE_DEVICE_TAPE_FILE_SYSTEM": 0x00000020,
    "FILE_DEVICE_TRANSPORT": 0x00000021,
    "FILE_DEVICE_UNKNOWN": 0x00000022,
    "FILE_DEVICE_VIDEO": 0x00000023,
    "FILE_DEVICE_VIRTUAL_DISK": 0x00000024,
    "FILE_DEVICE_WAVE_IN": 0x00000025,
    "FILE_DEVICE_WAVE_OUT": 0x00000026,
    "FILE_DEVICE_8042_PORT": 0x00000027,
    "FILE_DEVICE_NETWORK_REDIRECTOR": 0x00000028,
    "FILE_DEVICE_BATTERY": 0x00000029,
    "FILE_DEVICE_BUS_EXTENDER": 0x0000002a,
    "FILE_DEVICE_MODEM": 0x0000002b,
    "FILE_DEVICE_VDM": 0x0000002c,
    "FILE_DEVICE_MASS_STORAGE": 0x0000002d,
    "FILE_DEVICE_SMB": 0x0000002e,
    "FILE_DEVICE_KS": 0x0000002f,
    "FILE_DEVICE_CHANGER": 0x00000030,
    "FILE_DEVICE_SMARTCARD": 0x00000031,
    "FILE_DEVICE_ACPI": 0x00000032,
    "FILE_DEVICE_DVD": 0x00000033,
    "FILE_DEVICE_FULLSCREEN_VIDEO": 0x00000034,
    "FILE_DEVICE_DFS_FILE_SYSTEM": 0x00000035,
    "FILE_DEVICE_DFS_VOLUME": 0x00000036,
    "FILE_DEVICE_SERENUM": 0x00000037,
    "FILE_DEVICE_TERMSRV": 0x00000038,
    "FILE_DEVICE_KSEC": 0x00000039,
    "FILE_DEVICE_FIPS": 0x0000003A,
    "FILE_DEVICE_INFINIBAND": 0x0000003B,
    "FILE_DEVICE_VMBUS": 0x0000003E,
    "FILE_DEVICE_CRYPT_PROVIDER": 0x0000003F,
    "FILE_DEVICE_WPD": 0x00000040,
    "FILE_DEVICE_BLUETOOTH": 0x00000041,
    "FILE_DEVICE_MT_COMPOSITE": 0x00000042,
    "FILE_DEVICE_MT_TRANSPORT": 0x00000043,
    "FILE_DEVICE_BIOMETRIC": 0x00000044,
    "FILE_DEVICE_PMI": 0x00000045,
}

# Regex to match #define NAME expr
DEFINE_REGEX = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)(?:\([^\)]*\))?[ \t]+([^\r\n/]+)",
    re.MULTILINE
)

# Regex to detect CTL_CODE(...) macro calls
CTL_CODE_REGEX = re.compile(
    r"CTL_CODE\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,\)]+)\s*\)"
)

# Strip C integer literal suffixes like U, L, UL, ULL, LL, i64, ui64
INT_SUFFIX_REGEX = re.compile(r"\b((?:0x[0-9a-fA-F]+)|(?:\d+))(?:[uU][lL]{0,2}|[lL]{1,2}[uU]?|[iIuU]64)\b")


@dataclass
class ConstantDefinition:
    name: str
    value: int
    raw_expression: str
    hex_str: str

    def __repr__(self) -> str:
        return f"Constant({self.name} = {self.hex_str} [{self.value}])"


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    """Standard Windows CTL_CODE macro expansion."""
    return (((device_type & 0xFFFF) << 16) | ((access & 0x3) << 14) | ((function & 0xFFF) << 2) | (method & 0x3)) & 0xFFFFFFFF


class SafeEvaluator:
    """Safely evaluates constant mathematical and bitwise expressions using Python AST."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None):
        self.symbols: Dict[str, int] = dict(symbols or {})

    def evaluate_node(self, node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return self.evaluate_node(node.body)

        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return int(node.value)
            raise ValueError(f"Unsupported constant type: {type(node.value)}")

        if hasattr(ast, "Num") and isinstance(node, getattr(ast, "Num")):
            return int(node.n)

        if isinstance(node, ast.Name):
            if node.id in self.symbols:
                return self.symbols[node.id]
            raise ValueError(f"Unknown symbol identifier: {node.id}")

        if isinstance(node, ast.UnaryOp):
            operand = self.evaluate_node(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Invert):
                return ~operand
            raise ValueError(f"Unsupported unary operator: {type(node.op)}")

        if isinstance(node, ast.BinOp):
            left = self.evaluate_node(node.left)
            right = self.evaluate_node(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.FloorDiv):
                return left // right if right != 0 else 0
            if isinstance(node.op, ast.Mod):
                return left % right if right != 0 else 0
            if isinstance(node.op, ast.LShift):
                return left << (right & 0x3F)
            if isinstance(node.op, ast.RShift):
                return left >> (right & 0x3F)
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            raise ValueError(f"Unsupported binary operator: {type(node.op)}")

        raise ValueError(f"Unsupported AST node: {type(node)}")

    def eval_expr(self, expr_str: str) -> Optional[int]:
        try:
            tree = ast.parse(expr_str.strip(), mode="eval")
            return self.evaluate_node(tree)
        except Exception:
            return None


class ConstantEvaluator:
    """
    Extracts and evaluates `#define` constants from C header files or text snippets.
    Resolves multi-step dependencies and IOCTL macro definitions.
    """

    def __init__(self, initial_env: Optional[Dict[str, int]] = None):
        self.env: Dict[str, int] = dict(DEFAULT_IOCTL_ENV)
        if initial_env:
            self.env.update(initial_env)
        self.definitions: List[ConstantDefinition] = []

    def _sanitize_expression(self, expr: str) -> str:
        """Strip comments, C casts, integer suffixes, and normalize octal/CTL_CODE."""
        # Strip single-line comments and trailing inline comments
        expr = re.sub(r"/\*.*?\*/", "", expr)
        expr = re.sub(r"//.*$", "", expr)
        expr = expr.strip()

        # Replace CTL_CODE(...) calls with expanded arithmetic
        def replace_ctl_code(match: re.Match) -> str:
            d_type = match.group(1).strip()
            func = match.group(2).strip()
            method = match.group(3).strip()
            access = match.group(4).strip()
            return f"(((({d_type}) & 0xFFFF) << 16) | ((({access}) & 0x3) << 14) | ((({func}) & 0xFFF) << 2) | (({method}) & 0x3))"

        expr = CTL_CODE_REGEX.sub(replace_ctl_code, expr)

        # Strip C-style casts like (DWORD), (ULONG), (int), (UINT32), (uint32_t)
        expr = re.sub(r"\([ \t]*(?:unsigned[ \t]+|signed[ \t]+)?(?:int|long|short|char|DWORD|ULONG|UINT[0-9]*|INT[0-9]*|size_t|uint[0-9]*_t|int[0-9]*_t)[ \t]*\)", "", expr)

        # Strip integer suffixes (e.g. 100ULL -> 100, 0x100UL -> 0x100)
        expr = INT_SUFFIX_REGEX.sub(r"\1", expr)

        # Convert C octal literals (e.g. 0755 -> 0o755) while preserving single '0' and hex
        expr = re.sub(r"\b0([0-7]+)\b", r"0o\1", expr)

        return expr.strip()

    def process_text(self, text: str) -> List[ConstantDefinition]:
        """
        Parses all #define constants from text, performing multi-pass resolution.
        """
        raw_defines: List[Tuple[str, str]] = []
        for match in DEFINE_REGEX.finditer(text):
            name = match.group(1)
            raw_val = match.group(2).strip()
            # Ignore standard header guards like #define _HEADER_H_
            if not raw_val or raw_val.startswith('"') or raw_val.startswith('<'):
                continue
            cleaned = self._sanitize_expression(raw_val)
            if cleaned:
                raw_defines.append((name, cleaned))

        # Multi-pass resolution
        resolved_any = True
        max_passes = 10
        pass_count = 0
        unresolved = raw_defines

        while resolved_any and unresolved and pass_count < max_passes:
            pass_count += 1
            resolved_any = False
            remaining = []
            evaluator = SafeEvaluator(self.env)

            for name, expr in unresolved:
                val = evaluator.eval_expr(expr)
                if val is not None:
                    self.env[name] = val
                    hex_repr = f"0x{val & 0xFFFFFFFF:X}" if 0 <= val <= 0xFFFFFFFF else f"0x{val:X}"
                    self.definitions.append(
                        ConstantDefinition(
                            name=name,
                            value=val,
                            raw_expression=expr,
                            hex_str=hex_repr
                        )
                    )
                    resolved_any = True
                else:
                    remaining.append((name, expr))
            unresolved = remaining

        return self.definitions

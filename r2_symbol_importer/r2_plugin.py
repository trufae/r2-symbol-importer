#!/usr/bin/env python3
"""
radare2 In-Session r2pipe Plugin and CLI Runner.
Executes inside radare2 via `#!pipe python3 -m r2_symbol_importer.r2_plugin <path>`
or as a standalone command.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import r2pipe
from r2_symbol_importer.core.pipeline import SymbolPipeline
from r2_symbol_importer.core.preludes import PreludeType


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog="r2-symbol-importer",
        description="Extract and import C types, function signatures, and constants into an active radare2/iaito session."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to C header file (.h, .i) or include directory containing headers."
    )
    parser.add_argument(
        "--install-iaito",
        action="store_true",
        help="Install bootstrap plugin loader into iaito user plugin directory to enable native menu integration."
    )
    parser.add_argument(
        "--no-types",
        action="store_true",
        help="Skip C struct, union, enum, and typedef import ('to')."
    )
    parser.add_argument(
        "--no-protos",
        action="store_true",
        help="Skip function prototypes / signatures import ('afs')."
    )
    parser.add_argument(
        "--no-flags",
        action="store_true",
        help="Skip #define constants and IOCTL flags import ('f const.*')."
    )
    parser.add_argument(
        "--prelude",
        choices=["auto", "windows", "posix", "stdint", "none"],
        default="auto",
        help="Type prelude preset for radare2 TinyCC parser (default: auto)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print radare2 commands and header preview to stdout without applying to session."
    )
    parser.add_argument(
        "--output-script",
        "-o",
        metavar="FILE.r2",
        help="Save generated radare2 commands to a standalone .r2 script file."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result summary in JSON format."
    )
    return parser.parse_args(args)


def main(args=None) -> int:
    parsed = parse_args(args)

    # Handle --install-iaito
    if parsed.install_iaito:
        try:
            from r2_symbol_importer.iaito_plugin import install_to_iaito_dir
            loader_path = install_to_iaito_dir()
            print(f"[+] Successfully installed iaito plugin loader to:\n    {loader_path}")
            print("[+] 'Import C Symbols & Headers...' will now appear in iaito's Tools/Plugins menu on startup.")
            return 0
        except Exception as e:
            print(f"[-] Failed to install iaito plugin: {e}", file=sys.stderr)
            return 1

    if not parsed.target:
        print("Error: target path required unless using --install-iaito.", file=sys.stderr)
        return 1

    target_path = Path(parsed.target)

    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        return 1

    prelude_type = PreludeType(parsed.prelude)
    pipeline = SymbolPipeline(prelude_type=prelude_type)

    try:
        result = pipeline.extract_from_path(target_path)
    except Exception as e:
        print(f"Extraction error: {e}", file=sys.stderr)
        return 1

    import_types = not parsed.no_types
    import_protos = not parsed.no_protos
    import_flags = not parsed.no_flags

    # Handle --output-script
    if parsed.output_script:
        pipeline.export_r2_script(
            result,
            parsed.output_script,
            import_types=import_types,
            import_protos=import_protos,
            import_flags=import_flags
        )
        print(f"[+] Saved radare2 script to {parsed.output_script}")

    # Handle --dry-run
    if parsed.dry_run:
        print("=== GENERATED C HEADER ===")
        print(result.clean_header)
        print("\n=== GENERATED R2 COMMANDS ===")
        cmds = pipeline.generate_r2_commands(
            result,
            import_types=import_types,
            import_protos=import_protos,
            import_flags=import_flags
        )
        for cmd in cmds:
            print(cmd)
        print(f"\n[+] Extracted: {result.summary}")
        return 0

    # In-session execution via r2pipe
    try:
        r2 = r2pipe.open()
    except Exception as e:
        print(
            f"[-] Could not connect to radare2 session via r2pipe: {e}\n"
            f"    Run this command inside radare2 using: #!pipe r2-symbol-importer {parsed.target}\n"
            f"    Or use --dry-run / --output-script to generate .r2 scripts.",
            file=sys.stderr
        )
        return 1

    report = pipeline.apply_to_r2(
        r2,
        result,
        import_types=import_types,
        import_protos=import_protos,
        import_flags=import_flags,
        match_functions=True
    )

    if parsed.json:
        out = {
            "types_loaded": report.types_loaded,
            "prototypes_applied": report.prototypes_applied,
            "constants_flagged": report.constants_flagged,
            "matched_functions": report.matched_functions,
            "errors": report.errors,
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"[+] Successfully loaded {report.types_loaded} types into radare2.")
        print(f"[+] Applied {report.prototypes_applied} function signatures.")
        if report.matched_functions:
            print(f"[+] Matched {len(report.matched_functions)} functions to existing session symbols.")
        print(f"[+] Defined {report.constants_flagged} constants as 'const.*' flags.")
        if report.errors:
            print(f"[!] Encountered {len(report.errors)} warnings/errors:")
            for err in report.errors:
                print(f"    - {err}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Orchestrator pipeline integrating AST extraction, constant evaluation,
topological sorting, prelude injection, and radare2 session ingestion.
"""

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from r2_symbol_importer.core.constants import ConstantDefinition, ConstantEvaluator
from r2_symbol_importer.core.parser import FunctionPrototype, SymbolExtractor
from r2_symbol_importer.core.preludes import PreludeType, get_prelude
from r2_symbol_importer.core.sorter import sort_type_definitions


@dataclass
class ExtractionResult:
    types: List[str] = field(default_factory=list)
    prototypes: List[FunctionPrototype] = field(default_factory=list)
    constants: List[ConstantDefinition] = field(default_factory=list)
    prelude_used: str = ""
    clean_header: str = ""

    @property
    def summary(self) -> str:
        return (
            f"{len(self.types)} types, "
            f"{len(self.prototypes)} prototypes, "
            f"{len(self.constants)} constants/flags"
        )


@dataclass
class ImportReport:
    types_loaded: int = 0
    prototypes_applied: int = 0
    constants_flagged: int = 0
    matched_functions: List[str] = field(default_factory=list)
    r2_outputs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class SymbolPipeline:
    """End-to-end symbol and type processing pipeline."""

    def __init__(self, prelude_type: PreludeType = PreludeType.AUTO):
        self.prelude_type = prelude_type

    def extract_from_text(self, content: str) -> ExtractionResult:
        """Runs extraction, constant evaluation, and topological sorting on in-memory text."""
        # 1. AST Type & Prototype Extraction
        extractor = SymbolExtractor()
        extractor.parse_content(content)

        # 2. Constant & IOCTL Evaluation
        const_eval = ConstantEvaluator()
        constants = const_eval.process_text(content)

        # 3. Sort Types Topologically
        sorted_types = sort_type_definitions(extractor.types)

        # 4. Generate Prelude & Final Clean C Header
        prelude = get_prelude(self.prelude_type, sample_content=content)
        header_lines = [
            "/* Auto-generated for radare2 / iaito */",
            prelude,
            "\n/* Extracted C Types */"
        ]
        for t in sorted_types:
            header_lines.append(t)
            header_lines.append("")

        clean_header = "\n".join(header_lines)

        return ExtractionResult(
            types=sorted_types,
            prototypes=extractor.prototypes,
            constants=constants,
            prelude_used=prelude,
            clean_header=clean_header,
        )

    def extract_from_path(self, target_path: Union[str, Path]) -> ExtractionResult:
        """Runs extraction across a single header file or an entire include directory."""
        p = Path(target_path)
        if not p.exists():
            raise FileNotFoundError(f"Path does not exist: {target_path}")

        files: List[Path] = []
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = sorted(list(p.rglob("*.h")) + list(p.rglob("*.i")) + list(p.rglob("*.hpp")))

        combined_text_list = []
        for f in files:
            combined_text_list.append(f.read_text(encoding="utf-8", errors="ignore"))

        full_content = "\n\n".join(combined_text_list)
        return self.extract_from_text(full_content)

    def generate_r2_commands(
        self,
        result: ExtractionResult,
        import_types: bool = True,
        import_protos: bool = True,
        import_flags: bool = True,
        header_file_path: Optional[str] = None
    ) -> List[str]:
        """Generates the list of radare2 commands representing this extraction result."""
        cmds: List[str] = []

        if import_types and result.types:
            if header_file_path:
                cmds.append(f"to {header_file_path}")
            else:
                cmds.append("# (Note: In live session, types are loaded via 'to <header_file>')")

        if import_flags and result.constants:
            for const in result.constants:
                cmds.append(f"f const.{const.name} = {const.hex_str}")

        if import_protos and result.prototypes:
            for proto in result.prototypes:
                cmds.append(f'"afs {proto.signature}"')

        return cmds

    def export_r2_script(
        self,
        result: ExtractionResult,
        output_script_path: Union[str, Path],
        header_path: Optional[str] = None,
        import_types: bool = True,
        import_protos: bool = True,
        import_flags: bool = True
    ):
        """Saves a standalone .r2 script file for batch loading."""
        cmds = self.generate_r2_commands(
            result,
            import_types=import_types,
            import_protos=import_protos,
            import_flags=import_flags,
            header_file_path=header_path
        )
        p = Path(output_script_path)
        p.write_text("\n".join(cmds) + "\n", encoding="utf-8")

    def apply_to_r2(
        self,
        r2_instance: Any,
        result: ExtractionResult,
        import_types: bool = True,
        import_protos: bool = True,
        import_flags: bool = True,
        match_functions: bool = True
    ) -> ImportReport:
        """
        Directly injects types, signatures, and flags into an active r2 session via r2pipe.
        """
        report = ImportReport()

        # 1. Ingest C Types via temporary header file
        if import_types and result.types:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".h", delete=False, encoding="utf-8") as tmp:
                tmp.write(result.clean_header)
                tmp_path = tmp.name

            try:
                out = r2_instance.cmd(f"to {tmp_path}")
                if out:
                    report.r2_outputs.append(f"to: {out.strip()}")
                report.types_loaded = len(result.types)
            except Exception as e:
                report.errors.append(f"Failed to load types: {e}")
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        # 2. Ingest Constants & Flags
        if import_flags and result.constants:
            for const in result.constants:
                cmd = f"f const.{const.name} = {const.hex_str}"
                try:
                    r2_instance.cmd(cmd)
                    report.constants_flagged += 1
                except Exception as e:
                    report.errors.append(f"Failed flag {const.name}: {e}")

        # 3. Ingest Function Prototypes & Signatures
        if import_protos and result.prototypes:
            # Query session functions to correlate names if requested
            known_funcs: Dict[str, Union[int, str]] = {}
            if match_functions:
                try:
                    afl_json = r2_instance.cmd("aflj")
                    if afl_json and afl_json.strip().startswith("["):
                        for f in json.loads(afl_json):
                            fname = f.get("name", "")
                            faddr = f.get("offset", 0)
                            known_funcs[fname] = faddr
                            # Also match stripped prefixes like sym.DriverEntry -> DriverEntry
                            if fname.startswith("sym."):
                                known_funcs[fname[4:]] = faddr
                except Exception:
                    pass

            for proto in result.prototypes:
                try:
                    # If function is recognized in session, seek and apply afs
                    if proto.name in known_funcs:
                        addr = known_funcs[proto.name]
                        r2_instance.cmd(f"s {addr}")
                        r2_instance.cmd(f'"afs {proto.signature}"')
                        report.matched_functions.append(f"{proto.name} @ {hex(addr) if isinstance(addr, int) else addr}")
                    else:
                        # Otherwise register signature type generally in r2
                        r2_instance.cmd(f'"afs {proto.signature}"')
                    report.prototypes_applied += 1
                except Exception as e:
                    report.errors.append(f"Failed signature for {proto.name}: {e}")

        return report

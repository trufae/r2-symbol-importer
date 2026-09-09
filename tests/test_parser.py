from r2_symbol_importer.core.parser import (
    SymbolExtractor,
    sanitize_c_declaration,
)
from r2_symbol_importer.core.pipeline import SymbolPipeline


def test_sanitize_c_declaration():
    raw_msvc = "_Must_inspect_result_ NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);"
    cleaned = sanitize_c_declaration(raw_msvc)
    assert "_Must_inspect_result_" not in cleaned
    assert "NTAPI" not in cleaned
    assert "_In_" not in cleaned
    assert "DriverEntry" in cleaned
    assert "DriverObject" in cleaned

    raw_gcc = "struct __attribute__((packed, aligned(4))) my_struct { int a; };"
    cleaned_gcc = sanitize_c_declaration(raw_gcc)
    assert "__attribute__" not in cleaned_gcc
    assert "struct my_struct" in cleaned_gcc


def test_symbol_extractor_windows_driver(sample_driver_path):
    extractor = SymbolExtractor(sample_driver_path)
    extractor.run()

    # Types extracted
    type_texts = "\n".join(extractor.types)
    assert "PACKET_HEADER" in type_texts
    assert "DEVICE_EXTENSION" in type_texts

    # Prototypes extracted
    proto_names = [p.name for p in extractor.prototypes]
    assert "DriverEntry" in proto_names
    assert "DispatchCreate" in proto_names
    assert "DispatchDeviceControl" in proto_names
    assert "DriverUnload" in proto_names

    # Check that calling convention NTAPI and SAL annotations are stripped from prototypes
    driver_entry_proto = next(p for p in extractor.prototypes if p.name == "DriverEntry")
    assert "NTAPI" not in driver_entry_proto.signature
    assert "_In_" not in driver_entry_proto.signature
    assert "_Must_inspect_result_" not in driver_entry_proto.signature


def test_symbol_extractor_posix(sample_posix_path):
    extractor = SymbolExtractor(sample_posix_path)
    extractor.run()

    type_texts = "\n".join(extractor.types)
    assert "wire_header" in type_texts
    assert "driver_context" in type_texts
    assert "__attribute__" not in type_texts

    proto_names = [p.name for p in extractor.prototypes]
    assert "init_protocol_driver" in proto_names
    assert "shutdown_protocol_driver" in proto_names


def test_pipeline_end_to_end(sample_driver_path):
    pipeline = SymbolPipeline()
    result = pipeline.extract_from_path(sample_driver_path)

    assert len(result.types) >= 2
    assert len(result.prototypes) == 4
    assert len(result.constants) >= 7

    # Check prelude inclusion
    assert "typedef unsigned long DWORD;" in result.clean_header
    assert "PACKET_HEADER" in result.clean_header

import pytest
import r2pipe
from r2_symbol_importer.core.pipeline import SymbolPipeline


@pytest.fixture
def r2_session():
    """Provides a clean in-memory radare2 session."""
    r2 = r2pipe.open("malloc://4096")
    yield r2
    try:
        r2.quit()
    except Exception:
        pass


def test_r2_load_types_and_structs(r2_session, sample_driver_path):
    pipeline = SymbolPipeline()
    result = pipeline.extract_from_path(sample_driver_path)

    report = pipeline.apply_to_r2(
        r2_session,
        result,
        import_types=True,
        import_protos=True,
        import_flags=True,
        match_functions=False,
    )

    assert report.types_loaded >= 2
    assert report.constants_flagged >= 7
    assert report.prototypes_applied >= 4

    # 1. Verify structs and typedefs in radare2 type database ('ts', 'tt')
    ts_all = r2_session.cmd("ts")
    tt_all = r2_session.cmd("tt")
    assert "_PACKET_HEADER" in ts_all or "PACKET_HEADER" in tt_all

    # 2. Verify struct inspection ('ts')
    ts_inspect = r2_session.cmd("ts _PACKET_HEADER")
    if not ts_inspect.strip():
        ts_inspect = r2_session.cmd("ts PACKET_HEADER")
    assert "SequenceNumber" in ts_inspect or "PayloadLength" in ts_inspect or "Flags" in ts_inspect

    # 3. Verify flags ('f~const.')
    flags_out = r2_session.cmd("f~const.")
    assert "const.IOCTL_SAMPLE_READ_DATA" in flags_out
    assert "const.DRIVER_FLAG_ACTIVE" in flags_out


def test_r2_posix_integration(r2_session, sample_posix_path):
    pipeline = SymbolPipeline()
    result = pipeline.extract_from_path(sample_posix_path)

    report = pipeline.apply_to_r2(
        r2_session,
        result,
        import_types=True,
        import_protos=True,
        import_flags=True,
        match_functions=False,
    )

    assert report.types_loaded >= 2
    assert report.constants_flagged >= 4

    # Verify structs loaded
    ts_all = r2_session.cmd("ts")
    assert "wire_header" in ts_all or "driver_context" in ts_all

    # Verify flags
    flags_out = r2_session.cmd("f~const.")
    assert "const.PROTOCOL_MAGIC" in flags_out

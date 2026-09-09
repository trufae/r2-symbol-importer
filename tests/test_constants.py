import pytest
from r2_symbol_importer.core.constants import (
    ConstantEvaluator,
    ctl_code,
    DEFAULT_IOCTL_ENV,
)


def test_ctl_code_calculation():
    # CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
    # DeviceType: 0x8000 << 16 = 0x80000000
    # Access: FILE_READ_ACCESS (1) << 14 = 0x4000
    # Function: 0x800 << 2 = 0x2000
    # Method: METHOD_BUFFERED (0) = 0
    # Expected: 0x80004000 | 0x2000 = 0x80006000
    res = ctl_code(0x8000, 0x800, 0, 1)
    assert res == 0x80006000


def test_constant_evaluator_literals():
    header = """
    #define CONST_DEC 1234
    #define CONST_HEX 0xABCD
    #define CONST_OCT 0755
    #define CONST_BIN 0b1010
    #define CONST_SUFFIX 0x100UL
    #define CONST_ULL 1ULL
    """
    evaluator = ConstantEvaluator()
    defs = evaluator.process_text(header)
    mapping = {d.name: d.value for d in defs}

    assert mapping["CONST_DEC"] == 1234
    assert mapping["CONST_HEX"] == 0xABCD
    assert mapping["CONST_OCT"] == 0o755
    assert mapping["CONST_BIN"] == 0b1010
    assert mapping["CONST_SUFFIX"] == 0x100
    assert mapping["CONST_ULL"] == 1


def test_constant_evaluator_expressions():
    header = """
    #define BASE_VAL 0x1000
    #define OFFSET_VAL 0x20
    #define COMBINED (BASE_VAL + OFFSET_VAL * 2)
    #define SHIFTED (1 << 8)
    #define MASK_OR (SHIFTED | 0x01)
    #define INVERTED (~0xF0)
    """
    evaluator = ConstantEvaluator()
    defs = evaluator.process_text(header)
    mapping = {d.name: d.value for d in defs}

    assert mapping["BASE_VAL"] == 0x1000
    assert mapping["OFFSET_VAL"] == 0x20
    assert mapping["COMBINED"] == 0x1040
    assert mapping["SHIFTED"] == 256
    assert mapping["MASK_OR"] == 257
    assert mapping["INVERTED"] == ~0xF0


def test_constant_evaluator_ioctl_macros(sample_driver_path):
    evaluator = ConstantEvaluator()
    content = sample_driver_path.read_text()
    defs = evaluator.process_text(content)
    mapping = {d.name: d.value for d in defs}

    assert "IOCTL_DEVICE_BASE" in mapping
    assert mapping["IOCTL_DEVICE_BASE"] == 0x8000
    assert "IOCTL_SAMPLE_READ_DATA" in mapping
    assert mapping["IOCTL_SAMPLE_READ_DATA"] == 0x80006000

    assert "DRIVER_FLAG_ACTIVE" in mapping
    assert mapping["DRIVER_FLAG_ACTIVE"] == 1
    assert "DRIVER_FLAG_INITIALIZED" in mapping
    assert mapping["DRIVER_FLAG_INITIALIZED"] == 2
    assert "DRIVER_FLAG_SUSPENDED" in mapping
    assert mapping["DRIVER_FLAG_SUSPENDED"] == 4
    assert mapping["DRIVER_FULL_MASK"] == 7
    assert mapping["MAX_PACKET_SIZE"] == 4096

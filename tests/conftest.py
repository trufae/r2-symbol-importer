from pathlib import Path
import pytest

@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def sample_driver_path(fixtures_dir) -> Path:
    return fixtures_dir / "sample_driver.h"

@pytest.fixture
def sample_posix_path(fixtures_dir) -> Path:
    return fixtures_dir / "sample_posix.h"

@pytest.fixture
def sample_binary_c_path(fixtures_dir) -> Path:
    return fixtures_dir / "sample_binary.c"

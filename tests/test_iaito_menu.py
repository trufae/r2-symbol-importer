import os
import sys
from pathlib import Path
import pytest
from r2_symbol_importer.qt_compat import QT_AVAILABLE

os.environ["QT_QPA_PLATFORM"] = "offscreen"


def test_iaito_plugin_dir_resolution():
    from r2_symbol_importer.iaito_plugin import get_iaito_plugin_dir
    p = get_iaito_plugin_dir()
    assert isinstance(p, Path)
    assert "radareorg" in str(p)
    assert "plugins" in str(p)


def test_install_to_iaito_dir(tmp_path, monkeypatch):
    from r2_symbol_importer import iaito_plugin

    fake_plugin_dir = tmp_path / "iaito" / "plugins" / "python"
    monkeypatch.setattr(iaito_plugin, "get_iaito_plugin_dir", lambda: fake_plugin_dir)

    loader = iaito_plugin.install_to_iaito_dir()
    assert loader.exists()
    assert loader.name == "r2_symbol_importer_loader.py"
    content = loader.read_text()
    assert "ip.install_menu()" in content


@pytest.mark.skipif(not QT_AVAILABLE, reason="PySide/PyQt is not installed")
def test_iaito_menu_installation():
    from r2_symbol_importer.qt_compat import QtWidgets
    from r2_symbol_importer.iaito_plugin import find_main_window, install_menu

    app = QtWidgets.QApplication.instance()
    if not app:
        app = QtWidgets.QApplication([])

    # Create a mock iaito main window with Tools menu
    main_win = QtWidgets.QMainWindow()
    main_win.setWindowTitle("iaito - Test")
    tools_menu = main_win.menuBar().addMenu("&Tools")
    file_menu = main_win.menuBar().addMenu("&File")

    # Verify discovery
    found_win = find_main_window()
    assert found_win is not None

    # Install menu action
    installed = install_menu(parent_window=main_win)
    assert installed is True

    # Verify action added to Tools menu
    actions = [a.text() for a in tools_menu.actions()]
    assert "Import C Symbols & Headers..." in actions

    # Verify idempotency (no duplicate actions added on second install_menu call)
    count_before = len(tools_menu.actions())
    installed_again = install_menu(parent_window=main_win)
    assert installed_again is True
    assert len(tools_menu.actions()) == count_before

    main_win.close()

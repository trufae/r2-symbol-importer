import os
import pytest
from r2_symbol_importer.qt_compat import QT_AVAILABLE

# Ensure Qt runs offscreen during test execution
os.environ["QT_QPA_PLATFORM"] = "offscreen"


@pytest.mark.skipif(not QT_AVAILABLE, reason="PySide/PyQt is not installed")
def test_iaito_gui_dialog_preview(sample_driver_path):
    from r2_symbol_importer.qt_compat import QtWidgets
    from r2_symbol_importer.iaito_plugin import SymbolImporterDialog

    app = QtWidgets.QApplication.instance()
    if not app:
        app = QtWidgets.QApplication([])

    dialog = SymbolImporterDialog(r2_instance=None)
    dialog.path_input.setText(str(sample_driver_path))
    dialog.run_preview()

    assert dialog.current_result is not None
    assert dialog.types_list.count() >= 2
    assert dialog.protos_list.count() == 4
    assert dialog.constants_table.rowCount() >= 7
    assert "PACKET_HEADER" in dialog.header_preview.toPlainText()
    dialog.close()

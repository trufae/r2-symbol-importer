"""
iaito GUI Plugin - Symbol & Type Acquisition Dialog and Menu Integration for radare2 / iaito.
Compatible with PySide6, PyQt6, PySide2, and PyQt5.
"""

import os
import sys
from pathlib import Path
from typing import Any, Optional

import r2pipe
from r2_symbol_importer.core.pipeline import ExtractionResult, SymbolPipeline
from r2_symbol_importer.core.preludes import PreludeType
from r2_symbol_importer.qt_compat import QAction, QT_AVAILABLE, QtCore, QtGui, QtWidgets, require_qt


class SymbolImporterDialog(QtWidgets.QDialog if QT_AVAILABLE else object):
    """iaito Qt Dialog for visual symbol, type, and IOCTL importation."""

    def __init__(self, r2_instance: Optional[Any] = None, parent: Optional[Any] = None):
        require_qt()
        super().__init__(parent)
        self.r2 = r2_instance
        self.current_result: Optional[ExtractionResult] = None

        self.setWindowTitle("iaito Symbol & Header Importer")
        self.resize(720, 520)
        self.setup_ui()

    def get_r2_session(self):
        if self.r2 is None:
            try:
                self.r2 = r2pipe.open()
            except Exception as e:
                self.log(f"Warning: Could not connect to active r2 session: {e}")
        return self.r2

    def setup_ui(self):
        main_layout = QtWidgets.QVBoxLayout(self)

        # 1. Target Selection Box
        path_group = QtWidgets.QGroupBox("Source C Header or Directory")
        path_layout = QtWidgets.QHBoxLayout(path_group)

        self.path_input = QtWidgets.QLineEdit()
        self.path_input.setPlaceholderText("Select C Header (.h, .i) or include folder...")
        
        btn_file = QtWidgets.QPushButton("Browse File...")
        btn_dir = QtWidgets.QPushButton("Browse Directory...")
        btn_file.clicked.connect(self.browse_file)
        btn_dir.clicked.connect(self.browse_dir)

        path_layout.addWidget(self.path_input)
        path_layout.addWidget(btn_file)
        path_layout.addWidget(btn_dir)
        main_layout.addWidget(path_group)

        # 2. Options Group Box
        options_group = QtWidgets.QGroupBox("Import Options & Prelude")
        options_layout = QtWidgets.QGridLayout(options_group)

        self.chk_types = QtWidgets.QCheckBox("Import Structs, Unions & Typedefs (`to`)")
        self.chk_types.setChecked(True)
        self.chk_protos = QtWidgets.QCheckBox("Import Function Signatures (`afs`)")
        self.chk_protos.setChecked(True)
        self.chk_match_funcs = QtWidgets.QCheckBox("Auto-match & seek existing session functions")
        self.chk_match_funcs.setChecked(True)
        self.chk_flags = QtWidgets.QCheckBox("Import #define Constants as Flags (`f const.*`)")
        self.chk_flags.setChecked(True)

        options_layout.addWidget(self.chk_types, 0, 0)
        options_layout.addWidget(self.chk_protos, 0, 1)
        options_layout.addWidget(self.chk_match_funcs, 1, 1)
        options_layout.addWidget(self.chk_flags, 1, 0)

        # Prelude selection combo
        prelude_label = QtWidgets.QLabel("Type Prelude Preset:")
        self.combo_prelude = QtWidgets.QComboBox()
        self.combo_prelude.addItem("Auto-detect", PreludeType.AUTO)
        self.combo_prelude.addItem("Windows Kernel / DDK", PreludeType.WINDOWS)
        self.combo_prelude.addItem("POSIX / Linux", PreludeType.POSIX)
        self.combo_prelude.addItem("Standard stdint / C", PreludeType.STDINT)
        self.combo_prelude.addItem("None", PreludeType.NONE)

        prelude_box = QtWidgets.QHBoxLayout()
        prelude_box.addWidget(prelude_label)
        prelude_box.addWidget(self.combo_prelude)
        prelude_box.addStretch()
        options_layout.addLayout(prelude_box, 2, 0, 1, 2)

        main_layout.addWidget(options_group)

        # 3. Tabbed Preview & Logs
        self.tab_widget = QtWidgets.QTabWidget()

        # Types Tab
        self.types_list = QtWidgets.QListWidget()
        self.tab_widget.addTab(self.types_list, "Types (0)")

        # Signatures Tab
        self.protos_list = QtWidgets.QListWidget()
        self.tab_widget.addTab(self.protos_list, "Signatures (0)")

        # Constants Tab
        self.constants_table = QtWidgets.QTableWidget()
        self.constants_table.setColumnCount(3)
        self.constants_table.setHorizontalHeaderLabels(["Name", "Hex Value", "Raw Expression"])
        self.constants_table.horizontalHeader().setStretchLastSection(True)
        self.tab_widget.addTab(self.constants_table, "Constants & Flags (0)")

        # C Header Tab
        self.header_preview = QtWidgets.QPlainTextEdit()
        self.header_preview.setReadOnly(True)
        self.header_preview.setFont(QtGui.QFont("Monospace", 9))
        self.tab_widget.addTab(self.header_preview, "Generated C Header")

        # Session Log Tab
        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)
        self.tab_widget.addTab(self.log_view, "Session Log")

        main_layout.addWidget(self.tab_widget)

        # 4. Status and Progress Bar
        status_box = QtWidgets.QHBoxLayout()
        self.status_lbl = QtWidgets.QLabel("Ready.")
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setVisible(False)
        status_box.addWidget(self.status_lbl)
        status_box.addWidget(self.progress_bar)
        main_layout.addLayout(status_box)

        # 5. Action Buttons
        btn_box = QtWidgets.QHBoxLayout()
        self.btn_preview = QtWidgets.QPushButton("Preview Extraction")
        self.btn_preview.clicked.connect(self.run_preview)

        self.btn_import = QtWidgets.QPushButton("Import Symbols into radare2")
        self.btn_import.setStyleSheet("font-weight: bold; background-color: #2b5b84; color: white; padding: 6px 14px;")
        self.btn_import.clicked.connect(self.run_import)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)

        btn_box.addWidget(self.btn_preview)
        btn_box.addStretch()
        btn_box.addWidget(self.btn_import)
        btn_box.addWidget(btn_close)
        main_layout.addLayout(btn_box)

    def log(self, message: str):
        self.log_view.append(message)

    def browse_file(self):
        file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select C Header", "", "C Headers (*.h *.i *.hpp);;All Files (*)"
        )
        if file:
            self.path_input.setText(file)

    def browse_dir(self):
        folder = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Header Include Directory")
        if folder:
            self.path_input.setText(folder)

    def _extract_current(self) -> Optional[ExtractionResult]:
        target = self.path_input.text().strip()
        if not target:
            self.status_lbl.setText("<font color='red'>Error: No path specified.</font>")
            return None

        p = Path(target)
        if not p.exists():
            self.status_lbl.setText("<font color='red'>Error: Path does not exist.</font>")
            return None

        prelude_val = self.combo_prelude.currentData()
        pipeline = SymbolPipeline(prelude_type=prelude_val)

        try:
            self.status_lbl.setText("Extracting symbols via Tree-sitter AST...")
            QtWidgets.QApplication.processEvents()
            result = pipeline.extract_from_path(p)
            self.current_result = result
            self._update_preview_tabs(result)
            return result
        except Exception as e:
            self.status_lbl.setText(f"<font color='red'>Extraction error: {e}</font>")
            self.log(f"[Error] {e}")
            return None

    def _update_preview_tabs(self, result: ExtractionResult):
        # Update Types Tab
        self.types_list.clear()
        for t in result.types:
            self.types_list.addItem(t.replace("\n", " ").strip())
        self.tab_widget.setTabText(0, f"Types ({len(result.types)})")

        # Update Signatures Tab
        self.protos_list.clear()
        for p in result.prototypes:
            self.protos_list.addItem(p.signature)
        self.tab_widget.setTabText(1, f"Signatures ({len(result.prototypes)})")

        # Update Constants Tab
        self.constants_table.setRowCount(len(result.constants))
        for row, c in enumerate(result.constants):
            self.constants_table.setItem(row, 0, QtWidgets.QTableWidgetItem(c.name))
            self.constants_table.setItem(row, 1, QtWidgets.QTableWidgetItem(c.hex_str))
            self.constants_table.setItem(row, 2, QtWidgets.QTableWidgetItem(c.raw_expression))
        self.tab_widget.setTabText(2, f"Constants & Flags ({len(result.constants)})")

        # Update C Header Tab
        self.header_preview.setPlainText(result.clean_header)

    def run_preview(self):
        result = self._extract_current()
        if result:
            self.status_lbl.setText(f"<font color='green'>Parsed: {result.summary}</font>")
            self.log(f"[Preview] Parsed {result.summary}")

    def run_import(self):
        result = self._extract_current()
        if not result:
            return

        r2 = self.get_r2_session()
        if not r2:
            self.status_lbl.setText("<font color='red'>Error: radare2 session unavailable.</font>")
            return

        pipeline = SymbolPipeline(prelude_type=self.combo_prelude.currentData())
        
        self.status_lbl.setText("Ingesting symbols into radare2...")
        QtWidgets.QApplication.processEvents()

        report = pipeline.apply_to_r2(
            r2,
            result,
            import_types=self.chk_types.isChecked(),
            import_protos=self.chk_protos.isChecked(),
            import_flags=self.chk_flags.isChecked(),
            match_functions=self.chk_match_funcs.isChecked()
        )

        self.log(f"[Import] Loaded {report.types_loaded} types into session.")
        self.log(f"[Import] Applied {report.prototypes_applied} function signatures.")
        if report.matched_functions:
            self.log(f"[Import] Matched {len(report.matched_functions)} functions: {', '.join(report.matched_functions)}")
        self.log(f"[Import] Flagged {report.constants_flagged} constants.")

        if report.errors:
            for err in report.errors:
                self.log(f"[Warning] {err}")
            self.status_lbl.setText(
                f"<font color='orange'>Imported with warnings: {report.types_loaded} types, "
                f"{report.prototypes_applied} signatures, {report.constants_flagged} flags.</font>"
            )
        else:
            self.status_lbl.setText(
                f"<font color='green'>Successfully imported {report.types_loaded} types, "
                f"{report.prototypes_applied} signatures, and {report.constants_flagged} flags!</font>"
            )


def find_main_window() -> Optional[QtWidgets.QMainWindow]:
    """Locates iaito's QMainWindow instance."""
    require_qt()
    app = QtWidgets.QApplication.instance()
    if not app:
        return None
    for widget in app.topLevelWidgets():
        if isinstance(widget, QtWidgets.QMainWindow):
            return widget
    return None


def install_menu(
    parent_window: Optional[QtWidgets.QMainWindow] = None,
    r2_instance: Optional[Any] = None
) -> bool:
    """
    Installs the 'Import C Symbols & Headers...' action into iaito's menu bar.
    Looks for an existing 'Tools' or 'Plugins' menu, or creates one if absent.
    Guards against duplicates if called repeatedly.
    """
    require_qt()
    main_win = parent_window or find_main_window()
    if not main_win:
        return False

    menu_bar = main_win.menuBar()
    target_menu = None

    # Look for Tools or Plugins menu
    for action in menu_bar.actions():
        title = action.text().replace("&", "").strip()
        if title in ("Tools", "Plugins"):
            target_menu = action.menu()
            break

    if not target_menu:
        target_menu = menu_bar.addMenu("&Tools")

    # Guard against duplicate action installation
    action_text = "Import C Symbols & Headers..."
    for act in target_menu.actions():
        if act.text() == action_text:
            return True

    import_action = QAction(action_text, main_win)
    import_action.setStatusTip("Extract and import C types, function signatures, and constants into session")
    import_action.triggered.connect(lambda: launch(r2_instance=r2_instance, parent=main_win))

    target_menu.addAction(import_action)
    return True


def get_iaito_plugin_dir() -> Path:
    """Returns the OS-appropriate user plugin directory for iaito."""
    home = Path.home()
    if sys.platform == "win32":
        app_data = os.environ.get("APPDATA")
        base = Path(app_data) if app_data else home / "AppData" / "Roaming"
        return base / "radareorg" / "iaito" / "plugins" / "python"
    elif sys.platform == "darwin":
        return home / "Library" / "Application Support" / "radareorg" / "iaito" / "plugins" / "python"
    else:
        # Linux / BSD / POSIX
        data_home = os.environ.get("XDG_DATA_HOME")
        base = Path(data_home) if data_home else home / ".local" / "share"
        return base / "radareorg" / "iaito" / "plugins" / "python"


def install_to_iaito_dir() -> Path:
    """
    Installs a bootstrap loader into iaito's plugin directory so that
    the Symbol Importer menu action is automatically registered whenever iaito launches.
    """
    target_dir = get_iaito_plugin_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    loader_file = target_dir / "r2_symbol_importer_loader.py"

    loader_code = '''# Auto-generated loader for r2-symbol-importer
try:
    import r2_symbol_importer.iaito_plugin as ip
    ip.install_menu()
except Exception as e:
    import sys
    print(f"[r2-symbol-importer] Failed to initialize iaito menu: {e}", file=sys.stderr)
'''
    loader_file.write_text(loader_code, encoding="utf-8")
    return loader_file


def launch(r2_instance: Optional[Any] = None, parent: Optional[Any] = None) -> Optional[SymbolImporterDialog]:
    """Entry point for iaito's GUI dialog."""
    require_qt()
    app = QtWidgets.QApplication.instance()
    is_standalone = False
    if not app:
        app = QtWidgets.QApplication(sys.argv)
        is_standalone = True

    dialog = SymbolImporterDialog(r2_instance=r2_instance, parent=parent)
    dialog.show()

    if is_standalone:
        app.exec()
    return dialog


if __name__ == "__main__":
    launch()

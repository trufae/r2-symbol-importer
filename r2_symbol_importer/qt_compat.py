"""
Qt compatibility layer supporting PySide6, PyQt6, PySide2, and PyQt5.
"""

import sys
from typing import Optional

QT_AVAILABLE: bool = False
QT_LIB: Optional[str] = None
QtWidgets = None
QtCore = None
QtGui = None
Signal = None
Slot = None
QAction = None

# Attempt imports in order of preference
for lib_name in ("PySide6", "PyQt6", "PySide2", "PyQt5"):
    try:
        if lib_name == "PySide6":
            from PySide6 import QtWidgets, QtCore, QtGui
            from PySide6.QtCore import Signal, Slot
        elif lib_name == "PyQt6":
            from PyQt6 import QtWidgets, QtCore, QtGui
            from PyQt6.QtCore import pyqtSignal as Signal, pyqtSlot as Slot
        elif lib_name == "PySide2":
            from PySide2 import QtWidgets, QtCore, QtGui
            from PySide2.QtCore import Signal, Slot
        elif lib_name == "PyQt5":
            from PyQt5 import QtWidgets, QtCore, QtGui
            from PyQt5.QtCore import pyqtSignal as Signal, pyqtSlot as Slot
        
        QT_AVAILABLE = True
        QT_LIB = lib_name

        # QAction location varies: QtGui in Qt6, QtWidgets in Qt5
        if hasattr(QtGui, "QAction"):
            QAction = QtGui.QAction
        elif hasattr(QtWidgets, "QAction"):
            QAction = QtWidgets.QAction
        break
    except ImportError:
        continue


def require_qt():
    """Raise a user-friendly error if no Qt bindings are installed."""
    if not QT_AVAILABLE:
        raise ImportError(
            "No Qt bindings found (PySide6, PyQt6, PySide2, or PyQt5). "
            "Please install PySide6 with: pip install PySide6"
        )

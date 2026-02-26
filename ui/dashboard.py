"""
Main Dashboard Window
=====================
Enterprise-grade dark-themed SOC-style interface with:
  - Gradient header
  - Sidebar navigation
  - Tabbed content area
  - Status bar with real-time indicators
"""

import sys
import os
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, QSize, pyqtSignal
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QIcon, QPainter,
    QLinearGradient, QBrush, QPen, QAction,
)
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame,
    QSizePolicy, QStatusBar, QMessageBox, QFileDialog,
    QApplication, QSplitter, QTextEdit,
)

from ui.scanner_tab import ScannerTab
from ui.simulation_tab import SimulationTab
from ui.extension_tab import ExtensionTab
from ui.threat_intel_tab import ThreatIntelTab
from ui.phished_data_tab import PhishedDataTab
from core.api_client import api_key_available
from database.db_manager import (
    initialize_database, get_scan_count, export_to_csv, clear_all_scans,
)

# ---------------------------------------------------------------------------
# Colour palette - White Theme
# ---------------------------------------------------------------------------
BG_DARK      = "#ffffff"
BG_CARD      = "#f8fafc"
BG_SIDEBAR   = "#f1f5f9"
ACCENT       = "#6366f1"
ACCENT_HOVER = "#4f46e5"
TEXT_PRIMARY  = "#0f172a"
TEXT_MUTED    = "#64748b"
SUCCESS      = "#22c55e"
WARNING      = "#f59e0b"
DANGER       = "#ef4444"
BORDER       = "#e2e8f0"


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------
GLOBAL_STYLE = f"""
QMainWindow {{
    background-color: {BG_DARK};
}}
QWidget {{
    color: {TEXT_PRIMARY};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    background-color: {BG_DARK};
}}
QLabel {{
    color: {TEXT_PRIMARY};
    background-color: transparent;
}}
QFrame {{
    background-color: transparent;
}}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    color: {TEXT_PRIMARY};
    font-size: 13px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {ACCENT};
}}
QPushButton {{
    background-color: {ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: {ACCENT_HOVER};
}}
QPushButton:pressed {{
    background-color: #4f46e5;
}}
QPushButton:disabled {{
    background-color: #e2e8f0;
    color: #64748b;
}}
QProgressBar {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER};
    border-radius: 4px;
    text-align: center;
    color: {TEXT_PRIMARY};
    font-size: 11px;
    height: 12px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 3px;
}}
QTabWidget::pane {{
    border: none;
    background: {BG_DARK};
}}
QStackedWidget {{
    background-color: {BG_DARK};
}}
QScrollArea {{
    background-color: transparent;
    border: none;
}}
QScrollBar:vertical {{
    background: {BG_CARD};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: #cbd5e1;
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QTableWidget {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER};
    gridline-color: {BORDER};
    color: {TEXT_PRIMARY};
    font-size: 12px;
}}
QTableWidget::item {{
    padding: 6px;
}}
QHeaderView::section {{
    background-color: #e2e8f0;
    color: {TEXT_PRIMARY};
    font-weight: 600;
    border: none;
    padding: 8px;
    font-size: 12px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_CARD};
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT};
    border: 1px solid {BORDER};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
"""


# ---------------------------------------------------------------------------
# Sidebar button
# ---------------------------------------------------------------------------
class SidebarButton(QPushButton):
    """Custom sidebar navigation button."""

    def __init__(self, text: str, icon_char: str = "", parent=None):
        super().__init__(parent)
        display = f"  {icon_char}  {text}" if icon_char else f"  {text}"
        self.setText(display)
        self.setCheckable(True)
        self.setFixedHeight(48)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {TEXT_MUTED};
                border: none;
                border-radius: 8px;
                text-align: left;
                padding-left: 12px;
                font-size: 14px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background: rgba(99,102,241,0.10);
                color: {TEXT_PRIMARY};
            }}
            QPushButton:checked {{
                background: rgba(99,102,241,0.18);
                color: {ACCENT_HOVER};
                font-weight: 600;
                border-left: 3px solid {ACCENT};
            }}
        """)


# ---------------------------------------------------------------------------
# Header widget with gradient
# ---------------------------------------------------------------------------
class GradientHeader(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(64)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        grad = QLinearGradient(0, 0, self.width(), 0)
        grad.setColorAt(0.0, QColor("#6366f1"))
        grad.setColorAt(0.5, QColor("#818cf8"))
        grad.setColorAt(1.0, QColor("#a5b4fc"))
        painter.fillRect(self.rect(), QBrush(grad))

        # Title
        painter.setPen(QPen(QColor("#ffffff")))
        font = QFont("Segoe UI", 16, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(
            20, 0, self.width() - 40, self.height(),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            "🛡️  Enterprise Phishing Analysis Platform"
        )

        # Subtitle
        sub_font = QFont("Segoe UI", 10)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor("#f8fafc")))
        painter.drawText(
            20, 0, self.width() - 40, self.height() + 28,
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            "Educational Edition  •  Security Research Toolkit"
        )

        # Status pill
        api_on = api_key_available()
        pill_text = "● API Connected" if api_on else "● Local Engine"
        pill_color = QColor(SUCCESS) if api_on else QColor(WARNING)
        painter.setPen(QPen(pill_color))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(
            self.width() - 200, 0, 180, self.height(),
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
            pill_text,
        )
        painter.end()


# ---------------------------------------------------------------------------
# Log viewer panel
# ---------------------------------------------------------------------------
class LogViewer(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 11))
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: #ffffff;
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: #475569;
                padding: 8px;
            }}
        """)
        self.setMaximumHeight(160)

    def log(self, message: str, level: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        color_map = {"INFO": "#64748b", "WARN": WARNING, "ERROR": DANGER, "OK": SUCCESS}
        color = color_map.get(level, TEXT_MUTED)
        self.append(
            f'<span style="color:{TEXT_MUTED}">[{ts}]</span> '
            f'<span style="color:{color}">[{level}]</span> {message}'
        )
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainDashboard(QMainWindow):
    """Primary application window."""

    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "Enterprise Phishing Analysis & Simulation Platform  —  Educational Edition"
        )
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self.setStyleSheet(GLOBAL_STYLE)

        # Database init
        initialize_database()

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # --- Header ---
        self.header = GradientHeader()
        root_layout.addWidget(self.header)

        # --- Body (sidebar + content) ---
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        body.addWidget(sidebar)

        # Right area: stacked content + log viewer
        right_area = QVBoxLayout()
        right_area.setContentsMargins(0, 0, 0, 0)
        right_area.setSpacing(0)

        self.stack = QStackedWidget()
        self.log_viewer = LogViewer()

        # Create tabs
        self.scanner_tab = ScannerTab(log_callback=self._log)
        self.simulation_tab = SimulationTab(log_callback=self._log)
        self.extension_tab = ExtensionTab(log_callback=self._log)
        self.threat_intel_tab = ThreatIntelTab(log_callback=self._log)
        self.phished_data_tab = PhishedDataTab(log_callback=self._log)

        self.stack.addWidget(self.scanner_tab)         # 0
        self.stack.addWidget(self.threat_intel_tab)     # 1
        self.stack.addWidget(self.simulation_tab)       # 2
        self.stack.addWidget(self.extension_tab)        # 3
        self.stack.addWidget(self.phished_data_tab)     # 4

        right_area.addWidget(self.stack, stretch=1)
        right_area.addWidget(self.log_viewer)

        body_widget = QWidget()
        body_widget.setLayout(body)
        body.addLayout(right_area)

        root_layout.addWidget(body_widget)

        # --- Status bar ---
        self._build_status_bar()

        # Timer for status updates
        self._status_timer = QTimer()
        self._status_timer.timeout.connect(self._update_status)
        self._status_timer.start(5000)

        # Log signal for thread-safe logging
        self.log_signal.connect(self.log_viewer.log)

        # Initial log
        self._log("Platform initialised successfully", "OK")
        self._log(
            f"Engine mode: {'VirusTotal API' if api_key_available() else 'Local Heuristic + ML'}",
            "INFO"
        )
        self._log(f"Total scans in database: {get_scan_count()}", "INFO")

    # --- Sidebar -----------------------------------------------------------

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(f"""
            QWidget {{
                background-color: {BG_SIDEBAR};
                border-right: 1px solid {BORDER};
            }}
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 16, 10, 16)
        layout.setSpacing(4)

        # Nav buttons
        self.btn_scanner   = SidebarButton("URL Scanner",       "🔍")
        self.btn_intel      = SidebarButton("Threat Intel",      "📊")
        self.btn_simulation = SidebarButton("Simulation Lab",    "🎓")
        self.btn_extension  = SidebarButton("Extension Test",    "🧩")
        self.btn_phished    = SidebarButton("Phished Data",      "🎣")

        self.sidebar_buttons = [
            self.btn_scanner, self.btn_intel,
            self.btn_simulation, self.btn_extension,
            self.btn_phished,
        ]

        for i, btn in enumerate(self.sidebar_buttons):
            btn.clicked.connect(lambda checked, idx=i: self._switch_tab(idx))
            layout.addWidget(btn)

        layout.addSpacing(20)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {BORDER};")
        layout.addWidget(sep)

        layout.addSpacing(10)

        # Export / Clear buttons
        btn_export = QPushButton("  📥  Export CSV")
        btn_export.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_MUTED};
                border: 1px solid {BORDER}; border-radius: 6px;
                padding: 8px; font-size: 12px; text-align: left;
            }}
            QPushButton:hover {{ background: rgba(99,102,241,0.1); color: {TEXT_PRIMARY}; }}
        """)
        btn_export.clicked.connect(self._export_csv)
        layout.addWidget(btn_export)

        btn_clear = QPushButton("  🗑️  Clear Data")
        btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {TEXT_MUTED};
                border: 1px solid {BORDER}; border-radius: 6px;
                padding: 8px; font-size: 12px; text-align: left;
            }}
            QPushButton:hover {{ background: rgba(239,68,68,0.1); color: {DANGER}; }}
        """)
        btn_clear.clicked.connect(self._clear_data)
        layout.addWidget(btn_clear)

        layout.addStretch()

        # Version label
        ver = QLabel("v2.0.0  •  Educational Use Only")
        ver.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(ver)

        # Set initial selection
        self.btn_scanner.setChecked(True)

        return sidebar

    # --- Status bar --------------------------------------------------------

    def _build_status_bar(self):
        sb = QStatusBar()
        sb.setStyleSheet(f"""
            QStatusBar {{
                background-color: #f8fafc;
                border-top: 1px solid {BORDER};
                color: {TEXT_MUTED};
                font-size: 11px;
                padding: 4px 12px;
            }}
        """)
        self.status_label = QLabel()
        sb.addWidget(self.status_label)
        self.setStatusBar(sb)
        self._update_status()

    def _update_status(self):
        count = get_scan_count()
        api_status = "API ✓" if api_key_available() else "Local Engine"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_label.setText(
            f"  Scans: {count}  |  Engine: {api_status}  |  {now}"
        )

    # --- Navigation --------------------------------------------------------

    def _switch_tab(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.sidebar_buttons):
            btn.setChecked(i == index)
        # Refresh threat intel when switching to it
        if index == 1:
            self.threat_intel_tab.refresh()

    # --- Actions -----------------------------------------------------------

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scans to CSV", "phishing_scans.csv",
            "CSV Files (*.csv)"
        )
        if path:
            count = export_to_csv(path)
            self._log(f"Exported {count} scans to {path}", "OK")
            QMessageBox.information(self, "Export Complete", f"Exported {count} records.")

    def _clear_data(self):
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Delete ALL scan records? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            count = clear_all_scans()
            self._log(f"Cleared {count} scan records", "WARN")
            self._update_status()

    # --- Logging -----------------------------------------------------------

    def _log(self, message: str, level: str = "INFO"):
        """Thread-safe log method."""
        self.log_signal.emit(message, level)

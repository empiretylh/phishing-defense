"""
Educational Phishing Simulation Tab
=====================================
Generate and serve safe phishing simulation pages for awareness training.
Provides preset templates and a live preview via the local HTTP server.
"""

import os
import webbrowser
import threading
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QComboBox, QFrame, QTextEdit,
    QGroupBox, QGridLayout,
)

from core.simulation_generator import (
    PRESETS, generate_simulation_page,
    start_simulation_server, stop_simulation_server, server_running,
)

# Colours
BG_CARD  = "#f8fafc"
BORDER   = "#e2e8f0"
TEXT_PRI  = "#0f172a"
TEXT_MUT  = "#475569"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"
ACCENT   = "#6366f1"


class SimulationTab(QWidget):
    """Educational phishing simulation lab."""

    status_signal = pyqtSignal(str, str)

    def __init__(self, log_callback: Callable = None, parent=None):
        super().__init__(parent)
        self._log = log_callback or (lambda m, l="INFO": None)
        self._current_html_dir = None
        self._server_url = None
        self.status_signal.connect(self._update_status)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 12)
        layout.setSpacing(16)

        # Header
        title = QLabel("🎓  Educational Phishing Simulation Lab")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Generate safe, clearly-marked simulation pages for security-awareness training.\n"
            "Credentials entered will be captured and stored in the 'Phished Data' tab to demonstrate attacker behavior."
        )
        subtitle.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px; margin-bottom: 4px;")
        layout.addWidget(subtitle)

        # Warning banner
        banner = QFrame()
        banner.setStyleSheet(f"""
            QFrame {{
                background: rgba(245,158,11,0.08);
                border: 1px solid rgba(245,158,11,0.3);
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        banner_layout = QHBoxLayout(banner)
        banner_label = QLabel(
            "⚠️  This module is for <b>educational purposes only</b>. "
            "All generated pages are clearly marked as simulations. "
            "Captured credentials are stored locally for demonstration purposes."
        )
        banner_label.setWordWrap(True)
        banner_label.setStyleSheet(f"color: {WARNING}; font-size: 12px;")
        banner_layout.addWidget(banner_label)
        layout.addWidget(banner)

        # --- Controls ---
        controls = QGroupBox("Simulation Configuration")
        controls.setStyleSheet(f"""
            QGroupBox {{
                background: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 16px;
                font-size: 13px;
                font-weight: 600;
                color: {TEXT_PRI};
            }}
            QGroupBox::title {{ padding: 0 8px; }}
        """)
        cg = QGridLayout(controls)
        cg.setSpacing(12)

        # Preset selector
        cg.addWidget(QLabel("Template Preset:"), 0, 0)
        self.preset_combo = QComboBox()
        for key, cfg in PRESETS.items():
            self.preset_combo.addItem(f"{cfg['brand_name']}  ({key})", key)
        self.preset_combo.setMinimumHeight(38)
        cg.addWidget(self.preset_combo, 0, 1)

        # Buttons
        self.btn_generate = QPushButton("📄  Generate Page")
        self.btn_generate.setMinimumHeight(42)
        self.btn_generate.clicked.connect(self._generate)
        cg.addWidget(self.btn_generate, 0, 2)

        self.btn_start = QPushButton("🚀  Start Server")
        self.btn_start.setMinimumHeight(42)
        self.btn_start.clicked.connect(self._toggle_server)
        cg.addWidget(self.btn_start, 1, 0)

        self.btn_open = QPushButton("🌐  Open in Browser")
        self.btn_open.setMinimumHeight(42)
        self.btn_open.setEnabled(False)
        self.btn_open.clicked.connect(self._open_browser)
        cg.addWidget(self.btn_open, 1, 1)

        self.server_status = QLabel("Server: Stopped")
        self.server_status.setStyleSheet(f"color: {TEXT_MUT}; font-size: 12px;")
        cg.addWidget(self.server_status, 1, 2)

        layout.addWidget(controls)

        # --- Preview / info ---
        preview_label = QLabel("Generated Page Info")
        preview_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(preview_label)

        self.info_box = QTextEdit()
        self.info_box.setReadOnly(True)
        self.info_box.setFont(QFont("Consolas", 11))
        self.info_box.setStyleSheet(f"""
            QTextEdit {{
                background: #ffffff;
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 10px;
                color: #475569;
            }}
        """)
        self.info_box.setMinimumHeight(180)
        self.info_box.setPlaceholderText("Generate a simulation page to see details here…")
        layout.addWidget(self.info_box)

        # Phishing indicators reference
        ref_label = QLabel("📖  Phishing Indicator Reference")
        ref_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(ref_label)

        ref_box = QTextEdit()
        ref_box.setReadOnly(True)
        ref_box.setMaximumHeight(150)
        ref_box.setFont(QFont("Segoe UI", 11))
        ref_box.setStyleSheet(f"""
            QTextEdit {{
                background: rgba(99,102,241,0.06);
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 10px;
                color: #475569;
            }}
        """)
        ref_box.setHtml("""
        <ul>
            <li><b>URL mismatch</b> — domain doesn't match the brand</li>
            <li><b>Missing HTTPS</b> — legitimate sites use encryption</li>
            <li><b>Urgency language</b> — "Act now", "Account suspended"</li>
            <li><b>Generic greeting</b> — "Dear User" instead of your name</li>
            <li><b>Poor spelling / grammar</b> — common in phishing kits</li>
            <li><b>Suspicious attachments</b> — unexpected file downloads</li>
            <li><b>Request for credentials</b> — legitimate services rarely ask via email</li>
        </ul>
        """)
        layout.addWidget(ref_box)

        layout.addStretch()

    # --- Actions -----------------------------------------------------------

    def _generate(self):
        preset_key = self.preset_combo.currentData()
        self._log(f"Generating simulation page: {preset_key}", "INFO")

        html_path = generate_simulation_page(preset=preset_key)
        self._current_html_dir = os.path.dirname(html_path)

        self.info_box.clear()
        self.info_box.append(f"✅  Page generated successfully\n")
        self.info_box.append(f"  Template : {preset_key}")
        self.info_box.append(f"  Brand    : {PRESETS[preset_key]['brand_name']}")
        self.info_box.append(f"  File     : {html_path}")
        self.info_box.append(f"  Directory: {self._current_html_dir}")
        self.info_box.append(f"\n  Features:")
        self.info_box.append(f"  • Prominent educational banner at top")
        self.info_box.append(f"  • Credential capture enabled (for demonstration)")
        self.info_box.append(f"  • View captured data in 'Phished Data' tab")
        self.info_box.append(f"  • Post-submit awareness message")
        self.info_box.append(f"  • Phishing indicator explanations")

        self._log(f"Simulation page saved to {html_path}", "OK")

    def _toggle_server(self):
        if server_running():
            stop_simulation_server()
            self.btn_start.setText("🚀  Start Server")
            self.btn_open.setEnabled(False)
            self._server_url = None
            self.server_status.setText("Server: Stopped")
            self.server_status.setStyleSheet(f"color: {TEXT_MUT}; font-size: 12px;")
            self._log("Simulation server stopped", "INFO")
        else:
            if not self._current_html_dir:
                self._log("Generate a page first before starting the server", "WARN")
                return
            try:
                self._server_url = start_simulation_server(self._current_html_dir)
                self.btn_start.setText("⏹  Stop Server")
                self.btn_open.setEnabled(True)
                self.server_status.setText(f"Server: Running at {self._server_url}")
                self.server_status.setStyleSheet(f"color: {SUCCESS}; font-size: 12px;")
                self._log(f"Simulation server started at {self._server_url}", "OK")
            except Exception as e:
                self._log(f"Failed to start server: {e}", "ERROR")

    def _open_browser(self):
        if self._server_url:
            webbrowser.open(self._server_url)
            self._log(f"Opened browser: {self._server_url}", "INFO")

    def _update_status(self, text: str, level: str):
        self._log(text, level)

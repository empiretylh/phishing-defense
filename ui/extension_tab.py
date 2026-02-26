"""
Chrome Extension Testing Tab
==============================
UI panel for testing Chrome extensions against phishing detection.
"""

import os
import threading
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFrame, QTextEdit,
    QGroupBox, QGridLayout, QFileDialog,
)

from core.chrome_tester import (
    detect_chrome_path, chrome_available, get_chrome_version,
    validate_extension_manifest, launch_chrome_test, generate_test_report,
)

BG_CARD = "#f8fafc"
BORDER  = "#e2e8f0"
TEXT_PRI = "#0f172a"
TEXT_MUT = "#475569"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER  = "#ef4444"


class ExtensionTab(QWidget):
    """Chrome extension testing panel."""

    report_ready = pyqtSignal(dict)

    def __init__(self, log_callback: Callable = None, parent=None):
        super().__init__(parent)
        self._log = log_callback or (lambda m, l="INFO": None)
        self.report_ready.connect(self._show_report)
        self._build_ui()
        self._detect_chrome()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 12)
        layout.setSpacing(16)

        # Title
        title = QLabel("🧩  Chrome Extension Testing Module")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Test Chrome extensions for phishing detection capabilities. "
            "Only localhost test URLs are permitted."
        )
        subtitle.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px; margin-bottom: 4px;")
        layout.addWidget(subtitle)

        # Chrome info
        chrome_box = QGroupBox("Chrome Detection")
        chrome_box.setStyleSheet(f"""
            QGroupBox {{
                background: {BG_CARD}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 16px;
                font-size: 13px; font-weight: 600; color: {TEXT_PRI};
            }}
            QGroupBox::title {{ padding: 0 8px; }}
        """)
        ci = QGridLayout(chrome_box)

        self.chrome_status = QLabel("Detecting…")
        ci.addWidget(QLabel("Status:"), 0, 0)
        ci.addWidget(self.chrome_status, 0, 1)

        self.chrome_path_label = QLabel("—")
        ci.addWidget(QLabel("Path:"), 1, 0)
        ci.addWidget(self.chrome_path_label, 1, 1)

        self.chrome_version_label = QLabel("—")
        ci.addWidget(QLabel("Version:"), 2, 0)
        ci.addWidget(self.chrome_version_label, 2, 1)

        layout.addWidget(chrome_box)

        # Extension testing
        test_box = QGroupBox("Extension Testing")
        test_box.setStyleSheet(chrome_box.styleSheet())
        tl = QGridLayout(test_box)

        tl.addWidget(QLabel("Extension Dir:"), 0, 0)
        ext_row = QHBoxLayout()
        self.ext_path_input = QLineEdit()
        self.ext_path_input.setPlaceholderText("Path to unpacked extension directory (optional)")
        ext_row.addWidget(self.ext_path_input, stretch=1)

        browse_btn = QPushButton("Browse…")
        browse_btn.setMinimumWidth(90)
        browse_btn.clicked.connect(self._browse_extension)
        ext_row.addWidget(browse_btn)
        tl.addLayout(ext_row, 0, 1)

        tl.addWidget(QLabel("Test URL:"), 1, 0)
        self.test_url_input = QLineEdit()
        self.test_url_input.setText("http://127.0.0.1:8080/phishing-test")
        self.test_url_input.setPlaceholderText("http://127.0.0.1:8080/...")
        tl.addWidget(self.test_url_input, 1, 1)

        btn_row = QHBoxLayout()
        self.btn_validate = QPushButton("✅  Validate Manifest")
        self.btn_validate.setMinimumHeight(40)
        self.btn_validate.clicked.connect(self._validate_manifest)
        btn_row.addWidget(self.btn_validate)

        self.btn_launch = QPushButton("🚀  Launch Test")
        self.btn_launch.setMinimumHeight(40)
        self.btn_launch.clicked.connect(self._run_test)
        btn_row.addWidget(self.btn_launch)

        self.btn_full_report = QPushButton("📋  Full Report")
        self.btn_full_report.setMinimumHeight(40)
        self.btn_full_report.clicked.connect(self._run_full_report)
        btn_row.addWidget(self.btn_full_report)

        tl.addLayout(btn_row, 2, 0, 1, 2)
        layout.addWidget(test_box)

        # Output
        out_label = QLabel("Test Results")
        out_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(out_label)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setFont(QFont("Consolas", 11))
        self.output_box.setStyleSheet(f"""
            QTextEdit {{
                background: #ffffff; border: 1px solid {BORDER};
                border-radius: 6px; padding: 10px; color: #475569;
            }}
        """)
        self.output_box.setPlaceholderText("Test results will appear here…")
        layout.addWidget(self.output_box, stretch=1)

    # --- Chrome detection ---

    def _detect_chrome(self):
        path = detect_chrome_path()
        if path:
            self.chrome_status.setText("✅ Chrome detected")
            self.chrome_status.setStyleSheet(f"color: {SUCCESS}; font-weight: 600;")
            self.chrome_path_label.setText(path)
            version = get_chrome_version()
            self.chrome_version_label.setText(version or "Unknown")
            self._log(f"Chrome detected: {path}", "OK")
        else:
            self.chrome_status.setText("❌ Chrome not found")
            self.chrome_status.setStyleSheet(f"color: {DANGER}; font-weight: 600;")
            self._log("Chrome not found on this system", "WARN")

    # --- Actions ---

    def _browse_extension(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Extension Directory")
        if dir_path:
            self.ext_path_input.setText(dir_path)

    def _validate_manifest(self):
        ext_dir = self.ext_path_input.text().strip()
        if not ext_dir or not os.path.isdir(ext_dir):
            self._log("Please select a valid extension directory", "WARN")
            return

        result = validate_extension_manifest(ext_dir)
        self.output_box.clear()
        self.output_box.append("=== Manifest Validation ===\n")

        if result["valid"]:
            self.output_box.append("✅  Manifest is VALID\n")
        else:
            self.output_box.append("❌  Manifest is INVALID\n")

        if result["errors"]:
            self.output_box.append("Errors:")
            for e in result["errors"]:
                self.output_box.append(f"  ❌ {e}")

        if result["warnings"]:
            self.output_box.append("\nWarnings:")
            for w in result["warnings"]:
                self.output_box.append(f"  ⚠️ {w}")

        if result["manifest"]:
            m = result["manifest"]
            self.output_box.append(f"\nManifest Version : {m.get('manifest_version', '?')}")
            self.output_box.append(f"Name             : {m.get('name', '?')}")
            self.output_box.append(f"Version          : {m.get('version', '?')}")
            self.output_box.append(f"Permissions      : {m.get('permissions', [])}")

        self._log(
            f"Manifest validation: {'VALID' if result['valid'] else 'INVALID'}",
            "OK" if result["valid"] else "WARN"
        )

    def _run_test(self):
        test_url = self.test_url_input.text().strip()
        ext_dir = self.ext_path_input.text().strip() or None

        if not chrome_available():
            self._log("Chrome not available", "ERROR")
            return

        self._log(f"Launching Chrome test: {test_url}", "INFO")
        self.btn_launch.setEnabled(False)
        self.btn_launch.setText("Testing…")

        def _do():
            result = launch_chrome_test(test_url, ext_dir)
            self.report_ready.emit({"type": "launch", "data": result})

        threading.Thread(target=_do, daemon=True).start()

    def _run_full_report(self):
        ext_dir = self.ext_path_input.text().strip() or None
        test_url = self.test_url_input.text().strip()

        self._log("Generating full extension test report…", "INFO")
        self.btn_full_report.setEnabled(False)
        self.btn_full_report.setText("Running…")

        def _do():
            report = generate_test_report(ext_dir, test_url)
            self.report_ready.emit({"type": "full", "data": report})

        threading.Thread(target=_do, daemon=True).start()

    def _show_report(self, payload: dict):
        self.btn_launch.setEnabled(True)
        self.btn_launch.setText("🚀  Launch Test")
        self.btn_full_report.setEnabled(True)
        self.btn_full_report.setText("📋  Full Report")

        self.output_box.clear()
        rtype = payload.get("type", "")
        data = payload.get("data", {})

        if rtype == "launch":
            self.output_box.append("=== Chrome Launch Test ===\n")
            self.output_box.append(f"  Launched   : {data.get('launched')}")
            self.output_box.append(f"  Chrome     : {data.get('chrome_path')}")
            self.output_box.append(f"  Test URL   : {data.get('test_url')}")
            self.output_box.append(f"  Duration   : {data.get('duration', 0):.1f}s")
            self.output_box.append(f"\n  Notes:")
            for n in data.get("notes", []):
                self.output_box.append(f"    • {n}")

        elif rtype == "full":
            self.output_box.append("=== Full Extension Test Report ===\n")
            self.output_box.append(f"  Chrome detected : {data.get('chrome_detected')}")
            self.output_box.append(f"  Chrome version  : {data.get('chrome_version')}")
            self.output_box.append(f"  Overall status  : {data.get('overall_status')}")

            mv = data.get("manifest_validation")
            if mv:
                self.output_box.append(f"\n  Manifest valid  : {mv.get('valid')}")
                for e in mv.get("errors", []):
                    self.output_box.append(f"    ❌ {e}")
                for w in mv.get("warnings", []):
                    self.output_box.append(f"    ⚠️ {w}")

            lr = data.get("launch_result")
            if lr:
                self.output_box.append(f"\n  Launch result   : {'✅' if lr.get('launched') else '❌'}")
                for n in lr.get("notes", []):
                    self.output_box.append(f"    • {n}")

        self._log("Test report generated", "OK")

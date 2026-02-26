"""
URL Scanner Tab
===============
Full-featured phishing URL analysis panel with:
  - URL input and scan controls
  - Circular risk gauge
  - Classification badge
  - Engine breakdown details
  - Feature list
  - Reasoning output
  - Background scan queue
"""

import math
import threading
from typing import Callable, Dict, Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QRectF
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QPen, QBrush,
    QConicalGradient, QLinearGradient,
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QScrollArea,
    QGridLayout, QSizePolicy, QTextEdit, QProgressBar,
)

from core.api_client import api_key_available, scan_url
from core.heuristic_engine import analyze_url
from core.ml_engine import model_available, predict
from database.db_manager import insert_scan

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
BG_CARD  = "#f8fafc"
BORDER   = "#e2e8f0"
ACCENT   = "#6366f1"
TEXT_PRI  = "#0f172a"
TEXT_MUT  = "#475569"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"


def _risk_color(score: float) -> QColor:
    if score < 30:
        return QColor(SUCCESS)
    elif score < 65:
        return QColor(WARNING)
    return QColor(DANGER)


# ---------------------------------------------------------------------------
# Circular risk gauge widget
# ---------------------------------------------------------------------------
class RiskGauge(QWidget):
    """Animated circular gauge showing 0–100 risk score."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(200, 200)
        self._score = 0.0
        self._target = 0.0
        self._label = "—"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)

    def set_score(self, score: float, label: str = ""):
        self._target = max(0.0, min(100.0, score))
        self._label = label
        self._timer.start(16)  # ~60 fps

    def _animate(self):
        diff = self._target - self._score
        if abs(diff) < 0.5:
            self._score = self._target
            self._timer.stop()
        else:
            self._score += diff * 0.12
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 16

        # Background arc
        pen_bg = QPen(QColor("#e2e8f0"), 12)
        pen_bg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
        painter.drawArc(rect, 225 * 16, -270 * 16)

        # Filled arc
        color = _risk_color(self._score)
        pen_fg = QPen(color, 12)
        pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_fg)
        sweep = int(-270 * (self._score / 100) * 16)
        painter.drawArc(rect, 225 * 16, sweep)

        # Score text
        painter.setPen(QPen(QColor(TEXT_PRI)))
        painter.setFont(QFont("Segoe UI", 32, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(self._score)}")

        # Label
        label_rect = QRectF(cx - radius, cy + 20, radius * 2, 30)
        painter.setFont(QFont("Segoe UI", 11))
        painter.setPen(QPen(color))
        painter.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, self._label)

        painter.end()


# ---------------------------------------------------------------------------
# Feature card
# ---------------------------------------------------------------------------
class FeatureCard(QFrame):
    def __init__(self, title: str, value: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(f"color: {TEXT_MUT}; font-size: 11px;")
        lbl_value = QLabel(value)
        lbl_value.setStyleSheet(f"color: {TEXT_PRI}; font-size: 15px; font-weight: 600;")
        lbl_value.setObjectName("val")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_value)

    def set_value(self, value: str):
        lbl = self.findChild(QLabel, "val")
        if lbl:
            lbl.setText(value)


# ---------------------------------------------------------------------------
# Scanner Tab
# ---------------------------------------------------------------------------
class ScannerTab(QWidget):
    """URL Intelligence Scanner panel."""

    result_ready = pyqtSignal(dict)

    def __init__(self, log_callback: Callable = None, parent=None):
        super().__init__(parent)
        self._log = log_callback or (lambda m, l="INFO": None)
        self._scanning = False

        self.result_ready.connect(self._display_result)
        self._build_ui()

    # --- UI construction ---------------------------------------------------

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 12)
        layout.setSpacing(16)

        # Title
        title = QLabel("🔍  URL Intelligence Scanner")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "Analyse any URL for phishing indicators using API or local heuristic engine"
        )
        subtitle.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px; margin-bottom: 8px;")
        layout.addWidget(subtitle)

        # --- Input row ---
        input_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL to analyse (e.g. https://example.com/login)")
        self.url_input.setMinimumHeight(44)
        self.url_input.setFont(QFont("Segoe UI", 13))
        self.url_input.returnPressed.connect(self._start_scan)
        input_row.addWidget(self.url_input, stretch=1)

        self.scan_btn = QPushButton("⚡ Analyse")
        self.scan_btn.setMinimumHeight(44)
        self.scan_btn.setMinimumWidth(130)
        self.scan_btn.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.scan_btn.clicked.connect(self._start_scan)
        input_row.addWidget(self.scan_btn)

        layout.addLayout(input_row)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setVisible(False)
        self.progress.setMaximumHeight(4)
        layout.addWidget(self.progress)

        # --- Results area (scrollable) ---
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll_content = QWidget()
        self.results_layout = QVBoxLayout(scroll_content)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(16)

        # Top row: gauge + classification
        top_row = QHBoxLayout()
        top_row.setSpacing(24)

        self.gauge = RiskGauge()
        top_row.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignTop)

        # Right side info cards
        info_grid = QGridLayout()
        info_grid.setSpacing(12)

        self.card_classification = FeatureCard("Classification", "—")
        self.card_confidence = FeatureCard("Confidence", "—")
        self.card_engine = FeatureCard("Detection Engine", "—")
        self.card_risk = FeatureCard("Risk Score", "—")

        info_grid.addWidget(self.card_classification, 0, 0)
        info_grid.addWidget(self.card_confidence, 0, 1)
        info_grid.addWidget(self.card_engine, 1, 0)
        info_grid.addWidget(self.card_risk, 1, 1)

        top_row.addLayout(info_grid)
        top_row.addStretch()

        self.results_layout.addLayout(top_row)

        # Reasoning panel
        self.reasoning_label = QLabel("Detection Reasoning")
        self.reasoning_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.results_layout.addWidget(self.reasoning_label)

        self.reasoning_box = QTextEdit()
        self.reasoning_box.setReadOnly(True)
        self.reasoning_box.setMaximumHeight(180)
        self.reasoning_box.setFont(QFont("Consolas", 11))
        self.reasoning_box.setStyleSheet(f"""
            QTextEdit {{
                background: #ffffff;
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 10px;
                color: #475569;
            }}
        """)
        self.results_layout.addWidget(self.reasoning_box)

        # Features panel
        self.features_label = QLabel("Feature Breakdown")
        self.features_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        self.results_layout.addWidget(self.features_label)

        self.features_box = QTextEdit()
        self.features_box.setReadOnly(True)
        self.features_box.setMaximumHeight(200)
        self.features_box.setFont(QFont("Consolas", 11))
        self.features_box.setStyleSheet(f"""
            QTextEdit {{
                background: #ffffff;
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 10px;
                color: #475569;
            }}
        """)
        self.results_layout.addWidget(self.features_box)

        self.results_layout.addStretch()

        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, stretch=1)

    # --- Scan logic --------------------------------------------------------

    def _start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self._log("No URL entered", "WARN")
            return
        if self._scanning:
            self._log("Scan already in progress", "WARN")
            return

        self._scanning = True
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning…")
        self.progress.setVisible(True)
        self._log(f"Starting scan: {url}", "INFO")

        thread = threading.Thread(target=self._run_scan, args=(url,), daemon=True)
        thread.start()

    def _run_scan(self, url: str):
        """Execute scan in background thread."""
        result: Dict = {}
        try:
            # Strategy: API → ML → Heuristic
            if api_key_available():
                try:
                    result = scan_url(url)
                    self._log("VirusTotal API scan complete", "OK")
                except Exception as e:
                    self._log(f"API error: {e} — falling back to local engine", "WARN")
                    result = {}

            if not result and model_available():
                ml_result = predict(url)
                if ml_result:
                    result = ml_result
                    result["api_used"] = False
                    self._log("ML model prediction complete", "OK")

            if not result:
                result = analyze_url(url)
                result["api_used"] = False
                self._log("Heuristic analysis complete", "OK")

            # Persist to database
            insert_scan(
                url=url,
                risk_score=result.get("risk_score", 0),
                classification=result.get("classification", "Unknown"),
                confidence=result.get("confidence", 0),
                api_used=result.get("api_used", False),
                engine=result.get("engine", ""),
                reasoning="; ".join(result.get("reasoning", [])),
            )

        except Exception as e:
            result = {
                "risk_score": 0,
                "classification": "Error",
                "confidence": 0,
                "engine": "N/A",
                "reasoning": [str(e)],
                "features": {},
            }
            self._log(f"Scan error: {e}", "ERROR")

        self.result_ready.emit(result)

    # --- Display results ---------------------------------------------------

    def _display_result(self, result: Dict):
        self._scanning = False
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("⚡ Analyse")
        self.progress.setVisible(False)

        score = result.get("risk_score", 0)
        classification = result.get("classification", "Unknown")
        confidence = result.get("confidence", 0)
        engine = result.get("engine", "Unknown")
        reasoning = result.get("reasoning", [])
        features = result.get("features", {})

        # Gauge
        self.gauge.set_score(score, classification)

        # Cards
        self.card_classification.set_value(classification)
        color = _risk_color(score).name()
        self.card_classification.findChild(QLabel, "val").setStyleSheet(
            f"color: {color}; font-size: 15px; font-weight: 700;"
        )

        self.card_confidence.set_value(f"{confidence:.1%}")
        self.card_engine.set_value(engine)
        self.card_risk.set_value(f"{score:.1f} / 100")

        # Reasoning
        self.reasoning_box.clear()
        for i, r in enumerate(reasoning, 1):
            self.reasoning_box.append(f"  {i}. {r}")

        # Features
        self.features_box.clear()
        if features:
            for k, v in features.items():
                self.features_box.append(f"  {k:.<30s} {v}")
        else:
            self.features_box.append("  (No feature details available)")

"""
Threat Intelligence Tab
========================
Analytics dashboard showing:
  - Recent scans table
  - Risk trend chart (matplotlib)
  - Classification pie chart
  - Top suspicious keywords bar chart
  - API vs local engine ratio
"""

import io
from typing import Callable, List, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap, QImage
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QScrollArea, QTableWidget, QTableWidgetItem,
    QHeaderView, QSizePolicy, QGridLayout,
)

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg

from database.db_manager import (
    get_recent_scans, get_classification_counts,
    get_risk_trend, get_top_keywords, get_api_usage_ratio,
    get_scan_count,
)

BG_CARD  = "#f8fafc"
BORDER   = "#e2e8f0"
TEXT_PRI  = "#0f172a"
TEXT_MUT  = "#475569"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"
ACCENT   = "#6366f1"


def _fig_to_pixmap(fig: Figure, dpi: int = 100) -> QPixmap:
    """Render a matplotlib figure to a QPixmap."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight",
                facecolor="#f8fafc", edgecolor="none")
    buf.seek(0)
    img = QImage.fromData(buf.read())
    plt.close(fig)
    return QPixmap.fromImage(img)


class ChartWidget(QLabel):
    """Label that displays a matplotlib chart rendered as a pixmap."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                background: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                padding: 8px;
            }}
        """)
        self.setMinimumHeight(240)


class ThreatIntelTab(QWidget):
    """Threat intelligence analytics dashboard."""

    def __init__(self, log_callback: Callable = None, parent=None):
        super().__init__(parent)
        self._log = log_callback or (lambda m, l="INFO": None)
        self._build_ui()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 12)
        outer.setSpacing(16)

        # Title
        title = QLabel("📊  Threat Intelligence Dashboard")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        outer.addWidget(title)

        subtitle = QLabel("Aggregated analytics from all scans performed on this system")
        subtitle.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px; margin-bottom: 4px;")
        outer.addWidget(subtitle)

        # Refresh button
        from PyQt6.QtWidgets import QPushButton
        refresh_btn = QPushButton("🔄  Refresh Dashboard")
        refresh_btn.setMaximumWidth(200)
        refresh_btn.clicked.connect(self.refresh)
        outer.addWidget(refresh_btn)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setSpacing(16)

        # Stats row
        self.stats_layout = QHBoxLayout()
        self.stat_total = self._make_stat_card("Total Scans", "0")
        self.stat_phishing = self._make_stat_card("Phishing", "0")
        self.stat_suspicious = self._make_stat_card("Suspicious", "0")
        self.stat_safe = self._make_stat_card("Safe", "0")
        self.stats_layout.addWidget(self.stat_total)
        self.stats_layout.addWidget(self.stat_phishing)
        self.stats_layout.addWidget(self.stat_suspicious)
        self.stats_layout.addWidget(self.stat_safe)
        self.content_layout.addLayout(self.stats_layout)

        # Charts row
        charts_grid = QGridLayout()
        charts_grid.setSpacing(16)

        self.trend_chart = ChartWidget()
        self.pie_chart = ChartWidget()
        self.keyword_chart = ChartWidget()
        self.ratio_chart = ChartWidget()

        charts_grid.addWidget(self._wrap_chart("Risk Score Trend (30 days)", self.trend_chart), 0, 0)
        charts_grid.addWidget(self._wrap_chart("Classification Distribution", self.pie_chart), 0, 1)
        charts_grid.addWidget(self._wrap_chart("Top Suspicious Keywords", self.keyword_chart), 1, 0)
        charts_grid.addWidget(self._wrap_chart("API vs Local Engine Usage", self.ratio_chart), 1, 1)

        self.content_layout.addLayout(charts_grid)

        # Recent scans table
        table_label = QLabel("Recent Scans")
        table_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.content_layout.addWidget(table_label)

        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(7)
        self.scans_table.setHorizontalHeaderLabels([
            "ID", "URL", "Risk", "Classification", "Engine", "API", "Timestamp"
        ])
        self.scans_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.scans_table.setAlternatingRowColors(True)
        self.scans_table.setStyleSheet(f"""
            QTableWidget {{
                alternate-background-color: #ffffff;
            }}
        """)
        self.scans_table.setMinimumHeight(250)
        self.content_layout.addWidget(self.scans_table)

        self.content_layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

    # --- Helpers ---

    def _make_stat_card(self, title: str, value: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: {BG_CARD}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 16px;
            }}
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(f"color: {TEXT_MUT}; font-size: 11px;")
        lbl_v = QLabel(value)
        lbl_v.setObjectName("stat_val")
        lbl_v.setStyleSheet(f"color: {TEXT_PRI}; font-size: 24px; font-weight: 700;")
        layout.addWidget(lbl_t)
        layout.addWidget(lbl_v)
        return card

    def _wrap_chart(self, title: str, chart_widget: ChartWidget) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {BG_CARD}; border: 1px solid {BORDER};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color: {TEXT_PRI}; font-size: 12px; font-weight: 600;")
        layout.addWidget(lbl)
        layout.addWidget(chart_widget)
        return frame

    # --- Refresh ---

    def refresh(self):
        """Refresh all dashboard data and charts."""
        self._log("Refreshing threat intelligence dashboard…", "INFO")

        # Stats
        counts = get_classification_counts()
        total = get_scan_count()
        self.stat_total.findChild(QLabel, "stat_val").setText(str(total))
        self.stat_phishing.findChild(QLabel, "stat_val").setText(str(counts.get("Phishing", 0)))
        self.stat_suspicious.findChild(QLabel, "stat_val").setText(str(counts.get("Suspicious", 0)))
        self.stat_safe.findChild(QLabel, "stat_val").setText(str(counts.get("Safe", 0)))

        # Trend chart
        self._render_trend_chart()

        # Pie chart
        self._render_pie_chart(counts)

        # Keywords chart
        self._render_keyword_chart()

        # API ratio chart
        self._render_ratio_chart()

        # Table
        self._populate_table()

        self._log("Dashboard refreshed", "OK")

    def _render_trend_chart(self):
        data = get_risk_trend(30)
        fig, ax = plt.subplots(figsize=(5, 2.5))
        fig.patch.set_facecolor("#f8fafc")
        ax.set_facecolor("#f8fafc")

        if data:
            days = [d[0][-5:] for d in data]  # MM-DD
            scores = [d[1] for d in data]
            ax.fill_between(range(len(scores)), scores, alpha=0.15, color="#6366f1")
            ax.plot(scores, color="#6366f1", linewidth=2, marker="o", markersize=4)
            ax.set_xticks(range(len(days)))
            ax.set_xticklabels(days, rotation=45, fontsize=7, color="#475569")
        else:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                    color="#475569", fontsize=12, transform=ax.transAxes)

        ax.tick_params(colors="#475569", labelsize=8)
        ax.spines[:].set_color("#e2e8f0")
        ax.set_ylabel("Avg Risk", color="#475569", fontsize=9)
        fig.tight_layout()
        self.trend_chart.setPixmap(_fig_to_pixmap(fig))

    def _render_pie_chart(self, counts: dict):
        fig, ax = plt.subplots(figsize=(4, 2.5))
        fig.patch.set_facecolor("#f8fafc")

        if counts:
            labels = list(counts.keys())
            sizes = list(counts.values())
            colors_map = {"Safe": SUCCESS, "Suspicious": WARNING, "Phishing": DANGER}
            colors = [colors_map.get(l, ACCENT) for l in labels]
            ax.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%",
                   textprops={"color": "#0f172a", "fontsize": 10},
                   startangle=90, pctdistance=0.75)
        else:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                    color="#475569", fontsize=12, transform=ax.transAxes)

        fig.tight_layout()
        self.pie_chart.setPixmap(_fig_to_pixmap(fig))

    def _render_keyword_chart(self):
        data = get_top_keywords(8)
        fig, ax = plt.subplots(figsize=(5, 2.5))
        fig.patch.set_facecolor("#f8fafc")
        ax.set_facecolor("#f8fafc")

        if data:
            kws = [d[0] for d in data]
            cnts = [d[1] for d in data]
            bars = ax.barh(kws, cnts, color="#6366f1", height=0.6)
            ax.invert_yaxis()
        else:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                    color="#475569", fontsize=12, transform=ax.transAxes)

        ax.tick_params(colors="#475569", labelsize=9)
        ax.spines[:].set_color("#e2e8f0")
        fig.tight_layout()
        self.keyword_chart.setPixmap(_fig_to_pixmap(fig))

    def _render_ratio_chart(self):
        api_count, local_count = get_api_usage_ratio()
        fig, ax = plt.subplots(figsize=(4, 2.5))
        fig.patch.set_facecolor("#f8fafc")

        if api_count + local_count > 0:
            ax.bar(["API", "Local"], [api_count, local_count],
                   color=[ACCENT, WARNING], width=0.5)
        else:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                    color="#475569", fontsize=12, transform=ax.transAxes)

        ax.set_facecolor("#f8fafc")
        ax.tick_params(colors="#475569", labelsize=10)
        ax.spines[:].set_color("#e2e8f0")
        fig.tight_layout()
        self.ratio_chart.setPixmap(_fig_to_pixmap(fig))

    def _populate_table(self):
        scans = get_recent_scans(50)
        self.scans_table.setRowCount(len(scans))

        for row, scan in enumerate(scans):
            items = [
                str(scan.get("id", "")),
                scan.get("url", ""),
                f"{scan.get('risk_score', 0):.1f}",
                scan.get("classification", ""),
                scan.get("engine", ""),
                "Yes" if scan.get("api_used") else "No",
                scan.get("timestamp", ""),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                if col == 3:  # Classification
                    cls = text
                    if cls == "Phishing":
                        item.setForeground(QTableWidgetItem().foreground())
                        from PyQt6.QtGui import QBrush, QColor
                        item.setForeground(QBrush(QColor(DANGER)))
                    elif cls == "Suspicious":
                        from PyQt6.QtGui import QBrush, QColor
                        item.setForeground(QBrush(QColor(WARNING)))
                    elif cls == "Safe":
                        from PyQt6.QtGui import QBrush, QColor
                        item.setForeground(QBrush(QColor(SUCCESS)))
                self.scans_table.setItem(row, col, item)

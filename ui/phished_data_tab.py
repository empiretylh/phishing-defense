"""
Phished User Data Tab
=====================
Display credentials captured during phishing simulations for educational purposes.
Shows how attackers would collect and view stolen credentials.
"""

from typing import Callable
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QMessageBox, QFrame,
)

from database.db_manager import (
    get_phished_credentials,
    get_phished_count,
    get_phished_by_preset,
    clear_all_phished_credentials,
)

# Colours
BG_CARD = "#f8fafc"
BORDER = "#e2e8f0"
TEXT_PRI = "#0f172a"
TEXT_MUT = "#475569"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"
ACCENT = "#6366f1"


class PhishedDataTab(QWidget):
    """Display phished user data captured during simulations."""

    def __init__(self, log_callback: Callable = None, parent=None):
        super().__init__(parent)
        self._log = log_callback or (lambda m, l="INFO": None)
        self._build_ui()
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.timeout.connect(self.refresh_data)
        self._auto_refresh_timer.start(5000)  # Refresh every 5 seconds

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 12)
        layout.setSpacing(16)

        # Header
        title = QLabel("🎣  Phished User Data (Simulation)")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel(
            "View credentials captured during phishing simulations.\n"
            "This demonstrates how attackers collect stolen data for educational purposes."
        )
        subtitle.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px; margin-bottom: 4px;")
        layout.addWidget(subtitle)

        # Warning banner
        banner = QFrame()
        banner.setStyleSheet(f"""
            QFrame {{
                background: rgba(239,68,68,0.08);
                border: 1px solid rgba(239,68,68,0.3);
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        banner_layout = QHBoxLayout(banner)
        banner_label = QLabel(
            "⚠️  <b>EDUCATIONAL DATA ONLY</b> — These credentials were captured during "
            "controlled phishing simulations. This demonstrates attacker's view."
        )
        banner_label.setWordWrap(True)
        banner_label.setStyleSheet(f"color: {DANGER}; font-size: 12px;")
        banner_layout.addWidget(banner_label)
        layout.addWidget(banner)

        # Stats panel
        stats_panel = QGroupBox("Statistics")
        stats_panel.setStyleSheet(f"""
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
        stats_layout = QHBoxLayout(stats_panel)

        self.total_label = QLabel("Total Captured: 0")
        self.total_label.setStyleSheet(f"color: {TEXT_PRI}; font-size: 14px; font-weight: bold;")
        stats_layout.addWidget(self.total_label)

        stats_layout.addStretch()

        self.preset_label = QLabel("By Template: —")
        self.preset_label.setStyleSheet(f"color: {TEXT_MUT}; font-size: 13px;")
        stats_layout.addWidget(self.preset_label)

        layout.addWidget(stats_panel)

        # Action buttons
        btn_layout = QHBoxLayout()

        self.btn_refresh = QPushButton("🔄  Refresh")
        self.btn_refresh.setMinimumHeight(40)
        self.btn_refresh.clicked.connect(self.refresh_data)
        btn_layout.addWidget(self.btn_refresh)

        self.btn_clear = QPushButton("🗑️  Clear All Data")
        self.btn_clear.setMinimumHeight(40)
        self.btn_clear.setStyleSheet(f"""
            QPushButton {{
                background-color: {DANGER};
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: 600;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
        """)
        self.btn_clear.clicked.connect(self._clear_all)
        btn_layout.addWidget(self.btn_clear)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Data table
        table_label = QLabel("Captured Credentials")
        table_label.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(table_label)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "ID", "Username", "Password", "Template", "IP Address", "User Agent", "Timestamp"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 6px;
                gridline-color: {BORDER};
                color: {TEXT_PRI};
            }}
            QTableWidget::item {{
                padding: 8px;
            }}
            QTableWidget::item:selected {{
                background: {ACCENT};
                color: #ffffff;
            }}
            QHeaderView::section {{
                background: #f1f5f9;
                color: {TEXT_PRI};
                padding: 10px;
                border: none;
                border-bottom: 2px solid {ACCENT};
                font-weight: bold;
            }}
        """)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)

        # Initial data load
        self.refresh_data()

    def refresh_data(self):
        """Reload phished credentials from the database."""
        try:
            credentials = get_phished_credentials(limit=500)
            total_count = get_phished_count()
            by_preset = get_phished_by_preset()

            # Update stats
            self.total_label.setText(f"Total Captured: {total_count}")
            if by_preset:
                preset_text = ", ".join([f"{k}: {v}" for k, v in by_preset.items()])
                self.preset_label.setText(f"By Template: {preset_text}")
            else:
                self.preset_label.setText("By Template: —")

            # Update table
            self.table.setRowCount(0)
            for cred in credentials:
                row_pos = self.table.rowCount()
                self.table.insertRow(row_pos)

                self.table.setItem(row_pos, 0, QTableWidgetItem(str(cred["id"])))
                self.table.setItem(row_pos, 1, QTableWidgetItem(cred["username"]))
                self.table.setItem(row_pos, 2, QTableWidgetItem(cred["password"]))
                self.table.setItem(row_pos, 3, QTableWidgetItem(cred["preset"]))
                self.table.setItem(row_pos, 4, QTableWidgetItem(cred["ip_address"]))
                self.table.setItem(row_pos, 5, QTableWidgetItem(cred["user_agent"][:50] + "..." if len(cred["user_agent"]) > 50 else cred["user_agent"]))
                
                # Format timestamp
                try:
                    ts = datetime.fromisoformat(cred["timestamp"])
                    formatted_ts = ts.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_ts = cred["timestamp"]
                self.table.setItem(row_pos, 6, QTableWidgetItem(formatted_ts))

            self._log(f"Phished data refreshed: {total_count} records", "INFO")

        except Exception as e:
            self._log(f"Error refreshing phished data: {e}", "ERROR")
            QMessageBox.critical(self, "Error", f"Failed to refresh data:\n{e}")

    def _clear_all(self):
        """Clear all phished credential records after confirmation."""
        reply = QMessageBox.question(
            self,
            "Confirm Clear",
            "Are you sure you want to delete all phished credential records?\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                count = clear_all_phished_credentials()
                self._log(f"Cleared {count} phished credential records", "OK")
                QMessageBox.information(self, "Success", f"Deleted {count} records.")
                self.refresh_data()
            except Exception as e:
                self._log(f"Error clearing phished data: {e}", "ERROR")
                QMessageBox.critical(self, "Error", f"Failed to clear data:\n{e}")

    def showEvent(self, event):
        """Refresh data when tab becomes visible."""
        super().showEvent(event)
        self.refresh_data()

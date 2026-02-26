"""
Enterprise Phishing Analysis & Simulation Platform
====================================================
Educational Edition — Main Application Entry Point

Usage:
    python main.py

The application starts the PyQt6 desktop GUI with:
  - URL Intelligence Scanner
  - Threat Intelligence Dashboard
  - Educational Phishing Simulation Lab
  - Chrome Extension Testing Module

All modules are for educational cybersecurity research only.
"""

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt

from database.db_manager import initialize_database
from ui.dashboard import MainDashboard


def main():
    # High-DPI support
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("Phishing Analysis Platform")
    app.setOrganizationName("SecurityResearch")
    app.setApplicationVersion("2.0.0")

    # Default font
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    # Dark palette (supplements stylesheet)
    from PyQt6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0a0e17"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#111827"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#0d1117"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#1e293b"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#1e293b"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e2e8f0"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ef4444"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#6366f1"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#6366f1"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    # Initialize database
    initialize_database()

    # Launch main window
    window = MainDashboard()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

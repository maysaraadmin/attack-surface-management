# gui/dashboard_widget.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                            QLabel, QProgressBar, QFrame, QPushButton)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import Qt

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        main_layout = QVBoxLayout()
        
        # Header
        header = QLabel("Attack Surface Dashboard")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        # Stats grid
        stats_layout = QGridLayout()
        
        # Vulnerability stats
        vuln_frame = self.create_stat_frame("Critical Vulnerabilities", "5", QColor(220, 53, 69))
        stats_layout.addWidget(vuln_frame, 0, 0)
        
        high_frame = self.create_stat_frame("High Risk", "12", QColor(253, 126, 20))
        stats_layout.addWidget(high_frame, 0, 1)
        
        medium_frame = self.create_stat_frame("Medium Risk", "23", QColor(255, 193, 7))
        stats_layout.addWidget(medium_frame, 1, 0)
        
        low_frame = self.create_stat_frame("Low Risk", "45", QColor(40, 167, 69))
        stats_layout.addWidget(low_frame, 1, 1)
        
        main_layout.addLayout(stats_layout)
        
        # Recent activity
        recent_layout = QVBoxLayout()
        recent_label = QLabel("Recent Scans")
        recent_label.setFont(QFont("Arial", 12, QFont.Bold))
        recent_layout.addWidget(recent_label)
        
        # Sample recent scans
        scans = [
            ("example.com - Web Scan", "Completed", "2 min ago"),
            ("192.168.1.0/24 - Network Scan", "Running", "5 min ago"),
            ("api.example.com - API Scan", "Completed", "10 min ago")
        ]
        
        for scan, status, time in scans:
            scan_frame = QFrame()
            scan_frame.setFrameStyle(QFrame.Box)
            scan_layout = QHBoxLayout(scan_frame)
            
            scan_label = QLabel(scan)
            status_label = QLabel(status)
            time_label = QLabel(time)
            
            scan_layout.addWidget(scan_label)
            scan_layout.addWidget(status_label)
            scan_layout.addWidget(time_label)
            
            recent_layout.addWidget(scan_frame)
        
        main_layout.addLayout(recent_layout)
        
        # Quick actions
        actions_layout = QHBoxLayout()
        quick_scan_btn = QPushButton("Quick Scan")
        full_scan_btn = QPushButton("Full Scan")
        report_btn = QPushButton("Generate Report")
        
        actions_layout.addWidget(quick_scan_btn)
        actions_layout.addWidget(full_scan_btn)
        actions_layout.addWidget(report_btn)
        
        main_layout.addLayout(actions_layout)
        
        self.setLayout(main_layout)
    
    def create_stat_frame(self, title, value, color):
        frame = QFrame()
        frame.setFrameStyle(QFrame.Box)
        frame.setLineWidth(2)
        
        layout = QVBoxLayout(frame)
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignCenter)
        value_font = QFont()
        value_font.setPointSize(24)
        value_font.setBold(True)
        value_label.setFont(value_font)
        
        # Set text color
        palette = value_label.palette()
        palette.setColor(QPalette.WindowText, color)
        value_label.setPalette(palette)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        return frame
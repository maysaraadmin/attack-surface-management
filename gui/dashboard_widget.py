# gui/dashboard_widget.py
import os
import json
from datetime import datetime, timedelta
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                            QLabel, QFrame, QPushButton, QMessageBox)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import Qt, QTimer
import logging

# Configure logging
logger = logging.getLogger(__name__)

class DashboardWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_history = []
        self.vulnerability_stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        # Track if UI is initialized
        self.ui_initialized = False
        
        self.setup_ui()
        self.load_scan_history()
        
        # Setup a timer to refresh the dashboard periodically
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_dashboard)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
        
        # Mark UI as initialized after a short delay to ensure everything is set up
        QTimer.singleShot(100, self.mark_ui_initialized)
    
    def load_scan_history(self):
        """Load scan history from the results directory"""
        try:
            results_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'results')
            if not os.path.exists(results_dir):
                os.makedirs(results_dir, exist_ok=True)
                return
                
            self.scan_history = []
            for filename in os.listdir(results_dir):
                if filename.endswith('.json'):
                    try:
                        with open(os.path.join(results_dir, filename), 'r') as f:
                            scan_data = json.load(f)
                            if isinstance(scan_data, dict):
                                scan_data['timestamp'] = os.path.getmtime(os.path.join(results_dir, filename))
                                self.scan_history.append(scan_data)
                                # Update vulnerability stats
                                self.update_vulnerability_stats(scan_data)
                    except Exception as e:
                        logger.error(f"Error loading scan result {filename}: {str(e)}")
            
            # Sort by timestamp, newest first
            self.scan_history.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            
        except Exception as e:
            logger.error(f"Error loading scan history: {str(e)}")
    
    def update_vulnerability_stats(self, scan_data):
        """Update vulnerability statistics from scan data"""
        if 'vulnerabilities' in scan_data:
            for vuln in scan_data['vulnerabilities']:
                severity = vuln.get('severity', 'low').lower()
                if severity in self.vulnerability_stats:
                    self.vulnerability_stats[severity] += 1
        
    def mark_ui_initialized(self):
        """Mark the UI as fully initialized"""
        self.ui_initialized = True
        self.update_display()
    
    def refresh_dashboard(self):
        """Refresh the dashboard with latest data"""
        if not self.ui_initialized:
            return
            
        try:
            self.load_scan_history()
            self.update_display()
        except Exception as e:
            logger.error(f"Error refreshing dashboard: {str(e)}", exc_info=True)
    
    def update_display(self):
        """Update the display with current data"""
        if not hasattr(self, 'critical_frame') or not self.ui_initialized:
            return
            
        try:
            # Update vulnerability stats
            for severity, frame in [
                ('critical', self.critical_frame),
                ('high', self.high_frame),
                ('medium', self.medium_frame),
                ('low', self.low_frame)
            ]:
                if hasattr(frame, 'value_label') and frame.value_label is not None:
                    frame.value_label.setText(str(self.vulnerability_stats[severity]))
            
            # Update recent scans
            self.update_recent_scans()
        except Exception as e:
            logger.error(f"Error updating display: {str(e)}", exc_info=True)
    
    def format_timestamp(self, timestamp):
        """Format timestamp to relative time"""
        now = datetime.now().timestamp()
        diff = now - timestamp
        
        if diff < 60:
            return "just now"
        elif diff < 3600:
            minutes = int(diff // 60)
            return f"{minutes} min ago"
        elif diff < 86400:
            hours = int(diff // 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        else:
            days = int(diff // 86400)
            return f"{days} day{'s' if days > 1 else ''} ago"
    
    def update_recent_scans(self):
        """Update the recent scans list"""
        # Clear existing scan widgets
        for i in reversed(range(self.recent_layout.count())):
            widget = self.recent_layout.itemAt(i).widget()
            if widget and widget != self.recent_label:
                widget.deleteLater()
        
        # Add current scans
        for scan in self.scan_history[:5]:  # Show only the 5 most recent scans
            target = scan.get('target', 'Unknown')
            scan_type = scan.get('scan_type', 'scan').capitalize()
            status = scan.get('status', 'completed').capitalize()
            timestamp = scan.get('timestamp', 0)
            time_str = self.format_timestamp(timestamp)
            
            scan_frame = QFrame()
            scan_frame.setFrameStyle(QFrame.Box)
            scan_layout = QHBoxLayout(scan_frame)
            
            scan_label = QLabel(f"{target} - {scan_type}")
            status_label = QLabel(status)
            time_label = QLabel(time_str)
            
            # Style based on status
            if 'running' in status.lower():
                status_label.setStyleSheet("color: #007bff;")
            elif 'error' in status.lower():
                status_label.setStyleSheet("color: #dc3545;")
            
            scan_layout.addWidget(scan_label, 70)  # 70% width
            scan_layout.addWidget(status_label, 15)  # 15% width
            scan_layout.addWidget(time_label, 15)  # 15% width
            
            self.recent_layout.addWidget(scan_frame)
    
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
        
        # Vulnerability stats - using custom stat frames that can be updated
        self.critical_frame = self.create_stat_frame("Critical Vulnerabilities", str(self.vulnerability_stats['critical']), QColor(220, 53, 69))
        self.high_frame = self.create_stat_frame("High Risk", str(self.vulnerability_stats['high']), QColor(253, 126, 20))
        self.medium_frame = self.create_stat_frame("Medium Risk", str(self.vulnerability_stats['medium']), QColor(255, 193, 7))
        self.low_frame = self.create_stat_frame("Low Risk", str(self.vulnerability_stats['low']), QColor(40, 167, 69))
        
        stats_layout.addWidget(self.critical_frame, 0, 0)
        stats_layout.addWidget(self.high_frame, 0, 1)
        stats_layout.addWidget(self.medium_frame, 1, 0)
        stats_layout.addWidget(self.low_frame, 1, 1)
        
        main_layout.addLayout(stats_layout)
        
        # Recent activity
        recent_container = QFrame()
        self.recent_layout = QVBoxLayout(recent_container)
        self.recent_layout.setContentsMargins(0, 0, 0, 0)
        
        self.recent_label = QLabel("Recent Scans")
        self.recent_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.recent_layout.addWidget(self.recent_label)
        
        # Add a container for the scan list with a fixed height and scrollable if needed
        scan_list_container = QFrame()
        scan_list_layout = QVBoxLayout(scan_list_container)
        scan_list_layout.setContentsMargins(0, 0, 0, 0)
        
        # Add a placeholder for recent scans (will be populated by update_recent_scans)
        self.scan_list_layout = QVBoxLayout()
        self.scan_list_layout.setSpacing(5)
        scan_list_layout.addLayout(self.scan_list_layout)
        
        # Add a stretch to push content to the top
        scan_list_layout.addStretch()
        
        # Add the scan list container to the recent layout
        self.recent_layout.addWidget(scan_list_container)
        
        main_layout.addWidget(recent_container)
        
        # Quick actions
        actions_layout = QHBoxLayout()
        
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.full_scan_btn = QPushButton("Full Scan")
        self.report_btn = QPushButton("Generate Report")
        
        # Style the buttons
        for btn in [self.quick_scan_btn, self.full_scan_btn, self.report_btn]:
            btn.setMinimumHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #e2e6ea;
                }
                QPushButton:pressed {
                    background-color: #d6dbe0;
                }
            """)
        
        actions_layout.addWidget(self.quick_scan_btn)
        actions_layout.addWidget(self.full_scan_btn)
        actions_layout.addWidget(self.report_btn)
        
        main_layout.addLayout(actions_layout)
        
        self.setLayout(main_layout)
    
    def create_stat_frame(self, title, value, color):
        """Create a frame for displaying a statistic with the given title and value"""
        class StatFrame(QFrame):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.value_label = None
                self.setup_ui(title, value, color)
            
            def setup_ui(self, title, value, color):
                self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
                self.setLineWidth(1)
                self.setStyleSheet("""
                    QFrame {
                        background-color: #ffffff;
                        border-radius: 5px;
                        padding: 10px;
                    }
                """)
                
                layout = QVBoxLayout(self)
                layout.setContentsMargins(10, 10, 10, 10)
                layout.setSpacing(5)
                
                # Title
                title_label = QLabel(title)
                title_label.setAlignment(Qt.AlignCenter)
                title_label.setStyleSheet("""
                    QLabel {
                        color: #6c757d;
                        font-weight: bold;
                    }
                """)
                
                # Value - store as instance variable
                self.value_label = QLabel(value, self)
                self.value_label.setAlignment(Qt.AlignCenter)
                value_font = QFont()
                value_font.setPointSize(20)
                value_font.setBold(True)
                self.value_label.setFont(value_font)
                
                # Set text color
                self.value_label.setStyleSheet(f"color: {color.name()};")
                
                # Add widgets to layout
                layout.addWidget(title_label)
                layout.addWidget(self.value_label, 1, Qt.AlignVCenter)
                
                # Add a subtle shadow effect
                self.setGraphicsEffect(
                    QtWidgets.QGraphicsDropShadowEffect(
                        blurRadius=10,
                        xOffset=2,
                        yOffset=2,
                        color=QColor(0, 0, 0, 30)
                    )
                )
        
        frame = StatFrame()
        # Store a reference to the value_label in the frame for easy access
        frame.value_label = frame.findChildren(QLabel)[1]  # Get the second QLabel (value label)
        return frame
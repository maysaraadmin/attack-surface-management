# gui/scan_widget.py
import os
import sys
import json
import asyncio
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                            QLabel, QLineEdit, QPushButton, QComboBox, 
                            QTextEdit, QProgressBar, QGroupBox, QSpinBox,
                            QMessageBox, QCheckBox, QTabWidget, QFormLayout)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor
import logging

# Local imports
from core.scanner import NetworkScanner

# Configure logging
logger = logging.getLogger(__name__)

class ScanWidget(QWidget):
    """Widget for network scanning functionality"""
    
    def __init__(self, scan_type="port", target="", parent=None):
        super().__init__(parent)
        self.scan_type = scan_type
        self.target = target
        self.scanner = NetworkScanner()
        self.scan_results = []
        self.scan_in_progress = False
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface for the scan widget"""
        layout = QVBoxLayout()
        
        # Create tabs for different scan types
        self.tab_widget = QTabWidget()
        
        # Port Scan Tab
        self.port_scan_tab = self.create_port_scan_tab()
        self.tab_widget.addTab(self.port_scan_tab, "Port Scan")
        
        # Network Scan Tab
        self.network_scan_tab = self.create_network_scan_tab()
        self.tab_widget.addTab(self.network_scan_tab, "Network Scan")
        
        # Web Scan Tab
        self.web_scan_tab = self.create_web_scan_tab()
        self.tab_widget.addTab(self.web_scan_tab, "Web Scan")
        
        layout.addWidget(self.tab_widget)
        
        # Progress section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(200)
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def create_port_scan_tab(self):
        """Create the port scan configuration tab"""
        tab = QWidget()
        layout = QFormLayout()
        
        # Target input
        self.port_target_input = QLineEdit()
        self.port_target_input.setPlaceholderText("Enter IP address or hostname")
        if self.target:
            self.port_target_input.setText(self.target)
        layout.addRow("Target:", self.port_target_input)
        
        # Port range
        port_layout = QHBoxLayout()
        self.start_port_input = QSpinBox()
        self.start_port_input.setRange(1, 65535)
        self.start_port_input.setValue(1)
        port_layout.addWidget(QLabel("Start:"))
        port_layout.addWidget(self.start_port_input)
        
        self.end_port_input = QSpinBox()
        self.end_port_input.setRange(1, 65535)
        self.end_port_input.setValue(1024)
        port_layout.addWidget(QLabel("End:"))
        port_layout.addWidget(self.end_port_input)
        
        layout.addRow("Port Range:", port_layout)
        
        # Scan type
        self.port_scan_type = QComboBox()
        self.port_scan_type.addItems(["TCP Connect", "TCP SYN", "UDP"])
        layout.addRow("Scan Type:", self.port_scan_type)
        
        # Common ports checkbox
        self.common_ports_checkbox = QCheckBox("Scan common ports only")
        self.common_ports_checkbox.setChecked(True)
        layout.addRow("", self.common_ports_checkbox)
        
        tab.setLayout(layout)
        return tab
        
    def create_network_scan_tab(self):
        """Create the network scan configuration tab"""
        tab = QWidget()
        layout = QFormLayout()
        
        # Network range
        self.network_range_input = QLineEdit()
        self.network_range_input.setPlaceholderText("e.g., 192.168.1.0/24")
        layout.addRow("Network Range:", self.network_range_input)
        
        # Scan options
        self.ping_sweep_checkbox = QCheckBox("Perform ping sweep")
        self.ping_sweep_checkbox.setChecked(True)
        layout.addRow("", self.ping_sweep_checkbox)
        
        self.port_discovery_checkbox = QCheckBox("Port discovery")
        self.port_discovery_checkbox.setChecked(True)
        layout.addRow("", self.port_discovery_checkbox)
        
        self.os_detection_checkbox = QCheckBox("OS detection")
        layout.addRow("", self.os_detection_checkbox)
        
        tab.setLayout(layout)
        return tab
        
    def create_web_scan_tab(self):
        """Create the web scan configuration tab"""
        tab = QWidget()
        layout = QFormLayout()
        
        # URL input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL (e.g., http://example.com)")
        layout.addRow("URL:", self.url_input)
        
        # Scan options
        self.ssl_checkbox = QCheckBox("Check SSL/TLS")
        self.ssl_checkbox.setChecked(True)
        layout.addRow("", self.ssl_checkbox)
        
        self.headers_checkbox = QCheckBox("Analyze headers")
        self.headers_checkbox.setChecked(True)
        layout.addRow("", self.headers_checkbox)
        
        self.vuln_checkbox = QCheckBox("Check for common vulnerabilities")
        self.vuln_checkbox.setChecked(True)
        layout.addRow("", self.vuln_checkbox)
        
        tab.setLayout(layout)
        return tab
        
    def start_scan(self):
        """Start the selected scan"""
        if self.scan_in_progress:
            return
            
        current_tab = self.tab_widget.currentWidget()
        
        try:
            if current_tab == self.port_scan_tab:
                self.start_port_scan()
            elif current_tab == self.network_scan_tab:
                self.start_network_scan()
            elif current_tab == self.web_scan_tab:
                self.start_web_scan()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
            
    def start_port_scan(self):
        """Start a port scan"""
        target = self.port_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target IP or hostname")
            return
            
        self.scan_in_progress = True
        self.update_ui_state()
        
        start_port = self.start_port_input.value()
        end_port = self.end_port_input.value()
        
        if self.common_ports_checkbox.isChecked():
            # Common ports list
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
            ports = [p for p in common_ports if start_port <= p <= end_port]
        else:
            ports = list(range(start_port, end_port + 1))
            
        self.status_label.setText(f"Scanning {target}...")
        self.results_text.append(f"Starting port scan on {target}")
        
        # Run scan in a separate thread to avoid blocking UI
        self.scan_thread = ScanThread(self.scanner.port_scan, target, ports)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.results_ready.connect(self.handle_scan_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
        
    def start_network_scan(self):
        """Start a network scan"""
        network_range = self.network_range_input.text().strip()
        if not network_range:
            QMessageBox.warning(self, "Warning", "Please enter a network range")
            return
            
        self.scan_in_progress = True
        self.update_ui_state()
        
        self.status_label.setText(f"Scanning network {network_range}...")
        self.results_text.append(f"Starting network scan on {network_range}")
        
        # Run scan in a separate thread
        self.scan_thread = ScanThread(self.scanner.network_scan, network_range)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.results_ready.connect(self.handle_scan_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
        
    def start_web_scan(self):
        """Start a web scan"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a URL")
            return
            
        self.scan_in_progress = True
        self.update_ui_state()
        
        self.status_label.setText(f"Scanning {url}...")
        self.results_text.append(f"Starting web scan on {url}")
        
        # Run scan in a separate thread
        scan_options = {
            'check_ssl': self.ssl_checkbox.isChecked(),
            'analyze_headers': self.headers_checkbox.isChecked(),
            'check_vulnerabilities': self.vuln_checkbox.isChecked()
        }
        
        self.scan_thread = ScanThread(self.scanner.web_scan, url, scan_options)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.results_ready.connect(self.handle_scan_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_in_progress and hasattr(self, 'scan_thread'):
            self.scan_thread.terminate()
            self.scan_in_progress = False
            self.update_ui_state()
            self.status_label.setText("Scan stopped")
            self.results_text.append("Scan stopped by user")
            
    def clear_results(self):
        """Clear the scan results"""
        self.scan_results = []
        self.results_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")
        
    def export_results(self):
        """Export scan results to a file"""
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
            
        # Simple export to JSON file
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
            QMessageBox.information(self, "Success", f"Results exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
            
    def update_progress(self, value, message=""):
        """Update the progress bar and status"""
        self.progress_bar.setValue(value)
        if message:
            self.status_label.setText(message)
            
    def handle_scan_results(self, results):
        """Handle scan results from the scan thread"""
        self.scan_results = results
        
        # Display results in the text area
        self.results_text.clear()
        if isinstance(results, list):
            for i, result in enumerate(results):
                if isinstance(result, dict):
                    self.results_text.append(f"Result {i+1}: {result.get('target', 'Unknown')}")
                    for key, value in result.items():
                        if key != 'target':
                            self.results_text.append(f"  {key}: {value}")
                else:
                    self.results_text.append(f"Result {i+1}: {result}")
                self.results_text.append("")
        else:
            self.results_text.append(str(results))
            
    def scan_finished(self):
        """Called when scan is finished"""
        self.scan_in_progress = False
        self.update_ui_state()
        self.status_label.setText("Scan completed")
        
    def update_ui_state(self):
        """Update UI elements based on scan state"""
        self.start_button.setEnabled(not self.scan_in_progress)
        self.stop_button.setEnabled(self.scan_in_progress)
        
        # Disable input controls during scan
        enabled = not self.scan_in_progress
        self.port_target_input.setEnabled(enabled)
        self.start_port_input.setEnabled(enabled)
        self.end_port_input.setEnabled(enabled)
        self.port_scan_type.setEnabled(enabled)
        self.common_ports_checkbox.setEnabled(enabled)
        self.network_range_input.setEnabled(enabled)
        self.ping_sweep_checkbox.setEnabled(enabled)
        self.port_discovery_checkbox.setEnabled(enabled)
        self.os_detection_checkbox.setEnabled(enabled)
        self.url_input.setEnabled(enabled)
        self.ssl_checkbox.setEnabled(enabled)
        self.headers_checkbox.setEnabled(enabled)
        self.vuln_checkbox.setEnabled(enabled)


class ScanThread(QThread):
    """Thread for running scans in the background"""
    
    progress_updated = pyqtSignal(int, str)
    results_ready = pyqtSignal(object)
    
    def __init__(self, scan_function, *args, **kwargs):
        super().__init__()
        self.scan_function = scan_function
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        """Run the scan function"""
        try:
            # Emit progress updates
            self.progress_updated.emit(50, "Scanning in progress...")
            
            # Run the scan function
            results = self.scan_function(*self.args, **self.kwargs)
            
            # Emit final progress and results
            self.progress_updated.emit(100, "Scan completed")
            self.results_ready.emit(results)
            
        except Exception as e:
            self.progress_updated.emit(0, f"Error: {str(e)}")
            self.results_ready.emit({"error": str(e)})

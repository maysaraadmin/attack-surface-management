# gui/scan_widget.py
import os
import socket
import asyncio
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QLineEdit, 
    QPushButton, QTextEdit, QComboBox, QCheckBox, QProgressBar, QListWidget,
    QMessageBox, QFormLayout, QSpinBox, QGridLayout, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QStyle, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QObject, QSize
from PyQt5.QtGui import QFont, QTextCursor, QColor, QIcon, QPixmap

from core.scanner import NetworkScanner

class ScanWidget(QWidget):
    """Widget for configuring and running security scans"""
    
    # Signals
    scan_started = pyqtSignal()
    scan_finished = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    progress_updated = pyqtSignal(int, str)  # progress, status
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = NetworkScanner()
        self.scan_thread = None
        self.is_scanning = False
        self.setup_ui()
        self.setup_connections()
        
    def setup_ui(self):
        """Initialize the UI components"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create a splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)
        
        # Top panel: Scan configuration
        config_group = QGroupBox("Scan Configuration")
        config_layout = QFormLayout()
        
        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or 192.168.1.1")
        config_layout.addRow("Target:", self.target_input)
        
        # Scan type
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Quick Scan (Top 100 ports)",
            "Full Port Scan (1-65535)",
            "Custom Port Range",
            "Web Application Scan"
        ])
        config_layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Port range (initially hidden)
        self.port_range_layout = QHBoxLayout()
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(1)
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(1024)
        
        self.port_range_layout.addWidget(QLabel("From:"))
        self.port_range_layout.addWidget(self.port_start)
        self.port_range_layout.addWidget(QLabel("To:"))
        self.port_range_layout.addWidget(self.port_end)
        self.port_range_layout.addStretch()
        
        self.port_range_widget = QWidget()
        self.port_range_widget.setLayout(self.port_range_layout)
        self.port_range_widget.setVisible(False)  # Hidden by default
        config_layout.addRow("Port Range:", self.port_range_widget)
        
        # Scan options
        self.scan_options_group = QGroupBox("Scan Options")
        options_layout = QGridLayout()
        
        self.aggressive_check = QCheckBox("Aggressive Scan")
        self.service_version_check = QCheckBox("Service Version Detection")
        self.os_detection_check = QCheckBox("OS Detection")
        self.script_scan_check = QCheckBox("Script Scanning")
        
        options_layout.addWidget(self.aggressive_check, 0, 0)
        options_layout.addWidget(self.service_version_check, 0, 1)
        options_layout.addWidget(self.os_detection_check, 1, 0)
        options_layout.addWidget(self.script_scan_check, 1, 1)
        
        self.scan_options_group.setLayout(options_layout)
        config_layout.addRow(self.scan_options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_MediaPlay')))
        self.start_button.setStyleSheet("font-weight: bold;")
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_MediaStop')))
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        
        config_layout.addRow(button_layout)
        config_group.setLayout(config_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #c4c4c4;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
                margin: 0.5px;
            }
        """)
        
        # Results area
        results_tabs = QTabWidget()
        
        # Ports tab
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(5)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        self.ports_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Hosts tab
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(4)
        self.hosts_table.setHorizontalHeaderLabels(["Host", "Status", "Open Ports", "OS"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        
        # Vulnerabilities tab
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["CVE", "Severity", "Port", "Service", "Description"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        
        # Add tabs
        results_tabs.addTab(self.ports_table, "Open Ports")
        results_tabs.addTab(self.hosts_table, "Hosts")
        results_tabs.addTab(self.vuln_table, "Vulnerabilities")
        
        # Log area
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Courier New", 9))
        
        # Add widgets to splitter
        splitter.addWidget(config_group)
        splitter.addWidget(self.progress_bar)
        splitter.addWidget(results_tabs)
        splitter.addWidget(self.log_view)
        
        # Set initial sizes
        splitter.setSizes([200, 30, 400, 200])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        main_layout.addWidget(self.status_bar)
    
    def setup_connections(self):
        """Set up signal/slot connections"""
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.scan_type_combo.currentIndexChanged.connect(self.update_scan_type)
        
        # Connect signals from the scan thread
        self.scan_started.connect(self.on_scan_started)
        self.scan_finished.connect(self.on_scan_finished)
        self.scan_error.connect(self.on_scan_error)
        self.progress_updated.connect(self.update_progress)
    
    def log_message(self, message, level="info"):
        """Add a message to the log view"""
        timestamp = QDateTime.currentDateTime().toString("[yyyy-MM-dd hh:mm:ss]")
        
        if level == "error":
            color = "red"
            prefix = "[ERROR]"
        elif level == "warning":
            color = "orange"
            prefix = "[WARN]"
        else:
            color = "black"
            prefix = "[INFO]"
        
        self.log_view.setTextColor(QColor(color))
        self.log_view.append(f"{timestamp} {prefix} {message}")
        self.log_view.moveCursor(QTextCursor.End)
    
    def update_progress(self, value, message):
        """Update progress bar and status"""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"{message} ({value}%)")
        self.status_label.setText(message)
    
    def update_scan_type(self, index):
        """Update UI based on selected scan type"""
        if index == 2:  # Custom Port Range
            self.port_range_widget.setVisible(True)
        else:
            self.port_range_widget.setVisible(False)
    
    def validate_target(self, target):
        """Validate the target input"""
        target = target.strip()
        if not target:
            return False, "Please enter a target to scan"
        
        # Basic validation for IP or hostname
        try:
            # Try to resolve the target
            socket.gethostbyname(target)
            return True, ""
        except socket.gaierror:
            return False, "Invalid hostname or IP address"
    
    def start_scan(self):
        """Start the scanning process"""
        target = self.target_input.text().strip()
        valid, error = self.validate_target(target)
        
        if not valid:
            QMessageBox.warning(self, "Validation Error", error)
            return
        
        # Get scan options
        scan_type = self.scan_type_combo.currentIndex()
        options = {
            'aggressive': self.aggressive_check.isChecked(),
            'service_version': self.service_version_check.isChecked(),
            'os_detection': self.os_detection_check.isChecked(),
            'script_scan': self.script_scan_check.isChecked(),
        }
        
        # Determine port range
        if scan_type == 0:  # Quick Scan
            ports = "1-1024"
        elif scan_type == 1:  # Full Scan
            ports = "1-65535"
        elif scan_type == 2:  # Custom Range
            start = self.port_start.value()
            end = self.port_end.value()
            if start > end:
                QMessageBox.warning(self, "Error", "Start port cannot be greater than end port")
                return
            ports = f"{start}-{end}"
        else:  # Web Scan
            ports = "80,443,8080,8443"
        
        # Start the scan in a separate thread
        self.scan_thread = ScanThread(self.scanner, target, ports, options)
        self.scan_thread.finished.connect(self.on_scan_finished)
        self.scan_thread.error.connect(self.on_scan_error)
        self.scan_thread.progress.connect(self.progress_updated)
        
        self.scan_thread.start()
        self.scan_started.emit()
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.log_message("Scan stopped by user", "warning")
            self.update_progress(0, "Scan stopped")
    
    def on_scan_started(self):
        """Handle scan started event"""
        self.is_scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_message("Scan started")
    
    def on_scan_finished(self, results):
        """Handle scan completion"""
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        if results:
            self.log_message(f"Scan completed. Found {len(results.get('hosts', []))} hosts.")
            self.display_results(results)
        else:
            self.log_message("Scan completed with no results.", "warning")
    
    def on_scan_error(self, error):
        """Handle scan errors"""
        self.is_scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        self.log_message(f"Scan error: {error}", "error")
        QMessageBox.critical(self, "Scan Error", error)
    
    def display_results(self, results):
        """Display scan results in the UI"""
        # Clear previous results
        self.ports_table.setRowCount(0)
        self.hosts_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        
        # Process hosts and ports
        for host_data in results.get('hosts', []):
            host = host_data.get('ip', 'Unknown')
            status = host_data.get('status', 'unknown')
            
            # Add to hosts table
            row = self.hosts_table.rowCount()
            self.hosts_table.insertRow(row)
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host))
            self.hosts_table.setItem(row, 1, QTableWidgetItem(status.capitalize()))
            
            # Process ports
            for port_data in host_data.get('ports', []):
                port = port_data.get('port', '')
                protocol = port_data.get('protocol', 'tcp')
                state = port_data.get('state', 'unknown')
                service = port_data.get('service', 'unknown')
                version = port_data.get('version', '')
                
                # Add to ports table
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                self.ports_table.setItem(row, 0, QTableWidgetItem(str(port)))
                self.ports_table.setItem(row, 1, QTableWidgetItem(protocol.upper()))
                self.ports_table.setItem(row, 2, QTableWidgetItem(state.capitalize()))
                self.ports_table.setItem(row, 3, QTableWidgetItem(service))
                self.ports_table.setItem(row, 4, QTableWidgetItem(version))
                
                # Process vulnerabilities if any
                for vuln in port_data.get('vulnerabilities', []):
                    row = self.vuln_table.rowCount()
                    self.vuln_table.insertRow(row)
                    self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln.get('cve', 'N/A')))
                    self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln.get('severity', 'N/A')))
                    self.vuln_table.setItem(row, 2, QTableWidgetItem(str(port)))
                    self.vuln_table.setItem(row, 3, QTableWidgetItem(service))
                    self.vuln_table.setItem(row, 4, QTableWidgetItem(vuln.get('description', '')))
        
        # Resize columns to content
        for table in [self.ports_table, self.hosts_table, self.vuln_table]:
            table.resizeColumnsToContents()
    
    def clear_results(self):
        """Clear all scan results"""
        self.ports_table.setRowCount(0)
        self.hosts_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.log_view.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        self.status_label.setText("Ready")

class ScanWorker(QThread):
    """Worker thread for running scans in the background"""
    progress = pyqtSignal(int, str)  # progress percentage, status message
    result = pyqtSignal(dict)        # scan results
    error = pyqtSignal(str)          # error message
    finished = pyqtSignal(bool)      # success status
    
    # Signal for scan status updates
    status_update = pyqtSignal(str)
    
    def __init__(self, scan_type, target, options=None):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.options = options or {}
        self._is_running = False
        self._stop_requested = False
        self.scanner = NetworkScanner()
    
    def run(self):
        try:
            self._is_running = True
            self.status_update.emit(f"Starting {self.scan_type} on {self.target}...")
            
            try:
                if self._stop_requested:
                    self.status_update.emit("Scan was cancelled before starting")
                    return
                    
                if self.scan_type == "port_scan":
                    self.status_update.emit("Performing port scan...")
                    # Create a new event loop for the async operation
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        # Run the async port_scan method
                        result = loop.run_until_complete(
                            self.scanner.port_scan(self.target)
                        )
                        if 'error' in result:
                            self.error.emit(f"Port scan failed: {result['error']}")
                            self.finished.emit(False)
                        else:
                            self.result.emit(result)
                            self.finished.emit(True)
                    finally:
                        loop.close()
                        
                elif self.scan_type == "web_scan":
                    self.status_update.emit("Scanning web application...")
                    result = self.scanner.web_scan(self.target)
                    if 'error' in result and result['error']:
                        self.error.emit(f"Web scan failed: {result['error']}")
                        self.finished.emit(False)
                    else:
                        self.result.emit(result)
                        self.finished.emit(True)
                else:
                    self.error.emit(f"Unknown scan type: {self.scan_type}")
                    self.finished.emit(False)
                    
            except Exception as e:
                error_msg = f"Error during scan: {str(e)}"
                self.status_update.emit(f"Error: {error_msg}")
                self.error.emit(error_msg)
                self.finished.emit(False)
                
        except Exception as e:
            error_msg = f"Unexpected error in scan worker: {str(e)}"
            self.status_update.emit(f"Critical Error: {error_msg}")
            self.error.emit(error_msg)
            self.finished.emit(False)
            
        finally:
            self._is_running = False
            # Clean up scanner resources
            if hasattr(self, 'scanner') and self.scanner:
                if hasattr(self.scanner, 'close'):
                    try:
                        self.scanner.close()
                    except Exception as e:
                        self.error.emit(f"Error cleaning up scanner: {str(e)}")
                del self.scanner

class ScanWidget(QWidget):
    """Widget for configuring and running security scans"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = None
        self.worker_thread = None
        self.setup_ui()
        self.setup_connections()
        
    def setup_connections(self):
        """Connect signals and slots"""
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        
    def is_scanning(self):
        """Check if a scan is currently in progress"""
        return self.worker_thread is not None and self.worker_thread.isRunning()
        
    def cleanup_worker(self):
        """Clean up worker thread resources"""
        if self.worker_thread:
            if self.worker_thread.isRunning():
                self.worker_thread.terminate()
                self.worker_thread.wait()
            self.worker_thread.deleteLater()
            self.worker_thread = None
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Target input
        target_group = QGroupBox("Scan Target")
        target_layout = QHBoxLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address, domain, or URL")
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.target_input)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Port Scan", "Web Application Scan", "Full Scan"])
        options_layout.addWidget(QLabel("Scan Type:"))
        options_layout.addWidget(self.scan_type_combo)
        
        self.quick_scan_check = QCheckBox("Quick Scan")
        self.quick_scan_check.setChecked(True)
        options_layout.addWidget(self.quick_scan_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(QLabel("Scan Results:"))
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def validate_target(self, target, scan_type):
        """Validate the target based on scan type"""
        if not target:
            return "Please enter a target"
            
        target = target.strip()
        
        if scan_type == 'port_scan':
            # Validate IP address or hostname
            try:
                # Try parsing as IP address
                socket.inet_aton(target)
                return None
            except socket.error:
                try:
                    # Try resolving hostname
                    socket.gethostbyname(target)
                    return None
                except socket.gaierror:
                    return "Invalid IP address or hostname"
                    
        elif scan_type == 'web_scan':
            # Basic URL validation
            if not (target.startswith('http://') or target.startswith('https://')):
                target = 'http://' + target
                
            try:
                result = urlparse(target)
                if not all([result.scheme, result.netloc]):
                    return "Invalid URL format. Use http://example.com or https://example.com"
            except Exception:
                return "Invalid URL format"
                
        return None
        
    def start_scan(self):
        """Start the scanning process"""
        try:
            if self.is_scanning():
                QMessageBox.information(self, "Scan in Progress", 
                                      "A scan is already in progress.")
                return
                
            target = self.target_input.text().strip()
            scan_type = self.scan_type_combo.currentText().lower().replace(" ", "_")
            
            # Validate target
            validation_error = self.validate_target(target, scan_type)
            if validation_error:
                QMessageBox.warning(self, "Validation Error", validation_error)
                return
                
            # Check dependencies
            if scan_type == 'port_scan':
                try:
                    import nmap
                except ImportError:
                    QMessageBox.critical(
                        self, 
                        "Dependency Missing", 
                        "python-nmap is required for port scanning.\n\n"
                        "Please install it with:\n"
                        "pip install python-nmap"
                    )
                    return
            
            # Initialize scanner if not already done
            if self.scanner is None:
                try:
                    self.scanner = NetworkScanner()
                except Exception as e:
                    QMessageBox.critical(
                        self, 
                        "Scanner Error", 
                        f"Failed to initialize scanner: {str(e)}"
                    )
                    return
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.progress_bar.setValue(0)
            self.results_text.clear()
            
            # Create and start worker thread
            self.worker_thread = ScanWorker(scan_type, target)
            self.worker_thread.progress.connect(self.update_progress)
            self.worker_thread.result.connect(self.handle_scan_result)
            self.worker_thread.error.connect(self.handle_scan_error)
            self.worker_thread.finished.connect(self.scan_finished)
            self.worker_thread.start()
            
        except Exception as e:
            self.handle_scan_error(f"Failed to start scan: {str(e)}")
            self.scan_finished(False)
    
    def stop_scan(self):
        """Stop the currently running scan"""
        try:
            if self.is_scanning():
                self.worker_thread.requestInterruption()
                self.worker_thread.quit()
                if not self.worker_thread.wait(5000):  # Wait up to 5 seconds
                    self.worker_thread.terminate()
                    self.worker_thread.wait()
                self.cleanup_worker()
        except Exception as e:
            self.status_label.setText(f"Error stopping scan: {str(e)}")
        finally:
            self.scan_finished(False)
    
    def handle_scan_result(self, result):
        """Handle successful scan results"""
        try:
            if 'error' in result:
                self.results_text.append(f"\nError: {result['error']}")
                QMessageBox.warning(self, "Scan Error", f"An error occurred during the scan:\n{result['error']}")
                return
                
            # Format and display results
            result_text = self.format_results(result)
            self.results_text.append("\n=== Scan Results ===\n")
            self.results_text.append(result_text)
            
            # Check for vulnerabilities and show warning if found
            if 'vulnerabilities' in result and result['vulnerabilities']:
                vuln_count = len(result['vulnerabilities'])
                self.results_text.append(f"\n⚠️ Found {vuln_count} potential vulnerability(ies).")
                
                # Show critical vulnerabilities in a message box
                critical_vulns = [v for v in result['vulnerabilities'] 
                               if v.get('severity') in ['high', 'critical']]
                
                if critical_vulns:
                    vuln_text = "\n".join([f"- {v['type']}: {v['description']}" 
                                      for v in critical_vulns])
                    QMessageBox.warning(
                        self,
                        "Critical Vulnerabilities Found",
                        f"The following critical vulnerabilities were found:\n\n{vuln_text}"
                    )
        except Exception as e:
            self.handle_scan_error(f"Error processing scan results: {str(e)}")
    
    def handle_scan_error(self, error):
        """Handle scan errors"""
        try:
            error_msg = f"Error: {error}"
            self.results_text.append(error_msg)
            QMessageBox.critical(self, "Scan Error", error_msg)
        except Exception as e:
            self.status_label.setText(f"Error handling scan error: {str(e)}")
    
    def update_progress(self, progress, status):
        """Update the progress bar and status label"""
        self.progress_bar.setValue(progress)
        self.results_text.append(f"\n{status}")
    
    def format_results(self, result):
        # Format scan results for display
        if 'port_scan' in str(self.scan_type_combo.currentText().lower().replace(" ", "_")):
            return self.format_port_scan_results(result)
        elif 'web_scan' in str(self.scan_type_combo.currentText().lower().replace(" ", "_")):
            return self.format_web_scan_results(result)
        return str(result)
    
    def format_port_scan_results(self, result):
        formatted = "Port Scan Results:\n\n"
        for host, host_data in result.items():
            formatted += f"Host: {host}\n"
            formatted += f"Status: {host_data.get('status', {}).get('state', 'unknown')}\n\n"
            
            for proto in host_data.get('tcp', {}):
                port_data = host_data['tcp'][proto]
                formatted += f"Port {proto}: {port_data.get('state', 'unknown')} - {port_data.get('name', '')}\n"
        
        return formatted
    
    def format_web_scan_results(self, result):
        formatted = "Web Application Scan Results:\n\n"
        formatted += f"URL: {result.get('url', 'N/A')}\n"
        formatted += f"Status Code: {result.get('status_code', 'N/A')}\n\n"
        formatted += "Headers:\n"
        
        for key, value in result.get('headers', {}).items():
            formatted += f"  {key}: {value}\n"
        
        return formatted
    
    def scan_finished(self, success=True):
        """Clean up after scan completion"""
        try:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            
            if success:
                self.progress_bar.setValue(100)
            else:
                self.progress_bar.setValue(0)
                
            # Clean up worker thread
            self.cleanup_worker()
            
        except Exception as e:
            self.status_label.setText(f"Error during scan completion: {str(e)}")
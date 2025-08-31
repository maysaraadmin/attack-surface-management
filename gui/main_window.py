# gui/main_window.py
import os
import sys
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QStatusBar, 
                             QAction, QToolBar, QMessageBox, QVBoxLayout, 
                             QWidget, QFileDialog, QLabel)
from PyQt5.QtGui import QIcon, QPalette, QColor, QPixmap
from PyQt5.QtCore import Qt, QSize, QDir
from .dashboard_widget import DashboardWidget
from .scan_widget import ScanWidget
from .results_widget import ResultsWidget

# Default icons as base64-encoded strings
DEFAULT_ICONS = {
    'new': 'document-new',
    'scan': 'system-search',
    'report': 'document-export'
}

def get_icon(name):
    """Get icon from theme or fallback to default"""
    icon = QIcon.fromTheme(name)
    if icon.isNull():
        # Try to load from resources or use a default icon
        icon = QIcon.fromTheme(DEFAULT_ICONS.get(name, 'application-x-executable'))
    return icon

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Attack Surface Manager")
        self.setGeometry(100, 100, 1200, 800)
        
        try:
            self.setup_ui()
            self.setup_menu()
            self.setup_toolbar()
        except Exception as e:
            QMessageBox.critical(
                None,
                "Initialization Error",
                f"Failed to initialize application: {str(e)}\n\n"
                "Please check your installation and try again."
            )
            raise
        
    def setup_ui(self):
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs with error handling
        try:
            self.dashboard_tab = DashboardWidget()
            self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to initialize Dashboard: {str(e)}")
        
        try:
            self.scan_tab = ScanWidget()
            self.tab_widget.addTab(self.scan_tab, "Scan")
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to initialize Scan tab: {str(e)}")
        
        try:
            self.results_tab = ResultsWidget()
            self.tab_widget.addTab(self.results_tab, "Results")
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to initialize Results tab: {str(e)}")
        
        # If no tabs were added successfully, show error and exit
        if self.tab_widget.count() == 0:
            raise RuntimeError("Failed to initialize any application tabs")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Project", self)
        new_action.triggered.connect(self.new_project)
        file_menu.addAction(new_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Scan menu
        scan_menu = menubar.addMenu("Scan")
        
        start_scan_action = QAction("Start Scan", self)
        start_scan_action.triggered.connect(self.start_scan)
        scan_menu.addAction(start_scan_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_toolbar(self):
        """Set up the main toolbar with icons and actions"""
        try:
            toolbar = QToolBar("Main Toolbar")
            toolbar.setIconSize(QSize(24, 24))
            self.addToolBar(toolbar)
            
            # Add toolbar actions with fallback icons
            new_action = QAction(get_icon('document-new'), "New", self)
            new_action.triggered.connect(self.new_project)
            toolbar.addAction(new_action)
            
            self.scan_action = QAction(get_icon('system-search'), "Scan", self)
            self.scan_action.triggered.connect(self.start_scan)
            toolbar.addAction(self.scan_action)
            
            report_action = QAction(get_icon('document-export'), "Export Report", self)
            report_action.triggered.connect(self.export_report)
            toolbar.addAction(report_action)
            
            # Add a spacer
            toolbar.addSeparator()
            
            # Add a status label
            self.status_label = QLabel("Ready")
            toolbar.addWidget(self.status_label)
            
        except Exception as e:
            QMessageBox.critical(self, "Toolbar Error", 
                               f"Failed to set up toolbar: {str(e)}")
            raise
        
    def new_project(self):
        """Create a new project"""
        try:
            # Ask for confirmation if there's unsaved work
            if hasattr(self, 'has_unsaved_changes') and self.has_unsaved_changes:
                reply = QMessageBox.question(
                    self, 'New Project',
                    'You have unsaved changes. Create a new project anyway?',
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return
            
            # Reset the application state
            self.scan_tab.reset()
            self.results_tab.clear_results()
            self.has_unsaved_changes = False
            
            self.statusBar().showMessage("New project created", 3000)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create new project: {str(e)}")
    
    def export_report(self):
        """Export scan results to a file"""
        try:
            # Get the current scan results
            if not hasattr(self, 'scan_tab') or not hasattr(self.scan_tab, 'get_results'):
                QMessageBox.information(self, "No Data", "No scan results to export.")
                return
                
            results = self.scan_tab.get_results()
            if not results:
                QMessageBox.information(self, "No Data", "No scan results to export.")
                return
            
            # Ask for save location
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Scan Results",
                QDir.homePath(),
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write("=== Scan Results ===\n\n")
                    f.write(str(results))
                
                self.statusBar().showMessage(f"Report exported to {file_path}", 5000)
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export report: {str(e)}")
        
    def start_scan(self):
        """Start the scanning process"""
        try:
            # Check if a scan is already in progress
            if hasattr(self, 'scan_tab') and hasattr(self.scan_tab, 'is_scanning') and self.scan_tab.is_scanning():
                QMessageBox.information(self, "Scan in Progress", "A scan is already in progress.")
                return
                
            self.statusBar().showMessage("Starting scan...")
            
            # Ensure scan tab is visible
            self.tab_widget.setCurrentWidget(self.scan_tab)
            
            # Start the scan
            if hasattr(self.scan_tab, 'start_scan'):
                self.scan_tab.start_scan()
                
        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"Failed to start scan: {str(e)}")
            self.statusBar().showMessage("Scan failed", 5000)
        
    def show_about(self):
        QMessageBox.about(self, "About", 
                         "Attack Surface Management System\n"
                         "Version 1.0\n\n"
                         "A comprehensive tool for identifying and managing "
                         "security vulnerabilities in your infrastructure.")
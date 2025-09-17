# gui/main_window.py
import os
import sys
import asyncio
import logging
from pathlib import Path
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QStatusBar, QAction, 
                            QToolBar, QMessageBox, QVBoxLayout, QWidget, 
                            QFileDialog, QLabel, QHBoxLayout, QSizePolicy, QProgressBar, QApplication)
from PyQt5.QtGui import QIcon, QPixmap, QFont, QPalette, QColor
from PyQt5.QtCore import Qt, QSize, QDir, QSettings

# Import ScanWidget after QApplication is imported
from .scan_widget import ScanWidget

# Local imports
from core.scanner import NetworkScanner
from .dashboard_widget import DashboardWidget
from .scan_widget import ScanWidget
from .results_widget import ResultsWidget

# Default icons mapping
DEFAULT_ICONS = {
    'document-new': 'document-new',
    'document-open': 'document-open',
    'document-save': 'document-save',
    'document-save-as': 'document-save-as',
    'edit-cut': 'edit-cut',
    'edit-copy': 'edit-copy',
    'edit-paste': 'edit-paste',
    'edit-delete': 'edit-delete',
    'edit-find': 'edit-find',
    'edit-find-replace': 'edit-find-replace',
    'view-refresh': 'view-refresh',
    'go-previous': 'go-previous',
    'go-next': 'go-next',
    'go-up': 'go-up',
    'go-down': 'go-down',
    'go-home': 'go-home',
    'document-print': 'document-print',
    'document-print-preview': 'document-print-preview',
    'help-contents': 'help-contents',
    'dialog-information': 'dialog-information',
    'dialog-warning': 'dialog-warning',
    'dialog-error': 'dialog-error',
    'dialog-question': 'dialog-question',
    'edit-undo': 'edit-undo',
    'edit-redo': 'edit-redo',
    'document-properties': 'document-properties',
    'system-search': 'system-search',
    'document-export': 'document-export',
    'application-exit': 'application-exit'
}

# Configure logging
logger = logging.getLogger(__name__)

def get_icon(name):
    """Get icon from theme or fallback to default"""
    icon = QIcon.fromTheme(name)
    if icon.isNull():
        # Try to load from resources or use a default icon
        icon = QIcon.fromTheme(DEFAULT_ICONS.get(name, 'application-x-executable'))
    return icon

class MainWindow(QMainWindow):
    async def _cleanup(self):
        """Clean up resources asynchronously"""
        try:
            if hasattr(self, 'tab_widget') and self.tab_widget:
                for i in range(self.tab_widget.count()):
                    widget = self.tab_widget.widget(i)
                    if hasattr(widget, 'cleanup_worker'):
                        try:
                            if asyncio.iscoroutinefunction(widget.cleanup_worker):
                                await widget.cleanup_worker()
                            elif hasattr(widget, 'cleanup_worker'):
                                # If cleanup_worker exists but isn't async, call it directly
                                widget.cleanup_worker()
                        except Exception as e:
                            logger.error(f"Error during tab cleanup: {str(e)}")
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
    
    def closeEvent(self, event):
        if getattr(self, '_closing', False):
            event.ignore()
            return
            
        self._closing = True
        event.ignore()  # Don't close until cleanup is done
        
        def _run_cleanup():
            try:
                # Create a new event loop for cleanup
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                async def _async_close():
                    try:
                        # Clean up all tabs
                        if hasattr(self, 'tab_widget') and self.tab_widget:
                            for i in range(self.tab_widget.count()):
                                widget = self.tab_widget.widget(i)
                                if hasattr(widget, 'cleanup_worker'):
                                    try:
                                        if asyncio.iscoroutinefunction(widget.cleanup_worker):
                                            await widget.cleanup_worker()
                                        elif hasattr(widget, 'cleanup_worker'):
                                            # If cleanup_worker exists but isn't async, call it directly
                                            widget.cleanup_worker()
                                    except Exception as e:
                                        logger.error(f"Error during tab cleanup: {str(e)}")
                        
                        # Save window state and geometry
                        settings = QSettings("AttackSurfaceManager", "MainWindow")
                        settings.setValue("geometry", self.saveGeometry())
                        settings.setValue("windowState", self.saveState())
                        
                        # Close the application
                        self.deleteLater()
                        
                    except Exception as e:
                        logger.error(f"Error during shutdown: {str(e)}")
                    finally:
                        # Get QApplication instance and quit
                        app = QApplication.instance()
                        if app is not None:
                            app.quit()
                
                # Run the async cleanup
                loop.run_until_complete(_async_close())
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {str(e)}")
                app = QApplication.instance()
                if app is not None:
                    app.quit()
        
        # Run cleanup in a separate thread to avoid blocking the UI
        import threading
        cleanup_thread = threading.Thread(target=_run_cleanup, daemon=True)
        cleanup_thread.start()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Attack Surface Manager")
        self.setGeometry(100, 100, 1200, 800)
        self._closing = False
        
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
        
        # Initialize tabs list to keep track of successfully added tabs
        self.tabs = {}
        
        # Define tabs to be added with their initialization parameters
        tab_definitions = [
            ("Dashboard", DashboardWidget, "dashboard_tab", {}),
            ("Scan", ScanWidget, "scan_tab", {"scan_type": "port", "target": ""}),
            ("Results", ResultsWidget, "results_tab", {})
        ]
        
        for name, widget_class, attr_name, init_params in tab_definitions:
            try:
                logger.info(f"Initializing {name} tab...")
                tab_instance = widget_class(**init_params)
                self.tab_widget.addTab(tab_instance, name)
                setattr(self, attr_name, tab_instance)
                self.tabs[name.lower()] = tab_instance
                logger.info(f"Successfully initialized {name} tab")
            except Exception as e:
                error_msg = f"Failed to initialize {name} tab: {str(e)}"
                logger.error(error_msg, exc_info=True)
                QMessageBox.warning(self, f"{name} Tab Error", error_msg)
        
        # Verify scan tab was initialized
        if not hasattr(self, 'scan_tab') or self.scan_tab is None:
            logger.error("Scan tab initialization failed. Available tabs: %s", list(self.tabs.keys()))
            raise RuntimeError("Failed to initialize Scan tab. Check logs for details.")
            
        # If no tabs were added successfully, show error and exit
        if self.tab_widget.count() == 0:
            raise RuntimeError("Failed to initialize any application tabs. Check the logs for details.")
            
        logger.info(f"Successfully initialized {self.tab_widget.count()} tabs")
        
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
            toolbar.setObjectName("mainToolbar")  # Add this line to set object name
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
            # First, check if we have a direct reference to scan_tab
            if hasattr(self, 'scan_tab') and self.scan_tab is not None:
                scan_tab = self.scan_tab
            else:
                # Fallback: Try to find the scan tab by its type
                scan_tab = None
                for i in range(self.tab_widget.count()):
                    tab = self.tab_widget.widget(i)
                    if isinstance(tab, ScanWidget):  # Check if tab is an instance of ScanWidget
                        scan_tab = tab
                        self.scan_tab = tab  # Cache the reference for future use
                        break
            
            if not scan_tab:
                raise RuntimeError("Scan tab not found. The scan functionality is not available.")
                
            # Check if a scan is already in progress
            if hasattr(scan_tab, 'is_scanning') and callable(scan_tab.is_scanning):
                if scan_tab.is_scanning():
                    QMessageBox.information(self, "Scan in Progress", "A scan is already in progress.")
                    return
            
            self.statusBar().showMessage("Starting scan...")
            
            try:
                # Ensure scan tab is visible
                self.tab_widget.setCurrentWidget(scan_tab)
                
                # Start the scan
                if hasattr(scan_tab, 'start_scan') and callable(scan_tab.start_scan):
                    scan_tab.start_scan()
                    self.statusBar().showMessage("Scan started successfully")
                else:
                    raise RuntimeError("Scan tab does not have a start_scan method")
                    
            except Exception as e:
                raise RuntimeError(f"Error while starting scan: {str(e)}")
                
        except Exception as e:
            error_msg = f"Failed to start scan: {str(e)}"
            logger.error(error_msg, exc_info=True)
            QMessageBox.critical(self, "Scan Error", error_msg)
            self.statusBar().showMessage("Scan failed", 5000)
        
    def show_about(self):
        QMessageBox.about(self, "About", 
                         "Attack Surface Management System\n"
                         "Version 1.0\n\n"
                         "A comprehensive tool for identifying and managing "
                         "security vulnerabilities in your infrastructure.")
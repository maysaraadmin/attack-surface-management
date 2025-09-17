# main.py
import sys
import os
import asyncio
import traceback
import logging
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QCoreApplication
from gui.main_window import MainWindow

# Set up logging
def setup_logging():
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Clear previous log file with error handling
    log_file = log_dir / "app.log"
    if log_file.exists():
        try:
            log_file.unlink()
        except (PermissionError, OSError) as e:
            # If we can't delete the file, try to append to it with a separator
            try:
                with open(log_file, 'a') as f:
                    f.write("\n" + "="*50 + "\n")
                    f.write(f"New session started at {logging.Formatter('%(asctime)s').formatTime(logging.LogRecord(None, None, '', 0, '', (), None))}\n")
                    f.write("="*50 + "\n")
            except Exception:
                # If even appending fails, create a new log file with timestamp
                timestamp = logging.Formatter('%Y%m%d_%H%M%S').formatTime(logging.LogRecord(None, None, '', 0, '', (), None))
                log_file = log_dir / f"app_{timestamp}.log"
    
    # Set up root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # File handler for all logs
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # Console handler for warnings and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Enable debug logging for our application
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('gui').setLevel(logging.DEBUG)
    logging.getLogger('core').setLevel(logging.DEBUG)
    
    return logging.getLogger(__name__)

logger = setup_logging()

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler"""
    # Skip keyboard interrupt to allow normal termination
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
        
    error_msg = """
    An unhandled exception occurred:
    
    Type: {}
    Value: {}
    
    Traceback:
    {}
    """.format(
        exc_type.__name__,
        str(exc_value),
        "".join(traceback.format_tb(exc_traceback))
    )
    
    logger.critical("Unhandled exception: %s", error_msg, exc_info=(exc_type, exc_value, exc_traceback))
    
    # Show error dialog if QApplication exists
    app = QApplication.instance()
    if app is not None and QApplication.startingUp() is False and QApplication.closingDown() is False:
        try:
            error_box = QMessageBox()
            error_box.setIcon(QMessageBox.Critical)
            error_box.setWindowTitle("Error")
            error_box.setText("An unexpected error occurred")
            error_box.setDetailedText(error_msg)
            error_box.setStandardButtons(QMessageBox.Ok)
            error_box.exec_()
        except Exception as e:
            logger.error("Failed to show error dialog: %s", str(e), exc_info=True)
            print(f"Critical error: {error_msg}", file=sys.stderr)

def setup_application():
    """Configure application-wide settings"""
    # Enable High DPI scaling
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    
    # Set application information
    QCoreApplication.setOrganizationName("SecurityTeam")
    QCoreApplication.setApplicationName("Attack Surface Manager")
    QCoreApplication.setApplicationVersion("1.0.0")
    
    # Create application instance
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application icon if available
    try:
        icon_path = Path("assets/icons/app_icon.png")
        if icon_path.exists():
            app.setWindowIcon(QIcon(str(icon_path)))
    except Exception as e:
        logger.warning("Failed to set application icon: %s", str(e))
    
    return app

def main():
    # Set up global exception handler
    sys.excepthook = handle_exception
    
    try:
        logger.info("Starting application")
        
        # Create application instance
        app = QApplication(sys.argv)
        
        # Create and show main window
        window = MainWindow()
        window.show()
        
        # Start the event loop
        logger.info("Application started successfully")
        sys.exit(app.exec_())
            
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        if 'app' in locals():
            QMessageBox.critical(
                None,
                "Fatal Error",
                f"A fatal error occurred:\n{str(e)}\n\nCheck logs for more details."
            )
        return 1
    finally:
        logger.info("Application shutdown")

if __name__ == '__main__':
    sys.exit(main())
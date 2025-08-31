# main.py
import sys
import os
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
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "app.log"),
            logging.StreamHandler()
        ]
    )
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
        
        # Set up and configure the application
        app = setup_application()
        
        try:
            # Create and show main window
            window = MainWindow()
            window.show()
            
            logger.info("Application started successfully")
            return app.exec_()
            
        except Exception as e:
            logger.critical("Failed to create main window", exc_info=True)
            handle_exception(type(e), e, e.__traceback__)
            return 1
            
    except Exception as e:
        logger.critical("Failed to initialize application", exc_info=True)
        handle_exception(type(e), e, e.__traceback__)
        return 1
    finally:
        logger.info("Application shutdown")
        # Ensure all resources are cleaned up
        if 'app' in locals():
            app.quit()

if __name__ == '__main__':
    sys.exit(main())
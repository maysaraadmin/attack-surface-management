# gui/results_widget.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
                            QTreeWidgetItem, QSplitter, QTextEdit, QLabel,
                            QPushButton, QHeaderView)
from PyQt5.QtCore import Qt

class ResultsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.load_sample_data()
        
    def setup_ui(self):
        layout = QHBoxLayout()
        
        # Splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Results tree
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Target", "Type", "Status", "Risk"])
        self.results_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.results_tree.itemClicked.connect(self.show_details)
        
        # Right panel - Details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        details_layout.addWidget(QLabel("Scan Details:"))
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export Report")
        self.delete_btn = QPushButton("Delete Result")
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.delete_btn)
        details_layout.addLayout(button_layout)
        
        splitter.addWidget(self.results_tree)
        splitter.addWidget(details_widget)
        splitter.setSizes([300, 500])
        
        layout.addWidget(splitter)
        self.setLayout(layout)
    
    def load_sample_data(self):
        # Sample data for demonstration
        targets = [
            ("192.168.1.1", "Port Scan", "Completed", "Medium"),
            ("example.com", "Web Scan", "Completed", "High"),
            ("10.0.0.1", "Port Scan", "Failed", "Unknown")
        ]
        
        for target, scan_type, status, risk in targets:
            item = QTreeWidgetItem([target, scan_type, status, risk])
            self.results_tree.addTopLevelItem(item)
    
    def show_details(self, item):
        target = item.text(0)
        scan_type = item.text(1)
        
        details = f"""
        Target: {target}
        Scan Type: {scan_type}
        Status: {item.text(2)}
        Risk Level: {item.text(3)}
        
        Detailed Results:
        - Port 80: HTTP - Apache/2.4.41
        - Port 443: HTTPS - OpenSSL 1.1.1
        - Port 22: SSH - OpenSSH 8.2
        
        Recommendations:
        - Update Apache to latest version
        - Consider closing unnecessary ports
        - Implement proper firewall rules
        """
        
        self.details_text.setText(details)
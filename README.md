# Attack Surface Management System

A comprehensive tool for identifying, analyzing, and managing the attack surface of your infrastructure.

## Features

- **Port Scanning**: Discover open ports and services
- **Web Application Scanning**: Analyze web applications for common vulnerabilities
- **DNS Lookup**: Perform various DNS record lookups
- **Vulnerability Assessment**: Identify potential security issues
- **Interactive GUI**: User-friendly interface built with PyQt5

## Installation

1. **Prerequisites**:
   - Python 3.7 or higher
   - Nmap (for port scanning)
   - Git (optional, for cloning the repository)

2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/attack-surface-management.git
   cd attack-surface-management
   ```

3. **Create a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Start the application**:
   ```bash
   python main.py
   ```

2. **Using the application**:
   - **Dashboard**: View scan statistics and recent activity
   - **Scan**: Perform port scans and web application scans
   - **Results**: View and manage scan results

## Features in Detail

### Port Scanning
- TCP SYN scanning
- Service version detection
- Custom port ranges
- Quick scan options

### Web Application Scanning
- HTTP header analysis
- Security headers check
- Technology detection
- Basic vulnerability scanning

### DNS Analysis
- A, AAAA, MX, NS, TXT record lookups
- Reverse DNS lookups
- DNS zone transfer testing

## Security Considerations

- The application performs network scans which may be restricted in some environments
- Always ensure you have proper authorization before scanning any network
- Use responsibly and in accordance with all applicable laws and regulations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

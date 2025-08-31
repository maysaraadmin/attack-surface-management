# core/scanner.py
import nmap
import requests
import socket
import ssl
from urllib.parse import urlparse
import concurrent.futures
from datetime import datetime
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
    
    def port_scan(self, target, ports='1-1024'):
        """
        Perform a port scan on the target
        
        Args:
            target (str): IP address or hostname to scan
            ports (str): Ports to scan (default: 1-1024)
            
        Returns:
            dict: Scan results or error information
        """
        if not target:
            return {'error': 'No target specified'}
            
        # Validate target format (basic validation)
        try:
            # Check if it's an IP address
            socket.inet_aton(target)
        except socket.error:
            try:
                # Check if it's a valid hostname
                socket.gethostbyname(target)
            except socket.gaierror:
                return {'error': 'Invalid target format. Use IP or hostname'}
        
        try:
            logger.info(f"Starting port scan on {target} (ports: {ports})")
            
            # Use more conservative timing for better reliability
            scan_result = self.nm.scan(
                hosts=target,
                ports=ports,
                arguments='-sS -T3 --min-rate=1000'  # SYN scan with timing template 3 (normal)
            )
            
            if not scan_result.get('scan'):
                return {'error': 'No scan results returned'}
                
            return scan_result['scan']
            
        except nmap.PortScannerError as e:
            error_msg = f"Nmap scan failed: {str(e)}"
            logger.error(error_msg)
            return {'error': error_msg}
        except Exception as e:
            error_msg = f"Unexpected error during port scan: {str(e)}"
            logger.exception(error_msg)
            return {'error': error_msg}
    
    def service_discovery(self, target, port):
        """Discover services running on ports"""
        try:
            result = self.nm.scan(target, str(port), arguments='-sV')
            return result['scan']
        except Exception as e:
            return {'error': str(e)}
    
    def web_scan(self, url):
        """
        Scan web applications with improved error handling and security
        
        Args:
            url (str): The URL to scan
            
        Returns:
            dict: Scan results including headers, status code, and detected technologies
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        results = {
            'url': url,
            'headers': {},
            'technologies': [],
            'vulnerabilities': [],
            'error': None
        }
        
        try:
            # Basic URL validation
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                raise ValueError("Invalid URL format")
                
            # Configure session with security headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackSurfaceScanner/1.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            })
            
            # Make the request with timeout and redirect handling
            response = session.get(
                url, 
                timeout=10, 
                verify=False,  # Warning: Disabling SSL verification is not recommended for production
                allow_redirects=True,
                stream=True  # Don't download the whole response body immediately
            )
            
            # Process response
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            
            # Basic technology detection
            server_header = response.headers.get('server')
            if server_header:
                results['technologies'].append(f"Server: {server_header}")
                
            # Check for common security headers
            security_headers = [
                'x-xss-protection',
                'x-content-type-options',
                'x-frame-options',
                'content-security-policy',
                'strict-transport-security'
            ]
            
            missing_headers = [h for h in security_headers if h not in map(str.lower, response.headers)]
            if missing_headers:
                results['vulnerabilities'].append({
                    'type': 'security_headers_missing',
                    'severity': 'medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}'
                })
                
            # Check for server version disclosure
            if server_header and any(char.isdigit() for char in server_header):
                results['vulnerabilities'].append({
                    'type': 'server_version_disclosure',
                    'severity': 'low',
                    'description': f'Server version disclosed: {server_header}'
                })
            
            response.close()  # Ensure response is closed
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning {url}: {str(e)}")
            results['error'] = f"Request failed: {str(e)}"
        except Exception as e:
            logger.exception(f"Unexpected error scanning {url}")
            results['error'] = f"Unexpected error: {str(e)}"
        
        return results

class VulnerabilityScanner:
    def __init__(self):
        self.common_vulnerabilities = {
            'xss': 'Cross-Site Scripting',
            'sql_injection': 'SQL Injection',
            'csrf': 'Cross-Site Request Forgery',
            'rce': 'Remote Code Execution',
            'lfi': 'Local File Inclusion'
        }
    
    def check_common_vulns(self, target_data):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Placeholder for actual vulnerability checks
        # In a real system, this would integrate with tools like OWASP ZAP, Nuclei, etc.
        
        return vulnerabilities
# core/scanner.py
import socket
import ssl
import time
import random
import ipaddress
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
from typing import Dict, List, Union, Optional, Tuple, Any, Set
import requests
import httpx
from scapy.all import IP, TCP, sr1, conf, sr
from scapy.error import Scapy_Exception
from urllib.parse import urlparse, urlunparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from functools import partial

# Suppress only the single InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure Scapy to be less verbose
conf.verb = 0

# Common service ports and their typical services
COMMON_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
    8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb', 9200: 'elasticsearch'
}

# HTTP/HTTPS service detection fingerprints
SERVICE_FINGERPRINTS = {
    'http': [
        (b'Server', lambda x: x),
        (b'server', lambda x: x),
        (b'X-Powered-By', lambda x: x),
    ],
    'https': [
        (b'server', lambda x: x),
        (b'X-Powered-By', lambda x: x),
    ]
}

class NetworkScanner:
    def __init__(self):
        self.results = {}
        self.timeout = 2  # Default timeout in seconds
        self.threads = 50  # Default number of threads for concurrent scanning
        self.http_client = None
        self._init_http_client()
    
    def _init_http_client(self):
        """Initialize the HTTP client with default settings"""
        http2_enabled = False
        try:
            import h2  # Try to import h2 to check if it's installed
            http2_enabled = True
            logger.info("HTTP/2 support enabled")
        except ImportError:
            logger.warning("h2 package not found. HTTP/2 support disabled. Install with: pip install 'httpx[http2]'")
            
        self.http_client = httpx.AsyncClient(
            verify=False,  # Disable SSL verification for now
            timeout=10.0,
            follow_redirects=True,
            http2=http2_enabled,  # Only enable HTTP/2 if h2 is installed
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        )
    
    async def close(self):
        """Close any open connections"""
        if self.http_client:
            await self.http_client.aclose()
    
    def _is_valid_ip(self, target: str) -> bool:
        """Check if the target is a valid IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    async def _probe_http_service(self, target: str, port: int, is_ssl: bool = False) -> Dict[str, Any]:
        """Probe HTTP/HTTPS service for additional information"""
        scheme = 'https' if is_ssl or port in (443, 8443) else 'http'
        base_url = f"{scheme}://{target}:{port}"
        
        try:
            # Try to get root path
            response = await self.http_client.get(base_url)
            
            service_info = {
                'name': 'http' if scheme == 'http' else 'https',
                'product': None,
                'version': None,
                'extrainfo': {},
                'banner': None,
                'status_code': response.status_code,
                'headers': dict(response.headers)
            }
            
            # Try to extract server information from headers
            for header, value in response.headers.items():
                header_lower = header.lower()
                if 'server' in header_lower:
                    service_info['product'] = value.split('/')[0]
                elif 'x-powered-by' in header_lower:
                    service_info['extrainfo']['powered_by'] = value
            
            # Try to get /server-status or /status for more info
            if response.status_code == 200:
                status_urls = [
                    f"{base_url}/server-status",
                    f"{base_url}/status",
                    f"{base_url}/api/status"
                ]
                
                for status_url in status_urls:
                    try:
                        status_resp = await self.http_client.get(status_url, timeout=5)
                        if status_resp.status_code == 200 and 'server-status' in status_resp.headers.get('content-type', ''):
                            service_info['extrainfo']['server_status'] = 'enabled'
                            break
                    except Exception:
                        continue
            
            return service_info
            
        except Exception as e:
            logger.debug(f"HTTP probe failed for {base_url}: {str(e)}")
            return {
                'name': 'http' if scheme == 'http' else 'https',
                'error': str(e)
            }
    
    def _scan_port(self, target: str, port: int) -> Optional[Dict]:
        """
        Scan a single port using Scapy
        Returns a dictionary with port status or None if there was an error
        """
        try:
            # Create SYN packet
            ip_pkt = IP(dst=target)
            tcp_pkt = TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            
            # Send packet and get response
            response = sr1(ip_pkt/tcp_pkt, timeout=self.timeout, verbose=0)
            
            if response is None:
                return None
                
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close the connection
                    rst_pkt = IP(dst=target)/TCP(sport=tcp_pkt.sport, dport=port, flags="R")
                    sr1(rst_pkt, timeout=self.timeout, verbose=0)
                    
                    # Get service name
                    service_name = self._get_service_name(port)
                    
                    # For common HTTP/HTTPS ports, we'll do deeper inspection later
                    if port in [80, 443, 8080, 8443, 8000, 8888]:
                        service_name = 'http' if port in [80, 8080, 8000, 8888] else 'https'
                    
                    return {
                        'port': port,
                        'state': 'open',
                        'service': service_name,
                        'protocol': 'tcp'
                    }
                elif response[TCP].flags == 0x14:  # RST-ACK
                    return None
                    
        except Scapy_Exception as e:
            logger.warning(f"Scapy error while scanning port {port}: {str(e)}")
            
        return None
    
    def _get_service_name(self, port: int, protocol: str = 'tcp') -> str:
        """Get service name from common port numbers"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
            8080: 'http-proxy', 8443: 'https-alt'
        }
        return common_ports.get(port, 'unknown')
    
    async def port_scan(self, target: str, ports: str = '1-1024') -> Dict:
        """
        Perform a port scan on the target using Scapy for fast port scanning
        and HTTP/HTTPS service detection
        
        Args:
            target: IP address or hostname to scan
            ports: Ports to scan (e.g., '1-1024', '22,80,443', '1-100,8080,9000-9100')
            
        Returns:
            dict: Scan results or error information
        """
        if not target:
            return {'error': 'No target specified'}
        
        # Validate target
        ip = target if self._is_valid_ip(target) else self._resolve_hostname(target)
        if not ip:
            return {'error': 'Invalid target format. Use IP or hostname'}
        
        # Parse port ranges
        port_list = self._parse_ports(ports)
        if not port_list:
            return {'error': 'Invalid port range'}
        
        results = {ip: {'tcp': {}}}
        open_ports = []
        
        try:
            logger.info(f"Starting port scan on {target} ({ip}) with {len(port_list)} ports")
            
            # Scan ports in parallel using thread pool
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Create a partial function with the target IP
                scan_func = partial(self._scan_port, ip)
                
                # Submit all port scans
                future_to_port = {
                    executor.submit(scan_func, port): port 
                    for port in port_list
                }
                
                # Process results as they complete
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            port_num = result['port']
                            results[ip]['tcp'][port_num] = {
                                'state': 'open',
                                'name': result['service'],
                                'protocol': 'tcp'
                            }
                            open_ports.append(port_num)
                    except Exception as e:
                        logger.warning(f"Error scanning port {port}: {str(e)}")
            
            # If no ports were found open, return error
            if not open_ports:
                return {'error': 'No open ports found'}
                
            # Perform service detection on open ports
            await self._perform_service_detection(target, open_ports, results[ip])
            
            return results
            
        except Exception as e:
            error_msg = f"Error during port scan: {str(e)}"
            logger.exception(error_msg)
            return {'error': error_msg}
    
    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse port ranges string into a list of port numbers"""
        ports = set()
        
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
                
        return sorted(ports)
    
    async def _perform_service_detection(self, target: str, ports: List[int], result: Dict) -> None:
        """Perform service detection using various techniques"""
        try:
            # Process each open port
            tasks = []
            for port in ports:
                port_info = result['tcp'][port]
                service = port_info.get('name', '').lower()
                
                # Handle HTTP/HTTPS services
                if service in ['http', 'https', 'http-proxy', 'https-alt'] or port in [80, 443, 8080, 8443]:
                    is_ssl = service in ['https', 'https-alt'] or port in [443, 8443]
                    tasks.append(self._probe_http_service(target, port, is_ssl))
                # Add more service detection here as needed
                
            # Run all service detection tasks concurrently
            if tasks:
                service_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Update results with service information
                for port, service_info in zip(ports, service_results):
                    if isinstance(service_info, dict) and 'error' not in service_info:
                        result['tcp'][port].update({
                            'name': service_info.get('name', result['tcp'][port].get('name', 'unknown')),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', {})
                        })
                        
        except Exception as e:
            logger.warning(f"Service detection failed: {str(e)}")
            
    async def close(self):
        """Close any open connections"""
        if self.http_client:
            await self.http_client.aclose()
    
    async def service_discovery(self, target: str, port: int) -> Dict:
        """
        Discover services running on a specific port
        
        Args:
            target: IP address or hostname
            port: Port number to scan
            
        Returns:
            dict: Service information or error message
        """
        try:
            # First check if port is open
            port_scan = await self.port_scan(target, str(port))
            if 'error' in port_scan:
                return port_scan
                
            # If port is open, perform service detection
            if target in port_scan and str(port) in port_scan[target].get('tcp', {}):
                # Use the existing service detection logic
                await self._perform_service_detection(target, [port], port_scan[target])
                return port_scan[target]['tcp'][port]
            
            return {'error': f'Port {port} is not open or not accessible'}
            
        except Exception as e:
            error_msg = f"Service discovery failed: {str(e)}"
            logger.exception(error_msg)
            return {'error': error_msg}
            
        finally:
            # Clean up any resources
            await self.close()
    
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
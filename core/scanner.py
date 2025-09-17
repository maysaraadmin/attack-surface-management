# core/scanner.py
import socket
import os
import ssl
import sys
import time
import random
import aiohttp
import asyncio
import ipaddress
import json
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from typing import Dict, List, Union, Optional, Tuple, Any, Set
import requests
import httpx
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.error import Scapy_Exception
# Import get_working_ifaces from the correct location based on Scapy version
try:
    from scapy.interfaces import get_working_ifaces
except ImportError:
    from scapy.arch import get_working_ifaces
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
    3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
    8080: 'http-proxy', 8443: 'https-alt'
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
    def __init__(self, debug=False):
        """
        Initialize the NetworkScanner.
        
        Args:
            debug (bool): Enable debug logging if True
        """
        self.results = {
            'status': 'initialized',
            'start_time': None,
            'end_time': None,
            'scan_duration': 0,
            'technologies': [],
            'vulnerabilities': [],
            'security_headers': {},
            'directories': [],
            'errors': []
        }
        self.timeout = 10  # Increased default timeout to 10 seconds
        self.threads = 50  # Default number of threads for concurrent scanning
        self.http_client = None
        self.sync_http_client = requests.Session()  # Initialize sync client immediately
        self._stop_requested = False  # Flag to control scan cancellation
        self._executor = None  # ThreadPoolExecutor instance
        
        # Initialize logger
        self.logger = logging.getLogger('scanner')
        self.debug = debug
        
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
            # Add console handler for debug output
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            
        self.logger.info("Initializing NetworkScanner")
        
        try:
            # Configure network settings first
            self._configure_network()
            # Don't initialize async client here, it will be initialized when needed
            self.logger.info("NetworkScanner initialization completed successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize NetworkScanner: {e}", exc_info=True)
            raise
        
    async def _init_http_client(self):
        """
        Initialize the async HTTP client with proper SSL context and timeout settings.
        
        This method should be called from within an async context.
        """
        if self.http_client is not None and not getattr(self.http_client, 'closed', True):
            self.logger.debug("HTTP client already initialized")
            return True
            
        try:
            self.logger.debug("Initializing HTTP client...")
            
            # Create a custom SSL context to handle various SSL/TLS versions
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Configure timeout settings
            timeout = aiohttp.ClientTimeout(
                total=30,  # Total request timeout in seconds
                connect=10,  # Connection timeout in seconds
                sock_connect=10,  # Socket connect timeout in seconds
                sock_read=10,  # Socket read timeout in seconds
            )
            
            # Configure connection pooling
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=100,  # Max number of simultaneous connections
                limit_per_host=10,  # Max connections per host
                ttl_dns_cache=300,  # DNS cache TTL in seconds
                force_close=True,  # Force close connections when done
                enable_cleanup_closed=True  # Clean up closed transports
            )
            
            # Create the async HTTP client with default headers
            self.http_client = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Cache-Control': 'max-age=0'
                },
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize HTTP client: {e}", exc_info=True)
            self.http_client = None
            return False
    
    async def __aenter__(self):
        """Async context manager entry point."""
        self.logger.debug("Entering NetworkScanner async context")
        if not await self._init_http_client():
            raise RuntimeError("Failed to initialize HTTP client")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit point."""
        self.logger.debug("Exiting NetworkScanner async context")
        await self.close()
    
    def __getattr__(self, name):
        """Forward undefined attribute access to the HTTP client."""
        if self.http_client is not None:
            return getattr(self.http_client, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    async def __call__(self, *args, **kwargs):
        """Allow the instance to be called as a function."""
        if self.http_client is None:
            raise RuntimeError("HTTP client not initialized")
        return await self.http_client(*args, **kwargs)
    
    async def close(self):
        """Close the HTTP client and clean up resources."""
        if self.http_client is not None and not self.http_client.closed:
            self.logger.debug("Closing HTTP client session")
            await self.http_client.close()
            self.http_client = None
        
        if hasattr(self, '_executor') and self._executor is not None:
            self.logger.debug("Shutting down thread pool executor")
            self._executor.shutdown(wait=False)
            self._executor = None
            
        # Close the sync HTTP client if it exists
        if hasattr(self, 'sync_http_client') and self.sync_http_client is not None:
            self.sync_http_client.close()
        
    def _configure_network(self):
        """Configure network-related settings for the scanner."""
        # Set socket timeout
        socket.setdefaulttimeout(self.timeout)
        
        # Configure asyncio event loop policy for Windows if needed
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        # Configure Scapy to be less verbose
        conf.verb = 0
        
        # Disable Scapy's IPv6 warning
        conf.warning_threshold = 0
        
        # Configure requests to retry on failure
        retry_strategy = requests.adapters.Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        # Configure default headers for sync client
        self.sync_http_client.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        # Mount the retry adapter
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.sync_http_client.mount("http://", adapter)
        self.sync_http_client.mount("https://", adapter)
        
        # Disable SSL warnings for requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    async def scan_web_application(self, url, callback=None):
        """
        Scan a web application for common vulnerabilities and gather information.
        
        Args:
            url (str): The URL of the web application to scan
            callback (callable, optional): A callback function that receives progress updates
                                          as (progress_percent, message)
            
        Returns:
            dict: A dictionary containing scan results including vulnerabilities, technologies, etc.
        """
        self.logger.info(f"Starting web application scan for: {url}")
        start_time = time.time()
        
        # Reset results
        self.results = {
            'url': url,
            'status': 'started',
            'technologies': [],
            'vulnerabilities': [],
            'security_headers': {},
            'directories': [],
            'scan_duration': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'error': None,
            'warnings': []
        }
        
        def update_progress(progress, message):
            """Update progress and log the message."""
            self.logger.info(f"Progress {progress}%: {message}")
            if callback:
                try:
                    callback(progress, message)
                except Exception as e:
                    self.logger.warning(f"Error in progress callback: {e}")
        
        # Start the scan with proper error handling
        try:
            # Initialize progress tracking
            update_progress(0, "Starting scan...")
            
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                self.logger.warning("URL missing scheme, defaulting to http://")
                url = 'http://' + url
                
            # Parse the URL
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            update_progress(5, f"Connecting to {base_url}...")
            self.logger.debug(f"Base URL: {base_url}")
            
            # Initialize async client if not already done
            if self.http_client is None or self.http_client.closed:
                if not await self._init_http_client():
                    raise RuntimeError("Failed to initialize HTTP client")
            
            # Configure timeout settings
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=10,
                sock_connect=10,
                sock_read=10
            )
            
            # Start the main scanning process
            async with self.http_client as session:
                update_progress(7, f"Sending request to {base_url}...")
                
                try:
                    # Make the initial request with proper timeout handling
                    async with session.get(base_url, allow_redirects=True, timeout=timeout) as response:
                        self.logger.info(f"Connected to {base_url}, status: {response.status}")
                        update_progress(10, f"Connected to server (Status: {response.status})")
                        
                        # Store basic response info
                        self.results['status_code'] = response.status
                        self.results['status'] = 'scanning'
                        
                        # Check for redirects
                        if response.history:
                            self.results['redirects'] = [str(r.url) for r in response.history]
                            self.results['final_url'] = str(response.url)
                            self.logger.info(f"Redirected to: {response.url}")
                        
                        # Detect technologies
                        update_progress(20, "Detecting technologies...")
                        await self._detect_technologies(response, self.results, update_progress)
                        
                        # Check security headers
                        update_progress(40, "Checking security headers...")
                        self._check_security_headers(response, self.results)
                        
                        # Check for common vulnerabilities
                        update_progress(60, "Scanning for vulnerabilities...")
                        await self._check_common_vulnerabilities(session, base_url, self.results)
                        
                        # Look for common directories and files
                        update_progress(80, "Checking for common directories and files...")
                        await self._check_common_files_exposure(session, base_url, self.results)
                        
                        # Generate security report
                        security_report = self._generate_security_report(self.results)
                        if security_report:
                            self.results['security_report'] = security_report
                        
                        # Update status and timing if we reach here (no errors)
                        self.results['status'] = 'completed'
                        self.results['end_time'] = datetime.now().isoformat()
                        self.results['scan_duration'] = time.time() - start_time
                        
                        update_progress(100, "Scan completed successfully!")
                        self.logger.info(f"Scan completed in {self.results['scan_duration']:.2f} seconds")
                        
                        return self.results
                        
                except asyncio.TimeoutError:
                    error_msg = f"Connection to {base_url} timed out after 30 seconds"
                    self.logger.error(error_msg)
                    self.results['status'] = 'error'
                    self.results['error'] = "Connection timeout: The server took too long to respond"
                    self.results['warnings'] = self.results.get('warnings', []) + ["The server may be down or experiencing high load"]
                    self.results['end_time'] = datetime.now().isoformat()
                    self.results['scan_duration'] = time.time() - start_time
                    update_progress(0, "Error: Connection timed out")
                    return self.results
                    
                except aiohttp.ClientError as e:
                    error_msg = f"HTTP client error: {str(e)}"
                    self.logger.error(error_msg, exc_info=True)
                    self.results['status'] = 'error'
                    self.results['error'] = f"Connection error: {str(e)}"
                    self.results['end_time'] = datetime.now().isoformat()
                    self.results['scan_duration'] = time.time() - start_time
                    update_progress(0, f"Error: Connection failed - {str(e)[:100]}")
                    return self.results
                
                except Exception as e:
                    error_msg = f"Unexpected error: {str(e)}"
                    self.logger.error(error_msg, exc_info=True)
                    self.results['status'] = 'error'
                    self.results['error'] = error_msg
                    self.results['end_time'] = datetime.now().isoformat()
                    self.results['scan_duration'] = time.time() - start_time
                    update_progress(0, f"Error: {error_msg[:100]}")
                    return self.results
                    
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            self.results['status'] = 'error'
            self.results['error'] = error_msg
            self.results['end_time'] = datetime.now().isoformat()
            self.results['scan_duration'] = time.time() - start_time
            update_progress(0, f"Error: {error_msg}")
            return self.results
    
    async def _detect_technologies(self, response, results, callback=None):
        """Detect web technologies based on response headers and content"""
        try:
            if callback:
                callback(30, "Detecting web technologies...")
                
            # Handle both aiohttp and requests response objects
            if hasattr(response, 'headers'):
                headers = {k.lower(): str(v).lower() for k, v in response.headers.items()}
            else:
                headers = {k.lower(): str(v).lower() for k, v in response.get('headers', {}).items()}
            
            # Get content from response
            if hasattr(response, 'text'):
                if asyncio.iscoroutinefunction(response.text):
                    content = (await response.text()).lower()
                else:
                    content = str(response.text).lower()
            else:
                content = str(response.get('text', '')).lower()
            
            # Check for common web servers
            if 'server' in headers:
                server = headers['server']
                results['technologies'].append({
                    'name': 'Web Server',
                    'version': server,
                    'confidence': 'high'
                })
                
                # Detect specific server types
                if 'apache' in server:
                    results['technologies'].append({
                        'name': 'Apache',
                        'version': server.replace('apache/', '').strip(),
                        'confidence': 'high'
                    })
                elif 'nginx' in server:
                    results['technologies'].append({
                        'name': 'Nginx',
                        'version': server.replace('nginx/', '').strip(),
                        'confidence': 'high'
                    })
            
            # Check for common frameworks
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by']
                if powered_by:  # Only add if not empty
                    results['technologies'].append({
                        'name': 'Powered By',
                        'version': '',
                        'details': powered_by,
                        'confidence': 'medium'
                    })
            
            # Check for common frameworks in content
            if content:  # Only check if we have content
                if 'wordpress' in content:
                    results['technologies'].append({
                        'name': 'WordPress',
                        'confidence': 'high'
                    })
                
                if 'drupal' in content:
                    results['technologies'].append({
                        'name': 'Drupal',
                        'confidence': 'high'
                    })
                    
                if 'jquery' in content:
                    results['technologies'].append({
                        'name': 'jQuery',
                        'confidence': 'medium'
                    })
                    
                # Check for JavaScript frameworks
                if 'react' in content or 'react-dom' in content:
                    results['technologies'].append({
                        'name': 'React',
                        'confidence': 'medium'
                    })
                    
                if 'vue' in content:
                    results['technologies'].append({
                        'name': 'Vue.js',
                        'confidence': 'medium'
                    })
                    
                if 'angular' in content:
                    results['technologies'].append({
                        'name': 'Angular',
                        'confidence': 'medium'
                    })
                
        except Exception as e:
            logger.error(f"Error detecting technologies: {str(e)}")
            logger.error(traceback.format_exc())
            if callback:
                callback(0, f"Error detecting technologies: {str(e)}")
            
        return results

    def _check_security_headers(self, response, results):
        """Check for important security headers.
        
        Args:
            response: Can be either an aiohttp.ClientResponse or requests.Response object
            results: Dictionary to store the results
        """
        try:
            # Handle both aiohttp and requests response objects
            if hasattr(response, 'headers'):
                headers = {k: str(v) for k, v in response.headers.items()}
            else:
                headers = {k: str(v) for k, v in response.get('headers', {}).items()}
            
            security_headers = {}
            
            # List of important security headers to check
            important_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy',
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy'
            ]
            
            # Check each header
            for header in important_headers:
                # Case-insensitive header check
                header_value = None
                for h, v in headers.items():
                    if h.lower() == header.lower():
                        header_value = v
                        break
                
                security_headers[header] = header_value if header_value is not None else 'Not Set'
            
            # Add security headers to results
            results['security_headers'] = security_headers
            
            # Add security score if method exists
            if hasattr(self, '_calculate_security_score'):
                self._calculate_security_score(security_headers, results)
            
            return security_headers
            
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
            logger.error(traceback.format_exc())
            results['security_headers_error'] = str(e)
            return {}

    async def _check_common_vulnerabilities(self, session, base_url, results):
        """Check for common web vulnerabilities."""
        if not hasattr(self, '_vulnerability_checks'):
            self._vulnerability_checks = [
                self._check_xss_vulnerabilities,
                self._check_sql_injection,
                self._check_directory_traversal,
                self._check_csrf,
                self._check_security_headers_vulns,
                self._check_common_files_exposure
            ]
        
        if not session or session.closed:
            self.logger.error("Invalid or closed session provided to _check_common_vulnerabilities")
            results.setdefault('errors', []).append({
                'check': '_check_common_vulnerabilities',
                'error': 'Invalid or closed HTTP session'
            })
            return
        
        for check in self._vulnerability_checks:
            try:
                if session.closed:
                    self.logger.warning(f"Session closed before running {check.__name__}, reinitializing...")
                    if not await self._init_http_client():
                        raise RuntimeError("Failed to reinitialize HTTP client")
                    session = self.http_client
                
                self.logger.info(f"Running vulnerability check: {check.__name__}")
                await check(session, base_url, results)
                
            except Exception as e:
                error_msg = f"Error in {check.__name__}: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                # Add error to results but don't fail the entire scan
                results.setdefault('errors', []).append({
                    'check': check.__name__,
                    'error': error_msg,
                    'traceback': traceback.format_exc()
                })

    async def _check_xss_vulnerabilities(self, session, base_url, results):
        """Check for XSS vulnerabilities in the web application."""
        if not session or session.closed:
            self.logger.error("Invalid or closed session in _check_xss_vulnerabilities")
            return
            
        try:
            xss_payloads = [
                "<script>alert('XSS')</script>",
                '"><script>alert(1)</script>',
                '" onerror="alert(1)"',
                'javascript:alert(1)'
            ]
            
            # Parse the base URL
            try:
                parsed_url = urlparse(base_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    raise ValueError(f"Invalid base URL: {base_url}")
                    
                query_params = parse_qs(parsed_url.query) if parsed_url.query else {}
                
                # If no query parameters, use a default parameter to test
                if not query_params:
                    query_params = {'q': ['test']}
                    
                vuln_found = False
                
                for param in list(query_params.keys()):  # Create a list of keys to avoid modifying dict during iteration
                    if session.closed:
                        self.logger.warning("Session closed during XSS testing, reinitializing...")
                        if not await self._init_http_client():
                            raise RuntimeError("Failed to reinitialize HTTP client")
                        session = self.http_client
                        
                    for payload in xss_payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param] = [payload]
                            query_string = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                            test_url = parsed_url._replace(query=query_string).geturl()
                            
                            self.logger.debug(f"Testing XSS payload on {param}: {payload[:50]}...")
                            
                            async with session.get(test_url, allow_redirects=False, timeout=10) as response:
                                content = await response.text()
                                if payload in content:
                                    vuln = {
                                        'name': 'Cross-Site Scripting (XSS)',
                                        'severity': 'high',
                                        'description': f'Reflected XSS vulnerability found in parameter: {param}',
                                        'url': test_url,
                                        'payload': payload,
                                        'remediation': 'Implement proper input validation and output encoding.'
                                    }
                                    if 'vulnerabilities' not in results:
                                        results['vulnerabilities'] = []
                                    results['vulnerabilities'].append(vuln)
                                    vuln_found = True
                                    self.logger.warning(f"XSS vulnerability found in parameter: {param}")
                                    break  # No need to test other payloads for this parameter
                                    
                        except asyncio.TimeoutError:
                            self.logger.warning(f"Timeout while testing XSS payload on {param}")
                            continue
                        except Exception as e:
                            self.logger.warning(f"Error testing XSS payload on {param}: {str(e)}")
                            continue
                            
            except ValueError as ve:
                self.logger.error(f"Invalid URL format in _check_xss_vulnerabilities: {ve}")
                results.setdefault('errors', []).append({
                    'check': '_check_xss_vulnerabilities',
                    'error': f'Invalid URL format: {str(ve)}'
                })
                return
                        
        except Exception as e:
            self.logger.error(f"Error in _check_xss_vulnerabilities: {e}", exc_info=True)

    async def _check_sql_injection(self, session, base_url, results):
        """Check for potential SQL injection vulnerabilities"""
        try:
            sql_payloads = [
                "' OR '1'='1",
                '" OR "1"="1',
                "1' OR '1' = '1' -- -",
                '1" OR "1" = "1" -- -',
                "1; DROP TABLE users--"
            ]
            
            # Test in query parameters
            parsed_url = urlparse(base_url)
            query_params = parse_qs(parsed_url.query)
            
            for param in query_params:
                for payload in sql_payloads:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
                    
                    try:
                        async with session.get(test_url, timeout=15) as response:  # Increased from 5 to 15 seconds
                            content = await response.text()
                            
                            # Check for common SQL error messages
                            sql_errors = [
                                'SQL syntax',
                                'mysql_fetch',
                                'syntax error',
                                'unclosed quotation',
                                'quoted string not properly terminated',
                                'ORA-00933',
                                'SQL Server',
                                'PostgreSQL',
                                'syntax error at or near',
                                'unterminated quoted string'
                            ]
                            
                            if any(error.lower() in content.lower() for error in sql_errors):
                                results['vulnerabilities'].append({
                                    'name': 'SQL Injection',
                                    'severity': 'critical',
                                    'description': f'Potential SQL injection vulnerability found in parameter: {param}',
                                    'url': test_url,
                                    'remediation': 'Use parameterized queries or prepared statements to prevent SQL injection.'
                                })
                                break
                    
                    except asyncio.TimeoutError:
                        self.logger.warning(f"SQL injection check timed out for {test_url} (15s timeout)")
                        continue
                    except Exception as e:
                        self.logger.warning(f"Error testing SQL injection on {param}: {str(e)[:200]}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error in _check_sql_injection: {e}", exc_info=True)
            
    async def _check_directory_traversal(self, session, base_url, results):
        """Check for directory traversal vulnerabilities"""
        try:
            traversal_payloads = [
                '../../../../etc/passwd',
                '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..\\..\\..\\..\\windows\\win.ini',
                '..%5c..%5c..%5c..%5cwindows%5cwin.ini'
            ]
            
            parsed_url = urlparse(base_url)
            base_path = parsed_url.path if parsed_url.path else '/'
            
            for payload in traversal_payloads:
                test_path = base_path + payload if base_path.endswith('/') else base_path + '/' + payload
                test_url = urlunparse(parsed_url._replace(path=test_path))
                
                try:
                    async with session.get(test_url, timeout=15) as response:  # Increased from 5 to 15 seconds
                        content = await response.text()
                    
                        # Check for common sensitive file contents
                        if 'root:' in content or 'nobody:' in content or '; for 16-bit app support' in content:
                            results['vulnerabilities'].append({
                                'name': 'Directory Traversal',
                                'severity': 'high',
                                'description': f'Potential directory traversal vulnerability found at: {test_url}',
                                'url': test_url,
                                'remediation': 'Implement proper input validation and path normalization.'
                            })
                            break
                
                except asyncio.TimeoutError:
                    self.logger.warning(f"Directory traversal check timed out for {test_url} (15s timeout)")
                    continue
                except Exception as e:
                    self.logger.debug(f"Directory traversal check failed for {test_url}: {str(e)[:200]}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error in _check_directory_traversal: {e}", exc_info=True)
            
    async def _check_csrf(self, session, base_url, results):
        """Check for missing CSRF protection in forms"""
        try:
            async with session.get(base_url, timeout=15) as response:  # Increased from 5 to 15 seconds
                content = await response.text()
        
                # Look for forms
                forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
                
                for form in forms:
                    # Skip forms with method="get"
                    if 'method="get"' in form.lower() or 'method=get' in form.lower():
                        continue
                        
                    # Check for CSRF token
                    if not ('csrf_token' in form.lower() or 'csrf-token' in form.lower() or 
                           'authenticity_token' in form.lower() or 'csrfmiddlewaretoken' in form.lower()):
                        results['vulnerabilities'].append({
                            'name': 'Missing CSRF Protection',
                            'severity': 'medium',
                            'description': 'Form submission may be vulnerable to CSRF (Cross-Site Request Forgery)',
                            'url': base_url,
                            'remediation': 'Implement CSRF tokens for all state-changing operations.'
                        })
                        break
                        
        except asyncio.TimeoutError:
            self.logger.warning(f"CSRF check timed out for {base_url} (15s timeout)")
            return
        except Exception as e:
            self.logger.error(f"Error in _check_csrf for {base_url}: {str(e)[:200]}")
            return
            
    async def _check_security_headers_vulns(self, session, base_url, results):
        """Check for missing security headers"""
        try:
            async with session.get(base_url, timeout=15) as response:  # Increased from 5 to 15 seconds
                required_headers = [
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'X-XSS-Protection',
                    'Content-Security-Policy',
                    'Strict-Transport-Security',
                    'Referrer-Policy'
                ]
                
                headers = response.headers
                missing_headers = [h for h in required_headers if h not in headers]
                
                if missing_headers:
                    results['vulnerabilities'].append({
                        'name': 'Missing Security Headers',
                        'severity': 'medium',
                        'description': f'Missing recommended security headers: {", ".join(missing_headers)}',
                        'url': base_url,
                        'remediation': 'Configure the web server to include security headers.'
                    })
                    
        except asyncio.TimeoutError:
            self.logger.warning(f"Security headers check timed out for {base_url} (15s timeout)")
            return
        except Exception as e:
            self.logger.error(f"Error in _check_security_headers_vulns for {base_url}: {str(e)[:200]}")
            return
            
    def _generate_security_report(self, results):
        """Generate a security report with recommendations for missing security headers"""
        if 'security_headers' not in results:
            return ""
            
        report = []
        headers = results['security_headers']
        
        # Header recommendations
        header_recommendations = {
            'X-Content-Type-Options': {
                'recommendation': 'Set to "nosniff"',
                'severity': 'high',
                'description': 'Prevents MIME type sniffing which can lead to XSS attacks.'
            },
            'X-Frame-Options': {
                'recommendation': 'Set to "DENY" or "SAMEORIGIN"',
                'severity': 'high',
                'description': 'Prevents clickjacking attacks by controlling whether the page can be embedded in an iframe.'
            },
            'X-XSS-Protection': {
                'recommendation': 'Set to "1; mode=block"',
                'severity': 'medium',
                'description': 'Enables XSS filtering in older browsers.'
            },
            'Content-Security-Policy': {
                'recommendation': 'Implement a strong CSP policy',
                'severity': 'high',
                'description': 'Mitigates XSS, clickjacking, and other code injection attacks.'
            },
            'Strict-Transport-Security': {
                'recommendation': 'Set to "max-age=31536000; includeSubDomains; preload"',
                'severity': 'high',
                'description': 'Enforces secure (HTTPS) connections to the server.'
            },
            'Referrer-Policy': {
                'recommendation': 'Set to "no-referrer-when-downgrade" or stricter',
                'severity': 'low',
                'description': 'Controls how much referrer information is included with requests.'
            },
            'Permissions-Policy': {
                'recommendation': 'Define appropriate permissions for browser features',
                'severity': 'medium',
                'description': 'Controls which features and APIs can be used in the browser.'
            }
        }
        
        # Add missing headers to report
        for header, config in header_recommendations.items():
            if headers.get(header) == 'Not Set':
                report.append({
                    'header': header,
                    'status': 'Missing',
                    'severity': config['severity'],
                    'recommendation': config['recommendation'],
                    'description': config['description']
                })
        
        return report
        
    async def _check_common_files_exposure(self, session, base_url, results):
        """Check for exposure of common sensitive files"""
        try:
            common_files = [
                '.env',
                '.git/HEAD',
                '.git/config',
                '.git/refs/heads/master',
                '.svn/entries',
                '.DS_Store',
                'wp-config.php',
                'config/database.yml',
                'appsettings.json',
                'web.config',
                'phpinfo.php',
                'info.php',
                'test.php',
                'debug.php',
                'composer.json',
                'package.json',
                'yarn.lock',
                'package-lock.json',
                'robots.txt',
                'sitemap.xml',
                'crossdomain.xml',
                'clientaccesspolicy.xml',
                '.htaccess',
                '.htpasswd',
                'web.config',
                'appsettings.json',
                'config.json',
                'config.php',
                'database.php',
                'db.php',
                'settings.php'
            ]
            
            parsed_url = urlparse(base_url)
            base_path = parsed_url.path if parsed_url.path else '/'
            
            for file_path in common_files:
                # Handle both absolute and relative paths
                test_paths = [
                    file_path,  # Absolute path
                    base_path + file_path if base_path.endswith('/') else base_path + '/' + file_path  # Relative path
                ]
                
                for path in test_paths:
                    test_url = urlunparse(parsed_url._replace(path=path))
                    
                    try:
                        async with session.get(test_url, timeout=15) as response:  # Increased from 5 to 15 seconds
                            if response.status == 200:
                                content = await response.text()
                                # Skip empty responses
                                if not content.strip():
                                    continue
                                    
                                results['vulnerabilities'].append({
                                    'name': 'Sensitive File Exposure',
                                    'severity': 'high',
                                    'description': f'Sensitive file found: {test_url}',
                                    'url': test_url,
                                    'remediation': f'Remove or restrict access to {file_path} if not needed, or move it outside the web root.'
                                })
                                break  # No need to check other paths for this file
                                
                    except asyncio.TimeoutError:
                        self.logger.warning(f"Sensitive file check timed out for {test_url} (15s timeout)")
                        continue
                    except Exception as e:
                        self.logger.error(f"Sensitive file check failed for {test_url}: {str(e)[:200]}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error in _check_common_files_exposure: {e}", exc_info=True)

    async def _detect_technologies(self, response, result, callback=None):
        """Detect technologies used by the web application."""
        technologies = set()
        try:
            # Get response headers and content
            headers = {k.lower(): v for k, v in response.headers.items()}
            content = (await response.text()).lower()
            
            # Check server headers
            server = headers.get('server', '').lower()
            powered_by = headers.get('x-powered-by', '').lower()
            
            # Detect web server
            if 'apache' in server:
                version = server.split('apache/')[-1].split()[0] if 'apache/' in server else ''
                technologies.add(f"Apache {version}".strip())
            elif 'nginx' in server:
                version = server.split('nginx/')[-1].split()[0] if 'nginx/' in server else ''
                technologies.add(f"Nginx {version}".strip())
            elif 'iis' in server or 'microsoft' in server:
                version = server.split('iis/')[-1].split()[0] if 'iis/' in server else ''
                technologies.add(f"Microsoft IIS {version}".strip())
            
            # Detect PHP
            if 'php' in powered_by or '.php' in str(response.url) or '<?php' in content:
                php_version = ''
                if 'x-powered-by' in headers and 'php' in headers['x-powered-by']:
                    php_version = headers['x-powered-by'].split('php/')[-1].split()[0]
                technologies.add(f"PHP {php_version}".strip())
            
            # Detect WordPress
            if 'wp-content' in content or 'wp-includes' in content or 'wordpress' in content:
                technologies.add("WordPress")
                
            # Detect JavaScript frameworks
            if 'jquery' in content:
                technologies.add("jQuery")
            if 'react' in content or 'react-dom' in content:
                technologies.add("React")
            if 'vue' in content and 'vue.js' in content:
                technologies.add("Vue.js")
                
            # Detect databases
            if 'mysql' in content or 'mysqli' in content:
                technologies.add("MySQL")
            elif 'postgresql' in content or 'postgres' in content:
                technologies.add("PostgreSQL")
            # Detect frontend libraries with version detection
            if 'jquery' in content or 'jquery.js' in content:
                jq_version = 'unknown'
                jq_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', content)
                if jq_match:
                    jq_version = jq_match.group(1)
                    technologies.add(f'jQuery {jq_version}')
                else:
                    technologies.add('jQuery')
                    
            if 'bootstrap' in content or 'bootstrap.css' in content or 'bootstrap.js' in content:
                bs_version = 'unknown'
                bs_match = re.search(r'bootstrap[.-](\d+\.\d+\.\d+)', content)
                if bs_match:
                    bs_version = bs_match.group(1)
                    technologies.add(f'Bootstrap {bs_version}')
                else:
                    technologies.add('Bootstrap')
            
            # Convert set to sorted list and update results
            if technologies:
                result['technologies'] = sorted(list(technologies))
                
            # Log detected technologies
            if callback:
                detected = ', '.join(result['technologies']) if result.get('technologies') else 'None'
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: callback(80, f"Detected technologies: {detected}")
                )
                
        except Exception as e:
            logger.error(f"Error detecting technologies: {str(e)}")
            logger.debug(traceback.format_exc())
            if 'technologies' not in result:
                result['technologies'] = []
                
            if callback:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: callback(80, "Error detecting technologies")
                )
                
        return result

    async def _check_vulnerabilities(self, response, result, callback=None):
        """Check for common web vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get response text for content-based checks
            content = (await response.text()).lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for common security headers
            security_issues = [
                ('x-xss-protection', 'Missing X-XSS-Protection header', 'medium', 
                 'Add X-XSS-Protection header with value "1; mode=block"'),
                ('x-content-type-options', 'Missing X-Content-Type-Options header', 'low',
                 'Add X-Content-Type-Options header with value "nosniff"'),
                ('x-frame-options', 'Missing X-Frame-Options header', 'medium',
                 'Add X-Frame-Options header with value "DENY" or "SAMEORIGIN"'),
                ('content-security-policy', 'Missing Content-Security-Policy header', 'high',
                 'Implement a strong Content Security Policy'),
                ('strict-transport-security', 'Missing Strict-Transport-Security header', 'high',
                 'Add Strict-Transport-Security header with appropriate max-age and includeSubDomains'),
                ('server', 'Server header reveals too much information', 'low',
                 'Minimize server header information')
            ]
            
            for header, desc, severity, rec in security_issues:
                if header not in headers and header != 'server':
                    vulnerabilities.append({
                        'type': 'security_header',
                        'severity': severity,
                        'description': desc,
                        'recommendation': rec
                    })
            
            # Check for server information disclosure
            if 'server' in headers and ('apache' in headers['server'].lower() or 'nginx' in headers['server'].lower()):
                if re.search(r'\d+\.\d+(\.\d+)?', headers['server']):
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'description': f'Server version disclosure: {headers["server"]}',
                        'recommendation': 'Minimize server header information'
                    })
            
            # Check for common vulnerabilities based on technologies
            if 'wordpress' in ' '.join(result.get('technologies', [])).lower():
                # Check for WordPress version disclosure
                if re.search(r'wp-version: \d+\.\d+(\.\d+)?', content, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'description': 'WordPress version disclosure',
                        'recommendation': 'Remove version information from meta tags and headers'
                    })
            
            # Check for Moodle-specific issues
            if 'moodle' in ' '.join(result.get('technologies', [])).lower():
                if 'moodlewssetting_filter' in content or 'moodlewssetting_file' in content:
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'severity': 'medium',
                        'description': 'Moodle Web Services information disclosure',
                        'recommendation': 'Review and secure Moodle Web Services configuration'
                    })
            
            # Check for common exposed files
            if 'phpinfo' in content and 'php version' in content:
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': 'phpinfo() information disclosure',
                    'recommendation': 'Remove or secure phpinfo.php and similar files'
                })
            
            # Check for SQL errors in response
            sql_errors = [
                ('sql syntax', 'SQL syntax error', 'high'),
                ('odbc', 'ODBC error', 'high'),
                ('ora-', 'Oracle error', 'high'),
                ('microsoft jdbc', 'JDBC error', 'high'),
                ('sqlite', 'SQLite error', 'high'),
                ('pdoexception', 'PDO database error', 'high')
            ]
            
            for err, desc, severity in sql_errors:
                if err in content.lower():
                    vulnerabilities.append({
                        'type': 'database_error',
                        'severity': severity,
                        'description': f'Database error revealed: {desc}',
                        'recommendation': 'Ensure proper error handling to prevent information disclosure'
                    })
                    break
            
            # Add vulnerabilities to results
            result['vulnerabilities'] = vulnerabilities
            
            # Update callback with results
            if callback:
                count = len(vulnerabilities)
                if count > 0:
                    await asyncio.get_event_loop().run_in_executor(
                        None, 
                        lambda: callback(70, f"Found {count} potential security issues")
                    )
                else:
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: callback(70, "No obvious security issues found")
                    )
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {str(e)}")
            logger.debug(traceback.format_exc())
            
            if 'vulnerabilities' not in result:
                result['vulnerabilities'] = []
                
            if callback:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: callback(70, f"Error checking vulnerabilities: {str(e)}")
                )
            
            return result

def scan(self, url, callback=None, scan_type='web'):
    """
    Scan a website for common web vulnerabilities and information disclosure
    
    Args:
        url: URL to scan (e.g., http://example.com)
        callback: Optional callback function for progress updates
        scan_type: Type of scan ('web' for web app, 'full' for full scan including port scan)
        
    Returns:
        dict: Scan results including headers, technologies, and potential vulnerabilities
    """
    results = {
        'url': url,
        'scan_type': scan_type,
        'status': 'started',
        'start_time': datetime.utcnow().isoformat(),
        'end_time': None,
        'domain': None,
        'ip': None,
        'headers': {},
        'technologies': [],
        'vulnerabilities': [],
        'endpoints': [],
        'ports': {},
        'ssl_info': {},
        'error': None
    }
    
    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  # Remove port if present
        results['domain'] = domain
        
        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            results['ip'] = ip
            
            # If full scan, perform port scanning
            if scan_type == 'full':
                if callback:
                    callback(0, "Starting port scan...")
                port_results = self.port_scan(ip, '21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,27017,27018')
                results['ports'] = port_results.get('open_ports', {})
        
        except socket.gaierror as e:
            logger.warning(f"Could not resolve domain {domain}: {str(e)}")
            results['error'] = f"Could not resolve domain: {str(e)}"
            return results
        
        # Update URL in results with the normalized version
        results['url'] = url
        
        # Check SSL/TLS configuration
        self._check_ssl(parsed_url, results, callback)
        
        # Make the initial request
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        if callback:
            callback(10, "Making initial request...")
            
        response = session.get(
            url,
            timeout=15,
            allow_redirects=True
        )
        
        # Update final URL after redirects
        results['final_url'] = response.url
        results['redirect_chain'] = [r.url for r in response.history]
        
        # Get response details
        results['status_code'] = response.status_code
        results['headers'] = dict(response.headers)
        results['content_type'] = response.headers.get('Content-Type', '')
        results['content_length'] = len(response.content) if response.content else 0
        
        # Check for common security headers
        self._check_security_headers(response, results)
        
        # Detect technologies
        if callback:
            callback(30, "Detecting technologies...")
        self._detect_technologies(response, results, callback)
        
        # Check for common vulnerabilities
        if callback:
            callback(60, "Checking for vulnerabilities...")
        self._check_vulnerabilities(response, results, callback)
        
        # Check for common endpoints
        if callback:
            callback(80, "Checking common endpoints...")
        self._check_common_endpoints(session, url, results, callback)
        
        response.close()
        session.close()
        
        results['status'] = 'completed'
        results['end_time'] = datetime.utcnow().isoformat()
        
        return results
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Request failed: {str(e)}"
        logger.error(f"Error scanning {url}: {error_msg}")
        results['error'] = error_msg
        results['status'] = 'failed'
        return results
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.exception(f"Error scanning {url}")
        results['error'] = error_msg
        results['status'] = 'failed'
        return results
        
    def _check_ssl(self, parsed_url, results, callback=None):
        """Check SSL/TLS configuration"""
        if parsed_url.scheme != 'https':
            return
                
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate information
                    results['ssl_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_issuer': dict(x[0] for x in cert['issuer']),
                        'cert_subject': dict(x[0] for x in cert['subject']),
                        'cert_expiry': cert['notAfter'],
                        'cert_start': cert['notBefore'],
                        'cert_serial': cert.get('serialNumber', '')
                    }
                    
                    # Check for common SSL/TLS issues
                    self._check_ssl_vulnerabilities(ssock, results)
                    
        except Exception as e:
            logger.error(f"Error checking SSL: {str(e)}")
            logger.error(traceback.format_exc())
            results['ssl_error'] = str(e)

    def _check_security_headers(self, response, results):
        """Check for important security headers.
        
        Args:
            response: Can be either an aiohttp.ClientResponse or requests.Response object
            results: Dictionary to store the results
        """
        try:
            # Handle both aiohttp and requests response objects
            if hasattr(response, 'headers'):
                headers = {k: str(v) for k, v in response.headers.items()}
            else:
                headers = {k: str(v) for k, v in response.get('headers', {}).items()}
            
            security_headers = {}
            
            # List of important security headers to check
            important_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy',
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy'
            ]
            
            # Check each header
            for header in important_headers:
                # Case-insensitive header check
                header_value = None
                for h, v in headers.items():
                    if h.lower() == header.lower():
                        header_value = v
                        break
                
                security_headers[header] = header_value if header_value is not None else 'Not Set'
            
            # Add security headers to results
            results['security_headers'] = security_headers
            
            # Add security score based on headers present if method exists
            if hasattr(self, '_calculate_security_score'):
                self._calculate_security_score(security_headers, results)
                
            return security_headers
                
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
            logger.error(traceback.format_exc())
            results['security_headers_error'] = str(e)
            return {}

    def _check_common_endpoints(self, session, base_url, results, callback=None):
        """Check for common endpoints"""
        common_paths = [
            '/.env',
            '/admin',
            '/wp-admin',
            '/wp-login.php',
            '/administrator',
            '/.git/config',
            '/.svn/entries',
            '/.DS_Store',
            '/.htaccess',
            '/.htpasswd',
            '/phpinfo.php',
            '/test.php',
            '/api',
            '/api/v1',
            '/graphql',
            '/graphiql',
            '/graphql/console',
            '/graphql/playground',
            '/graphql/v1',
            '/graphql/v2',
            '/graphql/explorer',
            '/graphql/voyager',
            '/graphql/schema'
        ]
        
        endpoints = []
        base = urlparse(base_url)
        
        for path in common_paths:
            url = f"{base.scheme}://{base.netloc}{path}"
            try:
                response = session.head(url, timeout=10, allow_redirects=True)  # Increased from 5 to 10 seconds
                status = response.status_code
                endpoints.append({
                    'url': url,
                    'status': status,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': int(response.headers.get('Content-Length', 0)) 
                        if 'Content-Length' in response.headers 
                        else None
                })
                response.close()
            except Exception as e:
                logger.debug(f"Error checking {url}: {str(e)}")
                endpoints.append({
                    'url': url,
                    'status': 'error',
                    'error': str(e)
                })
        
        results['endpoints'] = endpoints
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

    def port_scan(self, target, ports=None, scan_type='tcp_connect'):
        """Perform a port scan on the specified target.
        
        Args:
            target (str): IP address or hostname to scan
            ports (list): List of ports to scan. If None, scans common ports
            scan_type (str): Type of scan ('tcp_connect', 'tcp_syn', 'udp')
            
        Returns:
            dict: Scan results with open ports and services
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5900, 8080]
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'start_time': datetime.now().isoformat(),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }
        
        try:
            self.logger.info(f"Starting port scan on {target} with {len(ports)} ports")
            
            if scan_type == 'tcp_connect':
                self._tcp_connect_scan(target, ports, results)
            elif scan_type == 'tcp_syn':
                self._tcp_syn_scan(target, ports, results)
            elif scan_type == 'udp':
                self._udp_scan(target, ports, results)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            self.logger.info(f"Port scan completed. Found {len(results['open_ports'])} open ports")
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def _tcp_connect_scan(self, target, ports, results):
        """Perform TCP connect scan"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self.COMMON_SERVICES.get(port, 'unknown')
                    results['open_ports'].append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                else:
                    results['closed_ports'].append({
                        'port': port,
                        'state': 'closed'
                    })
                    
            except socket.timeout:
                results['filtered_ports'].append({
                    'port': port,
                    'state': 'filtered'
                })
            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {str(e)}")
                results['filtered_ports'].append({
                    'port': port,
                    'state': 'filtered',
                    'error': str(e)
                })
    
    def _tcp_syn_scan(self, target, ports, results):
        """Perform TCP SYN scan using Scapy"""
        try:
            for port in ports:
                # Send SYN packet
                syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    results['filtered_ports'].append({
                        'port': port,
                        'state': 'filtered'
                    })
                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        # Send RST to close connection
                        rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                        send(rst_packet, verbose=0)
                        
                        service = self.COMMON_SERVICES.get(port, 'unknown')
                        results['open_ports'].append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                    elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                        results['closed_ports'].append({
                            'port': port,
                            'state': 'closed'
                        })
                    else:
                        results['filtered_ports'].append({
                            'port': port,
                            'state': 'filtered'
                        })
                else:
                    results['filtered_ports'].append({
                        'port': port,
                        'state': 'filtered'
                    })
                    
        except Exception as e:
            self.logger.error(f"SYN scan failed: {str(e)}")
            raise
    
    def _udp_scan(self, target, ports, results):
        """Perform UDP scan"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send empty UDP packet
                sock.sendto(b"", (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    # If we get a response, port is likely open
                    service = self.COMMON_SERVICES.get(port, 'unknown')
                    results['open_ports'].append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
                except socket.timeout:
                    # Timeout could mean open or filtered
                    results['filtered_ports'].append({
                        'port': port,
                        'state': 'open|filtered'
                    })
                except socket.error as e:
                    if e.errno == 10054:  # Port unreachable error
                        results['closed_ports'].append({
                            'port': port,
                            'state': 'closed'
                        })
                    else:
                        results['filtered_ports'].append({
                            'port': port,
                            'state': 'filtered',
                            'error': str(e)
                        })
                
                sock.close()
                
            except Exception as e:
                self.logger.debug(f"Error scanning UDP port {port}: {str(e)}")
                results['filtered_ports'].append({
                    'port': port,
                    'state': 'filtered',
                    'error': str(e)
                })
    
    def network_scan(self, network_range, scan_options=None):
        """Perform a network scan on the specified range.
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., '192.168.1.0/24')
            scan_options (dict): Scan options including ping_sweep, port_discovery, os_detection
            
        Returns:
            dict: Network scan results
        """
        if scan_options is None:
            scan_options = {
                'ping_sweep': True,
                'port_discovery': True,
                'os_detection': False
            }
        
        results = {
            'network_range': network_range,
            'start_time': datetime.now().isoformat(),
            'live_hosts': [],
            'dead_hosts': [],
            'scan_options': scan_options
        }
        
        try:
            self.logger.info(f"Starting network scan on {network_range}")
            
            # Parse network range
            network = ipaddress.ip_network(network_range, strict=False)
            hosts = list(network.hosts())
            
            # Ping sweep
            if scan_options.get('ping_sweep', True):
                self._ping_sweep(hosts, results)
            
            # Port discovery on live hosts
            if scan_options.get('port_discovery', True) and results['live_hosts']:
                self._network_port_discovery(results['live_hosts'], results)
            
            # OS detection
            if scan_options.get('os_detection', False) and results['live_hosts']:
                self._os_detection(results['live_hosts'], results)
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            self.logger.info(f"Network scan completed. Found {len(results['live_hosts'])} live hosts")
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def _ping_sweep(self, hosts, results):
        """Perform ping sweep to identify live hosts"""
        live_hosts = []
        
        # Use ThreadPoolExecutor for parallel pinging
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_host = {executor.submit(self._ping_host, str(host)): str(host) for host in hosts}
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    if future.result():
                        live_hosts.append(host)
                        results['live_hosts'].append({
                            'host': host,
                            'status': 'up',
                            'latency': None  # Could be measured if needed
                        })
                    else:
                        results['dead_hosts'].append({
                            'host': host,
                            'status': 'down'
                        })
                except Exception as e:
                    self.logger.debug(f"Error pinging {host}: {str(e)}")
                    results['dead_hosts'].append({
                        'host': host,
                        'status': 'error',
                        'error': str(e)
                    })
    
    def _ping_host(self, host):
        """Ping a single host"""
        try:
            # Use Scapy for ICMP ping
            icmp_packet = IP(dst=host)/ICMP()
            response = sr1(icmp_packet, timeout=2, verbose=0)
            return response is not None
        except Exception:
            # Fallback to system ping if Scapy fails
            try:
                result = os.system(f"ping -n 1 -w 1000 {host} > nul 2>&1")
                return result == 0
            except Exception:
                return False
    
    def _network_port_discovery(self, live_hosts, results):
        """Perform port discovery on live hosts"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
        
        for host_info in results['live_hosts']:
            host = host_info['host']
            host_info['open_ports'] = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        service = self.COMMON_SERVICES.get(port, 'unknown')
                        host_info['open_ports'].append({
                            'port': port,
                            'service': service
                        })
                except Exception:
                    pass
    
    def _os_detection(self, live_hosts, results):
        """Perform OS detection on live hosts"""
        for host_info in results['live_hosts']:
            host = host_info['host']
            try:
                # Use Scapy for OS detection (simplified)
                ttl_packet = IP(dst=host)/ICMP()
                response = sr1(ttl_packet, timeout=2, verbose=0)
                
                if response and hasattr(response, 'ttl'):
                    ttl = response.ttl
                    if ttl <= 64:
                        os_guess = "Linux/Unix"
                    elif ttl <= 128:
                        os_guess = "Windows"
                    else:
                        os_guess = "Unknown"
                    
                    host_info['os_guess'] = os_guess
                    host_info['ttl'] = ttl
                else:
                    host_info['os_guess'] = "Unknown"
                    
            except Exception as e:
                self.logger.debug(f"OS detection failed for {host}: {str(e)}")
                host_info['os_guess'] = "Unknown"
    
    async def web_scan(self, url, scan_options=None):
        """Perform a web application scan.
        
        Args:
            url (str): URL to scan
            scan_options (dict): Scan options including check_ssl, analyze_headers, check_vulnerabilities
            
        Returns:
            dict: Web scan results
        """
        if scan_options is None:
            scan_options = {
                'check_ssl': True,
                'analyze_headers': True,
                'check_vulnerabilities': True
            }
        
        # Use the existing scan_web_application method
        return await self.scan_web_application(url)
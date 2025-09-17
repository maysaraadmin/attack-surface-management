import asyncio
import sys
import os
import logging
import traceback
import time
import json
from datetime import datetime
from core.scanner import NetworkScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_scan.log')
    ]
)
logger = logging.getLogger(__name__)

def progress_callback(progress, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] Progress: {progress}% - {message}"
    logger.info(log_msg)
    print(log_msg)

def setup_logging():
    """Set up logging configuration."""
    # Create formatter
    log_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler with higher level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_formatter)
    
    # Create debug file handler with all messages
    file_handler = logging.FileHandler('web_scan_debug.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(log_formatter)
    
    # Create a separate log file for just the scan results
    result_handler = logging.FileHandler('web_scan_results.log')
    result_handler.setLevel(logging.INFO)
    result_handler.setFormatter(log_formatter)
    
    # Get root logger and set level
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    # Create a separate logger for results
    result_logger = logging.getLogger('results')
    result_logger.setLevel(logging.INFO)
    result_logger.addHandler(result_handler)
    
    # Set aiohttp and asyncio loggers to WARNING level to reduce noise
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('scapy').setLevel(logging.WARNING)
    
    return logger, result_logger

async def test_web_scan():
    # Set up logging
    logger, result_logger = setup_logging()
    
    # Log system information
    logger.info("=" * 80)
    logger.info("STARTING WEB APPLICATION SCAN")
    logger.info("=" * 80)
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Current working directory: {os.getcwd()}")
    logger.info(f"Command line: {' '.join(sys.argv)}")
    
    # Log environment variables that might affect the scan
    env_vars = [
        'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
        'PYTHONPATH', 'PATH', 'PYTHONUNBUFFERED'
    ]
    for var in env_vars:
        logger.debug(f"Environment {var}: {os.environ.get(var, 'Not set')}")
    
    print("\n=== Web Application Scanner ===\n")
    print("Starting web application scan...")
    print("Detailed logs are being saved to web_scan.log\n")
    
    if len(sys.argv) < 2:
        logger.error("No URL provided")
        print("\nError: No URL provided")
        print("Usage: python test_web_scan.py <url>")
        return 1

    url = sys.argv[1].strip('/')  # Remove trailing slash if any
    
    try:
        # Initialize scanner
        logger.info("Initializing scanner...")
        print("Initializing scanner...")
        scanner = NetworkScanner()
        logger.info("Scanner initialized successfully")
        print("Scanner initialized successfully\n")
        
        logger.info(f"Starting web application scan for {url}")
        print(f"Starting scan for: {url}")
        
        # Add timeout to prevent hanging
        timeout_seconds = 300  # 5 minutes
        logger.info(f"Starting scan with {timeout_seconds//60} minute timeout...")
        print(f"Starting scan with {timeout_seconds//60} minute timeout...\n")
        
        start_time = time.time()
        
        try:
            logger.info(f"Starting scan of {url} with timeout of {timeout_seconds} seconds")
            
            # Log scanner configuration
            logger.debug(f"Scanner configuration:")
            logger.debug(f"- Timeout: {scanner.timeout}")
            logger.debug(f"- Threads: {scanner.threads}")
            
            # Run the scan with timeout
            scan_task = asyncio.create_task(
                scanner.scan_web_application(url, callback=progress_callback)
            )
            
            # Wait for the scan to complete or timeout
            done, pending = await asyncio.wait(
                [scan_task],
                timeout=timeout_seconds,
                return_when=asyncio.ALL_COMPLETED
            )
            
            if scan_task in pending:
                # Task didn't complete in time
                scan_task.cancel()
                raise asyncio.TimeoutError(f"Scan timed out after {timeout_seconds} seconds")
                
            # Get the results from the completed task
            results = await scan_task
            
            # Log completion
            logger.info("Scan completed successfully")
            
            scan_duration = time.time() - start_time
            logger.info(f"Scan completed successfully in {scan_duration:.2f} seconds")
            print(f"\n=== Scan Completed Successfully in {scan_duration:.2f} seconds ===\n")
        except asyncio.TimeoutError as e:
            error_msg = f"Scan timed out after {timeout_seconds} seconds"
            logger.error(error_msg, exc_info=True)
            result_logger.error(f"SCAN FAILED: {error_msg}")
            print(f"\nError: {error_msg}")
            return 1
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            logger.error(error_msg, exc_info=True)
            result_logger.error(f"SCAN FAILED: {error_msg}")
            print(f"\nError: {error_msg}")
            print(f"Check web_scan_debug.log for details")
            return 1
            return
        
        # Print summary
        print("\n" + "="*70)
        print("SCAN SUMMARY".center(70))
        print("="*70)
        
        # Basic info
        print(f"\n{'URL:':<15} {results.get('url', 'N/A')}")
        print(f"{'Status:':<15} {results.get('status', 'unknown').upper()}")
        print(f"{'Status Code:':<15} {results.get('status_code', 'N/A')}")
        print(f"{'Start Time:':<15} {results.get('start_time', 'N/A')}")
        print(f"{'End Time:':<15} {results.get('end_time', 'N/A')}")
        print(f"{'Duration:':<15} {results.get('scan_duration', 0):.2f} seconds")
        
        # Print redirects if any
        if 'redirects' in results and results['redirects']:
            print("\nRedirects:")
            for i, redirect in enumerate(results['redirects'], 1):
                print(f"  {i}. {redirect}")
            print(f"Final URL: {results.get('final_url', 'N/A')}")
            
        # Print error if any
        if 'error' in results and results['error']:
            print(f"\nError: {results['error']}")
        
        if 'error' in results:
            logger.error(f"Scan error: {results['error']}")
            print(f"\nError: {results['error']}")
            return
        
        # Print technologies found
        if results.get('technologies'):
            print("\n" + "="*50)
            print("TECHNOLOGIES DETECTED")
            print("="*50)
            tech_list = results['technologies']
            if isinstance(tech_list, list) and len(tech_list) > 0:
                if isinstance(tech_list[0], dict):
                    # Old format: list of dicts with name/version/confidence
                    for i, tech in enumerate(tech_list, 1):
                        name = tech.get('name', 'Unknown')
                        version = f" ({tech.get('version')})" if tech.get('version') else ""
                        confidence = f" [confidence: {tech.get('confidence', 'unknown')}]" if 'confidence' in tech else ""
                        print(f"{i}. {name}{version}{confidence}")
                else:
                    # New format: list of strings
                    for i, tech in enumerate(tech_list, 1):
                        print(f"{i}. {tech}")
            else:
                print("No technologies detected.")
        else:
            print("\nNo technologies detected.")
            
        # Log the raw results for debugging
        logger.info("Raw results: %s", results)
        
        # Print security headers
        if results.get('security_headers'):
            print("\n" + "="*50)
            print("SECURITY HEADERS")
            print("="*50)
            headers = results['security_headers']
            
            # List of important security headers to check
            important_headers = [
                'x-frame-options',
                'content-security-policy',
                'x-content-type-options',
                'strict-transport-security',
                'x-xss-protection',
                'referrer-policy',
                'permissions-policy',
                'cross-origin-opener-policy',
                'cross-origin-embedder-policy',
                'cross-origin-resource-policy'
            ]
            
            found_headers = 0
            for header in important_headers:
                if header in headers:
                    print(f"✓ {header.upper()}: {headers[header]}")
                    found_headers += 1
                else:
                    print(f"✗ {header.upper()}: Missing")
                    
            # Print any additional headers that weren't in our important list
            additional_headers = set(headers.keys()) - set(important_headers)
            if additional_headers:
                print("\nAdditional Headers:")
                for header in additional_headers:
                    print(f"  {header}: {headers[header]}")
        
        # Print vulnerabilities found
        if results.get('vulnerabilities'):
            print("\n" + "="*50)
            print("SECURITY VULNERABILITIES")
            print("="*50)
            
            # Group vulnerabilities by severity
            vulns_by_severity = {}
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                if severity not in vulns_by_severity:
                    vulns_by_severity[severity] = []
                vulns_by_severity[severity].append(vuln)
            
            # Print in order of severity
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            for severity in severity_order:
                if severity in vulns_by_severity:
                    print(f"\n{severity.upper()} severity findings:")
                    for i, vuln in enumerate(vulns_by_severity[severity], 1):
                        print(f"\n{i}. {vuln.get('name', 'Unknown')}")
                        print(f"   {'-' * (len(vuln.get('name', 'Unknown')) + 3)}")
                        print(f"   Description: {vuln.get('description', 'No description')}")
                        print(f"   URL:         {vuln.get('url', 'N/A')}")
                        print(f"   Severity:    {vuln.get('severity', 'unknown').upper()}")
                        print(f"   Remediation: {vuln.get('remediation', 'No remediation provided.')}")
        else:
            print("\nNo security vulnerabilities found.")
            
        # Print statistics
        print("\n" + "="*50)
        print("SCAN STATISTICS")
        print("="*50)
        print(f"Total Requests:   {results.get('request_count', 0)}")
        print(f"Technologies:     {len(results.get('technologies', []))}")
        print(f"Vulnerabilities:  {len(results.get('vulnerabilities', []))}")
        print(f"Directories:      {len(results.get('directories', []))}")
        
        # Print directories found
        if results.get('directories'):
            print("\n=== Discovered Directories/Files ===")
            for i, item in enumerate(results['directories'], 1):
                print(f"{i}. {item['path']} (Status: {item.get('status_code', 'N/A')}, Type: {item.get('type', 'unknown')}, Size: {item.get('size', 'N/A')} bytes)")
    
    except asyncio.TimeoutError:
        error_msg = "Scan timed out after 5 minutes"
        logger.error(error_msg)
        print(f"\nError: {error_msg}")
    except Exception as e:
        error_msg = f"An error occurred during scanning: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        print(f"\nError: {error_msg}")
        print(f"\nDetailed error: {traceback.format_exc()}")
        
        # Try to close the scanner's HTTP client if it exists
        try:
            if hasattr(scanner, 'http_client') and scanner.http_client and not scanner.http_client.closed:
                await scanner.http_client.close()
                logger.info("Closed HTTP client session")
        except Exception as cleanup_error:
            logger.error(f"Error during cleanup: {cleanup_error}")
            
        return 1  # Return error status

def print_banner():
    """Print the application banner."""
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║             Web Application Scanner              ║
    ║            Vulnerability Assessment Tool         ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)

if __name__ == "__main__":
    try:
        print_banner()
        asyncio.run(test_web_scan())
    except KeyboardInterrupt:
        print("\n\nScan was interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nAn unexpected error occurred: {e}")
        logging.exception("Unexpected error in main:")
        sys.exit(1)

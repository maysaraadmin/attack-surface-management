from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add security headers for testing
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=()')
        super().end_headers()

if __name__ == '__main__':
    # Create a test directory with some files
    os.makedirs('test_server', exist_ok=True)
    with open('test_server/index.html', 'w') as f:
        f.write('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Server</title>
            <meta name="generator" content="WordPress 6.0" />
        </head>
        <body>
            <h1>Test Server</h1>
            <p>This is a test server for security scanning.</p>
            <a href="/admin">Admin Panel</a>
        </body>
        </html>
        ''')
    
    # Create a robots.txt file
    with open('test_server/robots.txt', 'w') as f:
        f.write('User-agent: *\nDisallow: /admin/\n')
    
    # Change to the test directory and start the server
    os.chdir('test_server')
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, CORSRequestHandler)
    print("Starting test server at http://localhost:8000")
    httpd.serve_forever()

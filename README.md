# QR Code C2 Framework

A covert command-and-control framework that uses QR codes embedded in a legitimate-looking web page to transfer commands and exfiltrate data. Designed for authorized red team engagements and penetration testing.

## How It Works

```
┌──────────┐   QR command embedded in HTML   ┌──────────────┐
│  C2      │ ─────────────────────────────▶   │  Web Page     │
│  Server  │                                  │  (web.html)   │
│ (main.py)│   ◀──── QR-encoded results ───── │               │
└──────────┘                                  └───────┬───────┘
                                                      │
                                              HTTP GET │ polls page
                                                      │
                                              ┌───────┴───────┐
                                              │   Implant      │
                                              │  (demo.py)     │
                                              └────────────────┘
```

1. **Server** (`main.py`) encodes commands into QR codes and embeds them in `web.html` — a fake IT services company page.
2. **Implant** (`demo.py`) periodically fetches `web.html`, extracts the QR code, decodes it, executes the command, and sends results back as QR-encoded PNG images.
3. All C2 traffic looks like normal web browsing to a corporate site with image uploads.

## Features

- **QR-based data channel** — commands and results are encoded as QR codes, evading text-based DLP/IDS inspection
- **Legitimate cover page** — `web.html` renders as a real IT services website
- **Sleep & jitter** — configurable poll interval with randomization to avoid detection patterns
- **Built-in implant commands** — `sleep`, `jitter`, `info`, `exit`/`kill`
- **Chunked output** — large command outputs are split across multiple QR codes
- **Multiple exfil methods** — POST (raw), POST (multipart), GET (base64 query param) with automatic fallback
- **HTTPS support** — direct TLS or Apache reverse proxy mode
- **Domain support** — use a domain name instead of raw IP for the callback
- **Persistent sessions** — implant uses `requests.Session` with browser-like headers
- **Config file** — `config.json` for persistent server settings

## Requirements

- Python 3.8+
- `zbar` shared library (required by `pyzbar`)
  - **Windows:** install from [zbar-windows](https://github.com/nicedayzhu/zbar-win64) or bundle the DLL
  - **Linux:** `sudo apt install libzbar0`
  - **macOS:** `brew install zbar`

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# 1. Start the C2 server
python main.py

# 2. From the menu, build the implant
#    Choose [2] Build victim implant
#    Enter your domain or IP when prompted

# 3. Transfer demo.py to the target and run it
python demo.py

# 4. Back on the server, choose [1] to enter command mode
#    Type shell commands — output appears automatically
```

## Server Menu

| Option | Description |
|--------|-------------|
| `[1]` Start C2 server | Enter interactive command mode |
| `[2]` Build victim implant | Generate `demo.py` with your IP/domain baked in |
| `[3]` Show configuration | Display current settings and last checkin |
| `[4]` Configure server | Change port, domain, HTTPS, Apache proxy mode |
| `[5]` Command history | View previously sent commands |

## Implant Built-in Commands

| Command | Description |
|---------|-------------|
| `sleep <seconds>` | Change poll interval (e.g. `sleep 30`) |
| `sleep` | Show current poll interval |
| `jitter <0-100>` | Set jitter percentage (e.g. `jitter 40`) |
| `jitter` | Show current jitter |
| `info` | Get target OS, hostname, arch, user |
| `exit` / `kill` | Terminate the implant |
| `help` | Show command help |
| Anything else | Executed as a shell command on the target |

## Configuration

Settings are stored in `config.json` and can be changed from the menu (`[4]`) or edited directly:

```json
{
    "port": 8080,
    "use_https": false,
    "use_apache_proxy": false,
    "domain": "c2.example.com",
    "ssl_cert_file": "cert.pem",
    "ssl_key_file": "key.pem"
}
```

### HTTPS Options

**Direct TLS** — the Python server terminates TLS:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

Then enable via menu `[4] → [1]`.

**Apache Reverse Proxy** — Apache handles TLS on port 443 and proxies to the Python server on localhost:

```apache
<VirtualHost *:443>
    ServerName c2.example.com
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/c2.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/c2.example.com/privkey.pem
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

Enable via menu `[4] → [3]`.

## File Structure

```
.
├── main.py            # C2 server — menu, QR encoding, HTTP handler
├── qr_template.py     # Implant template (placeholders replaced at build)
├── web.html           # Cover page with embedded QR code
├── requirements.txt   # Python dependencies
├── config.json        # Server configuration (auto-created)
├── demo.py            # Generated implant (after build)
├── cert.pem           # TLS cert (optional)
├── key.pem            # TLS key (optional)
└── server_files/      # QR command PNGs and received results
    └── processed/     # Results after decoding
```

## Disclaimer

This tool is intended **only** for authorized security testing, red team engagements, and educational purposes. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse.

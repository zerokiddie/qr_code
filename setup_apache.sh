#!/bin/bash
# Apache Reverse Proxy + Let's Encrypt SSL Setup Script
# For QR Code C2 Framework
# Tested on: Ubuntu 20.04/22.04, Debian 11/12

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BACKEND_PORT=8080

print_banner() {
    echo -e "${GREEN}"
    echo "=================================="
    echo " Apache + Let's Encrypt Setup"
    echo " QR Code C2 Reverse Proxy"
    echo "=================================="
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Run this script as root (sudo)${NC}"
        exit 1
    fi
}

get_config() {
    read -rp "[>] Enter your domain name (e.g. c2.example.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}[!] Domain cannot be empty${NC}"
        exit 1
    fi

    read -rp "[>] Enter your email for Let's Encrypt (e.g. admin@example.com): " EMAIL
    if [ -z "$EMAIL" ]; then
        echo -e "${RED}[!] Email cannot be empty${NC}"
        exit 1
    fi

    read -rp "[>] Backend port (default: 8080): " INPUT_PORT
    if [ -n "$INPUT_PORT" ]; then
        BACKEND_PORT="$INPUT_PORT"
    fi

    echo ""
    echo -e "${YELLOW}[*] Domain:       ${DOMAIN}${NC}"
    echo -e "${YELLOW}[*] Email:        ${EMAIL}${NC}"
    echo -e "${YELLOW}[*] Backend port: ${BACKEND_PORT}${NC}"
    echo ""
    read -rp "[>] Continue? (y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "[!] Aborted."
        exit 0
    fi
}

install_packages() {
    echo -e "${GREEN}[+] Updating packages...${NC}"
    apt-get update -y

    echo -e "${GREEN}[+] Installing Apache and Certbot...${NC}"
    apt-get install -y apache2 certbot python3-certbot-apache

    echo -e "${GREEN}[+] Enabling Apache modules...${NC}"
    a2enmod proxy proxy_http ssl rewrite headers
}

configure_apache_http() {
    echo -e "${GREEN}[+] Creating initial HTTP vhost for ${DOMAIN}...${NC}"

    cat > /etc/apache2/sites-available/${DOMAIN}.conf <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}

    # Certbot will use this for the HTTP-01 challenge
    DocumentRoot /var/www/html

    # After SSL is set up, all HTTP traffic redirects to HTTPS
    # (certbot adds the redirect automatically)

    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
</VirtualHost>
EOF

    a2ensite ${DOMAIN}.conf
    a2dissite 000-default.conf 2>/dev/null || true
    systemctl reload apache2
}

obtain_ssl() {
    echo -e "${GREEN}[+] Obtaining Let's Encrypt certificate...${NC}"
    echo -e "${YELLOW}[*] Make sure DNS for ${DOMAIN} points to this server's public IP${NC}"
    echo -e "${YELLOW}[*] Make sure port 80 and 443 are open in your firewall${NC}"
    echo ""

    certbot --apache \
        -d "${DOMAIN}" \
        --non-interactive \
        --agree-tos \
        --email "${EMAIL}" \
        --redirect
}

configure_apache_ssl() {
    echo -e "${GREEN}[+] Configuring SSL vhost with reverse proxy...${NC}"

    # Certbot creates an SSL conf — we'll overwrite it with our proxy config
    SSL_CONF="/etc/apache2/sites-available/${DOMAIN}-le-ssl.conf"

    cat > "$SSL_CONF" <<EOF
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName ${DOMAIN}

    # SSL managed by Certbot
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # Reverse proxy to C2 backend
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:${BACKEND_PORT}/
    ProxyPassReverse / http://127.0.0.1:${BACKEND_PORT}/

    # Allow large POST bodies (QR image uploads)
    LimitRequestBody 10485760

    # Logging
    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_ssl_access.log combined
</VirtualHost>
</IfModule>
EOF

    # Make sure the SSL site is enabled
    a2ensite ${DOMAIN}-le-ssl.conf 2>/dev/null || true
    apache2ctl configtest
    systemctl reload apache2
}

setup_auto_renew() {
    echo -e "${GREEN}[+] Setting up auto-renewal cron...${NC}"
    # Certbot installs a systemd timer or cron by default, but let's make sure
    if systemctl list-timers | grep -q certbot; then
        echo -e "${GREEN}[+] Certbot systemd timer already active${NC}"
    else
        echo "0 3 * * * root certbot renew --quiet --post-hook 'systemctl reload apache2'" \
            > /etc/cron.d/certbot-renew
        echo -e "${GREEN}[+] Cron job added for certificate renewal${NC}"
    fi
}

update_c2_config() {
    # Update config.json if it exists in the script's directory
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    CONFIG_FILE="${SCRIPT_DIR}/config.json"

    echo -e "${GREEN}[+] Updating C2 config.json...${NC}"
    cat > "$CONFIG_FILE" <<EOF
{
    "port": ${BACKEND_PORT},
    "use_https": false,
    "use_apache_proxy": true,
    "domain": "${DOMAIN}",
    "ssl_cert_file": "cert.pem",
    "ssl_key_file": "key.pem"
}
EOF
    echo -e "${GREEN}[+] config.json updated (apache proxy mode enabled)${NC}"
}

configure_firewall() {
    if command -v ufw &>/dev/null; then
        echo -e "${GREEN}[+] Configuring UFW firewall...${NC}"
        ufw allow 80/tcp
        ufw allow 443/tcp
        # Block direct access to the backend port from outside
        ufw deny "${BACKEND_PORT}/tcp"
        echo -e "${GREEN}[+] Firewall: 80/443 open, ${BACKEND_PORT} blocked from external${NC}"
    else
        echo -e "${YELLOW}[*] UFW not found — manually ensure ports 80/443 are open and ${BACKEND_PORT} is blocked externally${NC}"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}=================================="
    echo " Setup Complete"
    echo "==================================${NC}"
    echo ""
    echo -e "  Domain:        https://${DOMAIN}"
    echo -e "  Backend:       http://127.0.0.1:${BACKEND_PORT}"
    echo -e "  SSL Cert:      /etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    echo -e "  SSL Key:       /etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    echo -e "  Apache logs:   /var/log/apache2/${DOMAIN}_ssl_*.log"
    echo ""
    echo -e "${YELLOW}[*] Next steps:${NC}"
    echo "  1. Start the C2 server:  python3 main.py"
    echo "  2. Build the implant:    choose [2] from the menu"
    echo "  3. The implant will connect to https://${DOMAIN}"
    echo ""
    echo -e "${YELLOW}[*] Useful commands:${NC}"
    echo "  systemctl status apache2        # check Apache"
    echo "  certbot certificates             # check SSL certs"
    echo "  certbot renew --dry-run          # test renewal"
    echo "  tail -f /var/log/apache2/${DOMAIN}_ssl_access.log"
    echo ""
}

# --- Main ---
print_banner
check_root
get_config
install_packages
configure_apache_http
obtain_ssl
configure_apache_ssl
setup_auto_renew
update_c2_config
configure_firewall
print_summary

#!/bin/bash


# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# URL vom Benutzer abfragen
echo -e "${CYAN}=== Schwachstellen-Scanner ===${NC}"
read -p "Gib die zu testende URL ein (z.B. http://example.com): " url

# Trailing slash entfernen
base_url="${url%/}"

# ==================== SQL Injection Tests ====================
test_sql_injection() {
    echo -e "\n${YELLOW}[*] Teste SQL Injection...${NC}"
    
    sql_payloads=(
        "' OR '1'='1"
        "' OR 1=1--"
        "admin'--"
        "' UNION SELECT NULL--"
        "1' AND '1'='1"
    )
    
    for payload in "${sql_payloads[@]}"; do
        # URL-Encoding für den Payload
        encoded=$(echo "$payload" | jq -sRr @uri 2>/dev/null || python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
        
        test_url="${base_url}/?id=${encoded}"
        
        # Request mit curl
        response=$(curl -s -L "$test_url" 2>/dev/null)
        
        # Suche nach SQL-Fehler-Keywords
        if echo "$response" | grep -iqE "SQL|syntax|mysql|database|warning|error in your SQL"; then
            echo -e "${RED}[!] WARNUNG: Mögliche SQL Injection gefunden mit Payload: $payload${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] SQL Injection Test abgeschlossen${NC}"
}

# ==================== XSS Tests ====================
test_xss() {
    echo -e "\n${YELLOW}[*] Teste Cross-Site Scripting (XSS)...${NC}"
    
    xss_payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg/onload=alert('XSS')>"
        "javascript:alert('XSS')"
    )
    
    for payload in "${xss_payloads[@]}"; do
        # URL-Encoding
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
        
        test_url="${base_url}/?search=${encoded}"
        response=$(curl -s -L "$test_url" 2>/dev/null)
        
        # Prüfe ob Payload im Response reflektiert wird
        if echo "$response" | grep -qF "$payload"; then
            echo -e "${RED}[!] WARNUNG: Mögliches XSS gefunden - Payload wird reflektiert${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] XSS Test abgeschlossen${NC}"
}

# ==================== Directory Enumeration ====================
test_directories() {
    echo -e "\n${YELLOW}[*] Suche versteckte Verzeichnisse...${NC}"
    
    directories=(
        "admin"
        "login"
        "dashboard"
        "backup"
        "config"
        "api"
        "uploads"
        "wp-admin"
        "phpmyadmin"
        "test"
        "dev"
        ".git"
        ".env"
        "robots.txt"
        "sitemap.xml"
    )
    
    found_count=0
    
    for dir in "${directories[@]}"; do
        test_url="${base_url}/${dir}"
        
        # HTTP Status Code abrufen
        status=$(curl -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null)
        
        if [ "$status" -eq 200 ]; then
            echo -e "${GREEN}[+] Gefunden: $test_url (Status: $status)${NC}"
            ((found_count++))
        elif [ "$status" -eq 403 ]; then
            echo -e "${YELLOW}[!] Zugriff verweigert (403): $test_url${NC}"
        fi
    done
    
    if [ $found_count -eq 0 ]; then
        echo -e "${GRAY}[-] Keine interessanten Verzeichnisse gefunden${NC}"
    fi
}

# ==================== Login Brute-Force Check ====================
test_login_bruteforce() {
    echo -e "\n${YELLOW}[*] Teste häufige Login-Kombinationen...${NC}"
    echo -e "${GRAY}[i] Hinweis: Dies ist nur ein einfacher Test mit wenigen Versuchen${NC}"
    
    login_pages=(
        "/login"
        "/admin"
        "/signin"
        "/auth"
        "/wp-login.php"
    )
    
    for page in "${login_pages[@]}"; do
        test_url="${base_url}${page}"
        status=$(curl -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null)
        
        if [ "$status" -eq 200 ]; then
            echo -e "${GREEN}[+] Login-Seite gefunden: $test_url${NC}"
            echo -e "${RED}[!] WARNUNG: Login-Seite könnte anfällig für Brute-Force sein${NC}"
        fi
    done
    
    echo -e "${GREEN}[✓] Login-Test abgeschlossen${NC}"
}

# ==================== Security Headers Check ====================
test_security_headers() {
    echo -e "\n${YELLOW}[*] Prüfe Security Headers...${NC}"
    
    # Headers mit curl abrufen
    headers=$(curl -sI "$base_url" 2>/dev/null)
    
    # Array von Security Headers
    declare -A sec_headers=(
        ["X-Frame-Options"]="Schutz vor Clickjacking"
        ["X-Content-Type-Options"]="MIME-Type Sniffing Schutz"
        ["Strict-Transport-Security"]="HTTPS Erzwingung"
        ["Content-Security-Policy"]="XSS Schutz"
        ["X-XSS-Protection"]="Browser XSS Filter"
    )
    
    for header in "${!sec_headers[@]}"; do
        if echo "$headers" | grep -qi "^$header:"; then
            echo -e "${GREEN}[✓] $header gesetzt${NC}"
        else
            echo -e "${RED}[!] $header fehlt - ${sec_headers[$header]}${NC}"
        fi
    done
}

# ==================== Robots.txt Check ====================
test_robots() {
    echo -e "\n${YELLOW}[*] Prüfe robots.txt...${NC}"
    
    robots_url="${base_url}/robots.txt"
    status=$(curl -s -o /dev/null -w "%{http_code}" "$robots_url" 2>/dev/null)
    
    if [ "$status" -eq 200 ]; then
        echo -e "${GREEN}[+] robots.txt gefunden${NC}"
        content=$(curl -s "$robots_url" 2>/dev/null)
        
        # Zeige interessante Disallow-Einträge
        echo -e "${CYAN}Interessante Einträge:${NC}"
        echo "$content" | grep -i "Disallow:" | head -10
    else
        echo -e "${GRAY}[-] Keine robots.txt gefunden${NC}"
    fi
}

# ==================== SSL/TLS Check ====================
test_ssl() {
    echo -e "\n${YELLOW}[*] Prüfe SSL/TLS...${NC}"
    
    # Prüfe ob HTTPS verwendet wird
    if [[ $base_url == https://* ]]; then
        echo -e "${GREEN}[✓] Website nutzt HTTPS${NC}"
        
        # SSL-Details mit openssl abrufen (wenn verfügbar)
        if command -v openssl &> /dev/null; then
            domain=$(echo "$base_url" | sed -e 's|^https\?://||' -e 's|/.*$||')
            ssl_info=$(echo | openssl s_client -connect "${domain}:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
            
            if [ -n "$ssl_info" ]; then
                echo -e "${CYAN}Zertifikat-Info:${NC}"
                echo "$ssl_info"
            fi
        fi
    else
        echo -e "${RED}[!] WARNUNG: Website nutzt kein HTTPS!${NC}"
    fi
}

# ==================== Haupt-Menü ====================
echo -e "\n${CYAN}Wähle die Tests aus:${NC}"
echo "1 - SQL Injection"
echo "2 - Cross-Site Scripting (XSS)"
echo "3 - Directory Enumeration"
echo "4 - Login Brute-Force Check"
echo "5 - Security Headers"
echo "6 - Robots.txt Check"
echo "7 - SSL/TLS Check"
echo "8 - Alle Tests ausführen"

read -p $'\nDeine Wahl (1-8): ' choice

case $choice in
    1)
        test_sql_injection
        ;;
    2)
        test_xss
        ;;
    3)
        test_directories
        ;;
    4)
        test_login_bruteforce
        ;;
    5)
        test_security_headers
        ;;
    6)
        test_robots
        ;;
    7)
        test_ssl
        ;;
    8)
        test_sql_injection
        test_xss
        test_directories
        test_login_bruteforce
        test_security_headers
        test_robots
        test_ssl
        ;;
    *)
        echo -e "${RED}Ungültige Auswahl!${NC}"
        exit 1
        ;;
esac

echo -e "\n${CYAN}=== Scan abgeschlossen ===${NC}"
echo -e "\n${YELLOW}WICHTIG: Dies ist nur ein Basis-Scanner. Für professionelle Tests nutze:${NC}"
echo "- OWASP ZAP, Burp Suite (Web-Schwachstellen)"
echo "- SQLMap (SQL Injection)"
echo "- Gobuster, Dirb (Directory Brute-Force)"
echo "- Nmap (Port-Scanning)"
echo "- Nikto (Web-Server-Scanner)"

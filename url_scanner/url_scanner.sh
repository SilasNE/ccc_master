#!/bin/bash

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Globale Variablen für Empfehlungen
sqlVulnFound=false
xssVulnFound=false
directoriesFound=false
loginFound=false
missingHeaders=false
sslIssue=false

echo -e "${CYAN}=== Schwachstellen-Scanner ===${NC}"
read -p "Gib die zu testende URL ein (z.B. http://example.com): " url

# Basis-URL bereinigen (trailing slash entfernen)
baseUrl="${url%/}"

# ==================== SQL Injection Tests ====================
test_sql_injection() {
    local targetUrl="$1"
    
    echo -e "\n${YELLOW}[*] Teste SQL Injection...${NC}"
    
    local sqlPayloads=(
        "' OR '1'='1"
        "' OR 1=1--"
        "admin'--"
        "' UNION SELECT NULL--"
        "1' AND '1'='1"
    )
    
    for payload in "${sqlPayloads[@]}"; do
        encodedPayload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
        testUrl="${targetUrl}/?id=${encodedPayload}"
        
        response=$(curl -s -m 5 "$testUrl" 2>/dev/null)
        
        if echo "$response" | grep -iE "SQL|syntax|mysql|database|warning" >/dev/null; then
            echo -e "${RED}[!] WARNUNG: Mögliche SQL Injection gefunden mit Payload: $payload${NC}"
            sqlVulnFound=true
        fi
    done
    
    echo -e "${GREEN}[✓] SQL Injection Test abgeschlossen${NC}"
}

# ==================== XSS Tests ====================
test_xss() {
    local targetUrl="$1"
    
    echo -e "\n${YELLOW}[*] Teste Cross-Site Scripting (XSS)...${NC}"
    
    local xssPayloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg/onload=alert('XSS')>"
        "javascript:alert('XSS')"
    )
    
    for payload in "${xssPayloads[@]}"; do
        encodedPayload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
        testUrl="${targetUrl}/?search=${encodedPayload}"
        
        response=$(curl -s -m 5 "$testUrl" 2>/dev/null)
        
        if echo "$response" | grep -F "$payload" >/dev/null; then
            echo -e "${RED}[!] WARNUNG: Mögliches XSS gefunden - Payload wird reflektiert${NC}"
            xssVulnFound=true
        fi
    done
    
    echo -e "${GREEN}[✓] XSS Test abgeschlossen${NC}"
}

# ==================== Directory Enumeration ====================
test_directories() {
    local targetUrl="$1"
    
    echo -e "\n${YELLOW}[*] Suche versteckte Verzeichnisse...${NC}"
    
    local directories=(
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
    )
    
    local foundCount=0
    
    for dir in "${directories[@]}"; do
        testUrl="${targetUrl}/${dir}"
        statusCode=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "$testUrl" 2>/dev/null)
        
        if [ "$statusCode" = "200" ]; then
            echo -e "${GREEN}[+] Gefunden: $testUrl (Status: $statusCode)${NC}"
            ((foundCount++))
            directoriesFound=true
        elif [ "$statusCode" = "403" ]; then
            echo -e "${YELLOW}[!] Zugriff verweigert (403): $testUrl${NC}"
        fi
    done
    
    if [ $foundCount -eq 0 ]; then
        echo -e "${GRAY}[-] Keine interessanten Verzeichnisse gefunden${NC}"
    fi
}

# ==================== Brute Force Login (Basis) ====================
test_login_bruteforce() {
    local targetUrl="$1"
    
    echo -e "\n${YELLOW}[*] Teste häufige Login-Kombinationen...${NC}"
    echo -e "${GRAY}[i] Hinweis: Dies ist nur ein einfacher Test mit wenigen Versuchen${NC}"
    
    local loginPages=("/login" "/admin" "/signin" "/auth")
    
    for page in "${loginPages[@]}"; do
        testUrl="${targetUrl}${page}"
        statusCode=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "$testUrl" 2>/dev/null)
        
        if [ "$statusCode" = "200" ]; then
            echo -e "${GREEN}[+] Login-Seite gefunden: $testUrl${NC}"
            echo -e "${RED}[!] WARNUNG: Login-Seite ohne Rate-Limiting könnte anfällig für Brute-Force sein${NC}"
            loginFound=true
        fi
    done
    
    echo -e "${GREEN}[✓] Login-Test abgeschlossen${NC}"
}

# ==================== Security Headers Check ====================
test_security_headers() {
    local targetUrl="$1"
    
    echo -e "\n${YELLOW}[*] Prüfe Security Headers...${NC}"
    
    # Headers abrufen
    headers=$(curl -s -I -m 5 "$targetUrl" 2>/dev/null)
    
    if [ -z "$headers" ]; then
        echo -e "${RED}[!] Fehler beim Abrufen der Headers${NC}"
        return
    fi
    
    # Prüfe einzelne Security Headers
    if echo "$headers" | grep -i "X-Frame-Options:" >/dev/null; then
        echo -e "${GREEN}[✓] X-Frame-Options gesetzt${NC}"
    else
        echo -e "${RED}[!] X-Frame-Options fehlt - Schutz vor Clickjacking${NC}"
        missingHeaders=true
    fi
    
    if echo "$headers" | grep -i "X-Content-Type-Options:" >/dev/null; then
        echo -e "${GREEN}[✓] X-Content-Type-Options gesetzt${NC}"
    else
        echo -e "${RED}[!] X-Content-Type-Options fehlt - MIME-Type Sniffing Schutz${NC}"
        missingHeaders=true
    fi
    
    if echo "$headers" | grep -i "Strict-Transport-Security:" >/dev/null; then
        echo -e "${GREEN}[✓] Strict-Transport-Security gesetzt${NC}"
    else
        echo -e "${RED}[!] Strict-Transport-Security fehlt - HTTPS Erzwingung${NC}"
        missingHeaders=true
    fi
    
    if echo "$headers" | grep -i "Content-Security-Policy:" >/dev/null; then
        echo -e "${GREEN}[✓] Content-Security-Policy gesetzt${NC}"
    else
        echo -e "${RED}[!] Content-Security-Policy fehlt - XSS Schutz${NC}"
        missingHeaders=true
    fi
    
    if echo "$headers" | grep -i "X-XSS-Protection:" >/dev/null; then
        echo -e "${GREEN}[✓] X-XSS-Protection gesetzt${NC}"
    else
        echo -e "${RED}[!] X-XSS-Protection fehlt - Browser XSS Filter${NC}"
        missingHeaders=true
    fi
}

# ==================== Empfehlungssystem ====================
generate_recommendations() {
    local targetUrl="$1"
    
    echo -e "\n${CYAN}=== ANALYSE ABGESCHLOSSEN ===${NC}"
    echo -e "\n${CYAN}=== EMPFOHLENE NÄCHSTE SCHRITTE ===${NC}\n"
    
    local recommendations=0
    
    # SQL Injection Empfehlung
    if [ "$sqlVulnFound" = true ]; then
        echo -e "${RED}[!] SQL Injection Schwachstellen gefunden!${NC}"
        echo -e "${YELLOW}Empfohlene Tools:${NC}"
        echo "   1. SQLMap - Automatisierte SQL Injection Exploitation"
        echo "      Befehl: sqlmap -u \"${targetUrl}/?id=1\" --batch --banner"
        echo ""
        ((recommendations++))
    fi
    
    # XSS Empfehlung
    if [ "$xssVulnFound" = true ]; then
        echo -e "${RED}[!] XSS Schwachstellen gefunden!${NC}"
        echo -e "${YELLOW}Empfohlene Tools:${NC}"
        echo "   1. XSStrike - Advanced XSS Detection"
        echo "      Befehl: python xsstrike.py -u \"${targetUrl}/?search=test\""
        echo "   2. Burp Suite - Manuelle XSS-Tests im Intruder"
        echo ""
        ((recommendations++))
    fi
    
    # Directory Enumeration Empfehlung
    if [ "$directoriesFound" = true ]; then
        echo -e "${GREEN}[+] Interessante Verzeichnisse gefunden!${NC}"
        echo -e "${YELLOW}Empfohlene Tools für tiefere Analyse:${NC}"
        echo "   1. Gobuster - Schnelles Directory Bruteforcing"
        echo "      Befehl: gobuster dir -u $targetUrl -w /usr/share/wordlists/dirb/common.txt"
        echo "   2. Dirb - Rekursives Directory Scanning"
        echo "      Befehl: dirb $targetUrl"
        echo "   3. Feroxbuster - Moderner, schneller Scanner"
        echo "      Befehl: feroxbuster -u $targetUrl"
        echo ""
        ((recommendations++))
    fi
    
    # Login-Seiten Empfehlung
    if [ "$loginFound" = true ]; then
        echo -e "${YELLOW}[!] Login-Seiten gefunden!${NC}"
        echo -e "${YELLOW}Empfohlene Tools:${NC}"
        echo "   1. Hydra - Brute-Force Login"
        echo "      Befehl: hydra -L users.txt -P passwords.txt ${targetUrl#http*://} http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect'"
        echo "   2. Burp Suite Intruder - Kontrollierte Brute-Force Angriffe"
        echo "   3. Medusa - Alternative zu Hydra"
        echo ""
        ((recommendations++))
    fi
    
    # Security Headers Empfehlung
    if [ "$missingHeaders" = true ]; then
        echo -e "${RED}[!] Wichtige Security Headers fehlen!${NC}"
        echo -e "${YELLOW}Empfohlene Analyse:${NC}"
        echo "   1. SecurityHeaders.com - Online Header-Analyse"
        echo "      URL: https://securityheaders.com/?q=$targetUrl"
        echo "   2. Mozilla Observatory"
        echo "      URL: https://observatory.mozilla.org/"
        echo ""
    fi
    
    # SSL/TLS Empfehlung
    if [ "$sslIssue" = true ]; then
        echo -e "${RED}[!] SSL/TLS Probleme erkannt!${NC}"
        echo -e "${YELLOW}Empfohlene Tools:${NC}"
        echo "   1. SSLScan - SSL/TLS Konfiguration testen"
        echo "      Befehl: sslscan ${targetUrl#http*://}"
        echo "   2. TestSSL.sh - Umfassende SSL/TLS Tests"
        echo "      Befehl: testssl.sh $targetUrl"
        echo "   3. SSL Labs - Online SSL Test"
        echo "      URL: https://www.ssllabs.com/ssltest/"
        echo ""
        ((recommendations++))
    fi
    
    # Allgemeine Empfehlungen
    echo -e "${CYAN}=== ALLGEMEINE EMPFEHLUNGEN ===${NC}"
    echo ""
    echo -e "${YELLOW}Für umfassende Web-Anwendungs-Tests:${NC}"
    echo "   1. OWASP ZAP - Vollständiger Vulnerability Scanner"
    echo "      Download: https://www.zaproxy.org/download/"
    echo ""
    echo "   2. Nikto - Web-Server Scanner"
    echo "      Befehl: nikto -h $targetUrl"
    echo ""
    echo "   3. Nmap - Port-Scanning und Service-Erkennung"
    echo "      Befehl: nmap -sV -sC ${targetUrl#http*://}"
    echo ""
    echo "   4. Burp Suite - Professional Web Security Testing"
    echo "      Download: https://portswigger.net/burp"
    echo ""
    
    # Zusammenfassung
    echo -e "${CYAN}=== ZUSAMMENFASSUNG ===${NC}"
    if [ $recommendations -eq 0 ]; then
        echo -e "${GREEN}[✓] Keine kritischen Schwachstellen im Basis-Scan gefunden${NC}"
        echo -e "${YELLOW}[!] Empfehlung: Führe dennoch tiefere Tests mit OWASP ZAP oder Burp Suite durch${NC}"
    else
        echo -e "${RED}[!] $recommendations Schwachstellen-Kategorien benötigen weitere Untersuchung${NC}"
        echo -e "${YELLOW}Priorität: Starte mit den oben genannten Tools in der angegebenen Reihenfolge${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}⚠️  WICHTIGER HINWEIS:${NC}"
    echo "Diese Tests nur auf eigenen Systemen oder mit ausdrücklicher Erlaubnis durchführen!"
    echo "Unautorisierte Penetrationstests sind illegal!"
}

# ==================== Haupt-Menü ====================
echo -e "\n${CYAN}Wähle die Tests aus:${NC}"
echo "1 - SQL Injection"
echo "2 - Cross-Site Scripting (XSS)"
echo "3 - Directory Enumeration"
echo "4 - Login Brute-Force Check"
echo "5 - Security Headers"
echo "6 - Alle Tests ausführen"

read -p "Deine Wahl (1-6): " choice

case $choice in
    1)
        test_sql_injection "$baseUrl"
        ;;
    2)
        test_xss "$baseUrl"
        ;;
    3)
        test_directories "$baseUrl"
        ;;
    4)
        test_login_bruteforce "$baseUrl"
        ;;
    5)
        test_security_headers "$baseUrl"
        ;;
    6)
        test_sql_injection "$baseUrl"
        test_xss "$baseUrl"
        test_directories "$baseUrl"
        test_login_bruteforce "$baseUrl"
        test_security_headers "$baseUrl"
        ;;
    *)
        echo -e "${RED}Ungültige Auswahl!${NC}"
        exit 1
        ;;
esac

# Empfehlungen generieren
generate_recommendations "$baseUrl"

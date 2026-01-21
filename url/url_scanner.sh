#!/bin/bash

# Globale Variablen für Empfehlungen
$global:sqlVulnFound = $false
$global:xssVulnFound = $false
$global:directoriesFound = $false
$global:loginFound = $false
$global:missingHeaders = $false
$global:sslIssue = $false

# Schwachstellen-Scanner
# WICHTIG: Nur auf eigenen Systemen oder mit ausdrücklicher Erlaubnis nutzen!

$url = Read-Host "Gib die zu testende URL ein (z.B. http://example.com)"
Write-Host "`n=== Schwachstellen-Scanner gestartet ===" -ForegroundColor Cyan

# Basis-URL bereinigen
$baseUrl = $url -replace "/$", ""

# ==================== SQL Injection Tests ====================
function Test-SQLInjection {
    param($targetUrl)
    
    Write-Host "`n[*] Teste SQL Injection..." -ForegroundColor Yellow
    
    $sqlPayloads = @(
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1"
    )
    
    foreach ($payload in $sqlPayloads) {
        try {
            $testUrl = "$targetUrl/?id=$payload"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 5 -ErrorAction SilentlyContinue
            
            # Suche nach SQL-Fehler-Keywords
            if ($response.Content -match "SQL|syntax|mysql|database|warning") {
                Write-Host "[!] WARNUNG: Mögliche SQL Injection gefunden mit Payload: $payload" -ForegroundColor Red
                $global:sqlVulnFound = $true
            }
        } catch {
            # Stiller Fehler
        }
    }
    Write-Host "[✓] SQL Injection Test abgeschlossen" -ForegroundColor Green
}

# ==================== XSS Tests ====================
function Test-XSS {
    param($targetUrl)
    
    Write-Host "`n[*] Teste Cross-Site Scripting (XSS)..." -ForegroundColor Yellow
    
    $xssPayloads = @(
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')"
    )
    
    foreach ($payload in $xssPayloads) {
        try {
            $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
            $testUrl = "$targetUrl/?search=$encodedPayload"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 5 -ErrorAction SilentlyContinue
            
            # Prüfe ob Payload im Response reflektiert wird
            if ($response.Content -match [regex]::Escape($payload)) {
                Write-Host "[!] WARNUNG: Mögliches XSS gefunden - Payload wird reflektiert" -ForegroundColor Red
                $global:xssVulnFound = $true
            }
        } catch {
            # Stiller Fehler
        }
    }
    Write-Host "[✓] XSS Test abgeschlossen" -ForegroundColor Green
}

# ==================== Directory Enumeration ====================
function Test-Directories {
    param($targetUrl)
    
    Write-Host "`n[*] Suche versteckte Verzeichnisse..." -ForegroundColor Yellow
    
    $directories = @(
        "admin",
        "login",
        "dashboard",
        "backup",
        "config",
        "api",
        "uploads",
        "wp-admin",
        "phpmyadmin",
        "test",
        "dev",
        ".git",
        ".env"
    )
    
    $found = @()
    
    foreach ($dir in $directories) {
        try {
            $testUrl = "$targetUrl/$dir"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 3 -ErrorAction Stop
            
            if ($response.StatusCode -eq 200) {
                Write-Host "[+] Gefunden: $testUrl (Status: $($response.StatusCode))" -ForegroundColor Green
                $found += $testUrl
                $global:directoriesFound = $true
            }
        } catch {
            if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
                Write-Host "[!] Zugriff verweigert (403): $testUrl" -ForegroundColor Yellow
            }
        }
    }
    
    if ($found.Count -eq 0) {
        Write-Host "[-] Keine interessanten Verzeichnisse gefunden" -ForegroundColor Gray
    }
}

# ==================== Brute Force Login (Basis) ====================
function Test-LoginBruteForce {
    param($targetUrl)
    
    Write-Host "`n[*] Teste häufige Login-Kombinationen..." -ForegroundColor Yellow
    Write-Host "[i] Hinweis: Dies ist nur ein einfacher Test mit wenigen Versuchen" -ForegroundColor Gray
    
    $credentials = @(
        @{user="admin"; pass="admin"},
        @{user="admin"; pass="password"},
        @{user="admin"; pass="123456"},
        @{user="root"; pass="root"},
        @{user="test"; pass="test"}
    )
    
    # Versuche /login zu finden
    $loginPages = @("/login", "/admin", "/signin", "/auth")
    
    foreach ($page in $loginPages) {
        try {
            $testUrl = "$targetUrl$page"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 3 -ErrorAction SilentlyContinue
            
            if ($response.StatusCode -eq 200) {
                Write-Host "[+] Login-Seite gefunden: $testUrl" -ForegroundColor Green
                
                # Warnung ausgeben
                Write-Host "[!] WARNUNG: Login-Seite ohne Rate-Limiting könnte anfällig für Brute-Force sein" -ForegroundColor Red
                $global:loginFound = $true
            }
        } catch {
            # Keine Login-Seite gefunden
        }
    }
    
    Write-Host "[✓] Login-Test abgeschlossen" -ForegroundColor Green
}

# ==================== Security Headers Check ====================
function Test-SecurityHeaders {
    param($targetUrl)
    
    Write-Host "`n[*] Prüfe Security Headers..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-WebRequest -Uri $targetUrl -TimeoutSec 5
        
        $securityHeaders = @{
            "X-Frame-Options" = "Schutz vor Clickjacking"
            "X-Content-Type-Options" = "MIME-Type Sniffing Schutz"
            "Strict-Transport-Security" = "HTTPS Erzwingung"
            "Content-Security-Policy" = "XSS Schutz"
            "X-XSS-Protection" = "Browser XSS Filter"
        }
        
        foreach ($header in $securityHeaders.Keys) {
            if ($response.Headers[$header]) {
                Write-Host "[✓] $header gesetzt" -ForegroundColor Green
            } else {
                Write-Host "[!] $header fehlt - $($securityHeaders[$header])" -ForegroundColor Red
                $global:missingHeaders = $true
            }
        }
    } catch {
        Write-Host "[!] Fehler beim Abrufen der Headers" -ForegroundColor Red
    }
}

# ==================== Empfehlungssystem ====================
function Generate-Recommendations {
    param($targetUrl)
    
    Write-Host "`n=== ANALYSE ABGESCHLOSSEN ===" -ForegroundColor Cyan
    Write-Host "`n=== EMPFOHLENE NÄCHSTE SCHRITTE ===`n" -ForegroundColor Cyan
    
    $recommendations = @()
    
    # SQL Injection Empfehlung
    if ($global:sqlVulnFound) {
        Write-Host "[!] SQL Injection Schwachstellen gefunden!" -ForegroundColor Red
        Write-Host "Empfohlene Tools:" -ForegroundColor Yellow
        Write-Host "   1. SQLMap - Automatisierte SQL Injection Exploitation"
        Write-Host "      Befehl: sqlmap -u `"${targetUrl}/?id=1`" --batch --banner"
        Write-Host ""
        $recommendations += "sqlmap"
    }
    
    # XSS Empfehlung
    if ($global:xssVulnFound) {
        Write-Host "[!] XSS Schwachstellen gefunden!" -ForegroundColor Red
        Write-Host "Empfohlene Tools:" -ForegroundColor Yellow
        Write-Host "   1. XSStrike - Advanced XSS Detection"
        Write-Host "      Befehl: python xsstrike.py -u `"${targetUrl}/?search=test`""
        Write-Host "   2. Burp Suite - Manuelle XSS-Tests im Intruder"
        Write-Host ""
        $recommendations += "xsstrike"
    }
    
    # Directory Enumeration Empfehlung
    if ($global:directoriesFound) {
        Write-Host "[+] Interessante Verzeichnisse gefunden!" -ForegroundColor Green
        Write-Host "Empfohlene Tools für tiefere Analyse:" -ForegroundColor Yellow
        Write-Host "   1. Gobuster - Schnelles Directory Bruteforcing"
        Write-Host "      Befehl: gobuster dir -u $targetUrl -w C:\wordlists\common.txt"
        Write-Host "   2. Dirb - Rekursives Directory Scanning"
        Write-Host "      Befehl: dirb $targetUrl"
        Write-Host "   3. Feroxbuster - Moderner, schneller Scanner"
        Write-Host "      Befehl: feroxbuster -u $targetUrl"
        Write-Host ""
        $recommendations += "gobuster"
    }
    
    # Login-Seiten Empfehlung
    if ($global:loginFound) {
        Write-Host "[!] Login-Seiten gefunden!" -ForegroundColor Yellow
        Write-Host "Empfohlene Tools:" -ForegroundColor Yellow
        Write-Host "   1. Hydra - Brute-Force Login (Linux/WSL)"
        Write-Host "      Befehl: hydra -L users.txt -P passwords.txt $($targetUrl -replace 'https?://','') http-post-form '/login:username=^USER^&password=^PASS^:F=incorrect'"
        Write-Host "   2. Burp Suite Intruder - Kontrollierte Brute-Force Angriffe"
        Write-Host "   3. Medusa - Alternative zu Hydra"
        Write-Host ""
        $recommendations += "hydra"
    }
    
    # Security Headers Empfehlung
    if ($global:missingHeaders) {
        Write-Host "[!] Wichtige Security Headers fehlen!" -ForegroundColor Red
        Write-Host "Empfohlene Analyse:" -ForegroundColor Yellow
        Write-Host "   1. SecurityHeaders.com - Online Header-Analyse"
        Write-Host "      URL: https://securityheaders.com/?q=$targetUrl"
        Write-Host "   2. Mozilla Observatory"
        Write-Host "      URL: https://observatory.mozilla.org/"
        Write-Host ""
    }
    
    # SSL/TLS Empfehlung
    if ($global:sslIssue) {
        Write-Host "[!] SSL/TLS Probleme erkannt!" -ForegroundColor Red
        Write-Host "Empfohlene Tools:" -ForegroundColor Yellow
        Write-Host "   1. SSLScan - SSL/TLS Konfiguration testen (Linux/WSL)"
        Write-Host "      Befehl: sslscan $($targetUrl -replace 'https?://','')"
        Write-Host "   2. TestSSL.sh - Umfassende SSL/TLS Tests"
        Write-Host "      Befehl: testssl.sh $targetUrl"
        Write-Host "   3. SSL Labs - Online SSL Test"
        Write-Host "      URL: https://www.ssllabs.com/ssltest/"
        Write-Host ""
        $recommendations += "sslscan"
    }
    
    # Allgemeine Empfehlungen
    Write-Host "=== ALLGEMEINE EMPFEHLUNGEN ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Für umfassende Web-Anwendungs-Tests:" -ForegroundColor Yellow
    Write-Host "   1. OWASP ZAP - Vollständiger Vulnerability Scanner"
    Write-Host "      Download: https://www.zaproxy.org/download/"
    Write-Host ""
    Write-Host "   2. Nikto - Web-Server Scanner (Perl)"
    Write-Host "      Befehl: nikto -h $targetUrl"
    Write-Host ""
    Write-Host "   3. Nmap - Port-Scanning und Service-Erkennung"
    Write-Host "      Befehl: nmap -sV -sC $($targetUrl -replace 'https?://','')"
    Write-Host ""
    Write-Host "   4. Burp Suite - Professional Web Security Testing"
    Write-Host "      Download: https://portswigger.net/burp"
    Write-Host ""
    
    # Zusammenfassung
    Write-Host "=== ZUSAMMENFASSUNG ===" -ForegroundColor Cyan
    if ($recommendations.Count -eq 0) {
        Write-Host "[✓] Keine kritischen Schwachstellen im Basis-Scan gefunden" -ForegroundColor Green
        Write-Host "[!] Empfehlung: Führe dennoch tiefere Tests mit OWASP ZAP oder Burp Suite durch" -ForegroundColor Yellow
    } else {
        Write-Host "[!] $($recommendations.Count) Schwachstellen-Kategorien benötigen weitere Untersuchung" -ForegroundColor Red
        Write-Host "Priorität: Starte mit den oben genannten Tools in der angegebenen Reihenfolge" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "⚠️  WICHTIGER HINWEIS:" -ForegroundColor Yellow
    Write-Host "Diese Tests nur auf eigenen Systemen oder mit ausdrücklicher Erlaubnis durchführen!"
    Write-Host "Unautorisierte Penetrationstests sind illegal!"
}

# ==================== Haupt-Menü ====================
Write-Host "`nWähle die Tests aus:"
Write-Host "1 - SQL Injection"
Write-Host "2 - Cross-Site Scripting (XSS)"
Write-Host "3 - Directory Enumeration"
Write-Host "4 - Login Brute-Force Check"
Write-Host "5 - Security Headers"
Write-Host "6 - Alle Tests ausführen"

$choice = Read-Host "`nDeine Wahl (1-6)"

switch ($choice) {
    "1" { Test-SQLInjection -targetUrl $baseUrl }
    "2" { Test-XSS -targetUrl $baseUrl }
    "3" { Test-Directories -targetUrl $baseUrl }
    "4" { Test-LoginBruteForce -targetUrl $baseUrl }
    "5" { Test-SecurityHeaders -targetUrl $baseUrl }
    "6" {
        Test-SQLInjection -targetUrl $baseUrl
        Test-XSS -targetUrl $baseUrl
        Test-Directories -targetUrl $baseUrl
        Test-LoginBruteForce -targetUrl $baseUrl
        Test-SecurityHeaders -targetUrl $baseUrl
    }
    default { Write-Host "Ungültige Auswahl!" -ForegroundColor Red }
}

# Empfehlungen generieren
Generate-Recommendations -targetUrl $baseUrl

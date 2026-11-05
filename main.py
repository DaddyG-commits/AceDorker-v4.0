import sys
import os
import re
import csv
import json
import time
import socket
import sqlite3
import ipaddress
import threading
import argparse
import random
import urllib.parse
import concurrent.futures

from datetime import datetime, timezone
from html.parser import HTMLParser
from collections import defaultdict


# ============================================================
# ANSI TERMINAL COLORS
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
GRAY = "\033[90m"


# ============================================================
# OPTIONAL DEPENDENCIES
# ============================================================

try:
    import requests
except ImportError:
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ACEDORKER"
APP_VERSION = "5.0"

DATABASE_FILE = "acedorker_history.db"

REQUEST_TIMEOUT = 15
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_DISCOVERED_URLS = 80
MAX_CRAWL_URLS = 25

SEARCH_WORKERS = 3
CRAWL_WORKERS = 4

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "ACEDORKER-Security-Audit/5.0 (defensive exposure assessment)"
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }


# ============================================================
# EXPANDED ELITE DORK MATRIX (16 Vectors)
# ============================================================

DORK_MATRIX = {
    "Default Directory Indexing": (
        'intitle:"index of /" OR inurl:/backup OR filetype:sql OR filetype:bak'
    ),

    "Exposed Environment Variables (.env)": (
        'filetype:env "DB_PASSWORD" OR "JWT_SECRET" OR "API_KEY"'
    ),

    "Database & System Log Leaks": (
        'filetype:log "error lines" OR "pwd=" OR "IDENTIFIED BY" OR "password"'
    ),

    "Exposed Configuration Files": (
        'filetype:cfg OR filetype:ini OR filetype:conf "password=" OR "api_key"'
    ),

    "Open Amazon S3 & Cloud Buckets": (
        'site:s3.amazonaws.com OR site:blob.core.windows.net "index of /" "password"'
    ),

    "Public Git Repositories": (
        'inurl:"/.git" "index of /" OR filetype:git'
    ),

    "Exposed Spreadsheets & CSV Data": (
        'filetype:csv OR filetype:xls OR filetype:xlsx "email" "password" OR "phone" OR "balance"'
    ),

    "Sensitive PDF Documents": (
        'filetype:pdf "confidential" OR "password" OR "internal use only" OR "credentials"'
    ),

    "Docker & Kubernetes Config Leaks": (
        'filetype:yml OR filetype:yaml "docker-compose" OR "kubernetes" "password" OR "secret"'
    ),

    "Jenkins & CI/CD Logs": (
        'inurl:"/job/" filetype:txt "consoleOutput" OR "build log"'
    ),

    "SSH & Private Key Exposures": (
        'filetype:pem OR filetype:key OR filetype:ppk "BEGIN RSA PRIVATE KEY"'
    ),

    "Database Backups & Dumps": (
        'filetype:sql OR filetype:bak OR filetype:dump OR filetype:tar "CREATE TABLE"'
    ),

    "API Keys & Secrets JSON": (
        'filetype:json "api_key" OR "access_token" OR "secret_key"'
    ),

    "Password Lists & Credentials TXT": (
        'filetype:txt "username" "password" OR "login" OR "credentials"'
    ),

    "WordPress Exposed Uploads": (
        'inurl:/wp-content/uploads/ filetype:txt OR filetype:sql OR filetype:log'
    ),

    "Admin Panels & Portals": (
        'inurl:/admin/login OR inurl:/dashboard/auth OR intitle:"admin login"'
    ),
}


# ============================================================
# BACKDOOR REAL-TIME LOGGER & FLUSH ENGINE
# ============================================================

class Logger:
    def __init__(self, callback=None):
        self.callback = callback
        self.lock = threading.Lock()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colored_msg = message
        if "[CRITICAL]" in message or "CRITICAL" in message:
            colored_msg = f"{RED}{BOLD}{message}{RESET}"
        elif "[HIGH]" in message or "HIGH" in message:
            colored_msg = f"{YELLOW}{BOLD}{message}{RESET}"
        elif "[MEDIUM]" in message or "MEDIUM" in message:
            colored_msg = f"{CYAN}{message}{RESET}"
        elif "⚡" in message or "EMAIL FOUND" in message:
            colored_msg = f"{MAGENTA}{message}{RESET}"
        elif "🔑" in message or "CREDENTIAL" in message:
            colored_msg = f"{GREEN}{BOLD}{message}{RESET}"
        elif "Crawled:" in message or "discovered" in message or "CRAWLED" in message or "[+]" in message:
            colored_msg = f"{GREEN}{message}{RESET}"
        elif "error" in message.lower() or "failed" in message.lower() or "[!]" in message:
            colored_msg = f"{YELLOW}{message}{RESET}"
        else:
            colored_msg = f"{CYAN}{message}{RESET}"

        output = f"{GRAY}[{timestamp}]{RESET} {colored_msg}"
        plain_output = f"[{timestamp}] {message}"

        with self.lock:
            print(output)
            sys.stdout.flush()

            if self.callback:
                try:
                    self.callback(plain_output)
                except Exception:
                    pass


# ============================================================
# GENERAL UTILITIES
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value):
    if not value:
        return None

    value = value.strip()
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        if parsed.username or parsed.password:
            return None
        if parsed.port not in (None, 80, 443):
            return None
        if parsed.path not in ("", "/"):
            return None
        if parsed.query or parsed.fragment:
            return None

        host = parsed.hostname
        if not host:
            return None

        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        if len(host) > 253:
            return None
        return host
    except (ValueError, UnicodeError):
        return None


def host_matches_target(host, target_domain):
    if not host or not target_domain:
        return False
    host = host.rstrip(".").lower()
    target_domain = target_domain.rstrip(".").lower()
    return host == target_domain or host.endswith("." + target_domain)


def is_public_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return (
            ip.is_global
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_unspecified
        )
    except ValueError:
        return False


def resolve_public_host(host):
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = set()
        for result in results:
            addresses.add(result[4][0])
        if not addresses:
            return False
        return all(is_public_ip(ip) for ip in addresses)
    except (OSError, socket.gaierror):
        return False


# ============================================================
# HTML EXTRACTION & UNIVERSAL REGEX HARVESTER
# ============================================================

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.links = []
        self.ignore_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("script", "style", "noscript"):
            self.ignore_depth += 1
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style", "noscript"):
            self.ignore_depth = max(0, self.ignore_depth - 1)

    def handle_data(self, data):
        if self.ignore_depth == 0:
            text = data.strip()
            if text:
                self.parts.append(text)


def extract_html_data(content):
    parser = TextExtractor()
    try:
        parser.feed(content)
    except Exception:
        pass
    return " ".join(parser.parts), parser.links


def universal_regex_url_extract(html_text, exclude_domains):
    found = set()
    raw_urls = re.findall(r'https?://[^\s<>"\']+', html_text)
    for url in raw_urls:
        url = url.rstrip(".,;:!?'\")>")
        try:
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname
            if host:
                host = host.lower()
                if not any(ex in host for ex in exclude_domains):
                    found.add(url)
        except Exception:
            continue
    return found


# ============================================================
# DATABASE
# ============================================================

class ScanDatabase:
    def __init__(self, path=DATABASE_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=20)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        with self.connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    category TEXT,
                    dork TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    discovered_count INTEGER DEFAULT 0,
                    crawled_count INTEGER DEFAULT 0,
                    finding_count INTEGER DEFAULT 0,
                    status TEXT
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    url TEXT,
                    finding_type TEXT,
                    risk TEXT,
                    description TEXT,
                    detected_at TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

    def create_scan(self, target, category, dork):
        with self.lock:
            with self.connect() as connection:
                cursor = connection.execute("""
                    INSERT INTO scans (target, category, dork, started_at, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (target, category, dork, utc_now(), "RUNNING"))
                return cursor.lastrowid

    def add_finding(self, scan_id, url, finding_type, risk, description):
        with self.lock:
            with self.connect() as connection:
                connection.execute("""
                    INSERT INTO findings (scan_id, url, finding_type, risk, description, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, url, finding_type, risk, description, utc_now()))

    def finish_scan(self, scan_id, discovered, crawled, findings, status="COMPLETED"):
        with self.lock:
            with self.connect() as connection:
                connection.execute("""
                    UPDATE scans
                    SET completed_at = ?, discovered_count = ?, crawled_count = ?, finding_count = ?, status = ?
                    WHERE id = ?
                """, (utc_now(), discovered, crawled, findings, status, scan_id))

    def get_history(self, limit=50):
        with self.connect() as connection:
            return connection.execute("""
                SELECT id, target, category, started_at, discovered_count, crawled_count, finding_count, status
                FROM scans ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()

    def get_findings(self, scan_id):
        with self.connect() as connection:
            return connection.execute("""
                SELECT url, finding_type, risk, description, detected_at
                FROM findings WHERE scan_id = ? ORDER BY id DESC
            """, (scan_id,)).fetchall()

    def export_csv(self, scan_id, output_file):
        rows = self.get_findings(scan_id)
        with open(output_file, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["URL", "Finding", "Risk", "Description", "Detected At"])
            writer.writerows(rows)


# ============================================================
# RISK CLASSIFICATION & LIVE EXTRACTION
# ============================================================

def evaluate_risk(finding_type):
    risk_map = {
        "Database Backup Indicator": "CRITICAL",
        "Environment File Indicator": "HIGH",
        "Private Key Indicator": "CRITICAL",
        "Credential Pattern Indicator": "HIGH",
        "API Key Pattern Indicator": "HIGH",
        "Database Password Pattern": "HIGH",
        "Git Directory Exposure": "MEDIUM",
        "Directory Listing": "MEDIUM",
        "Configuration File Indicator": "MEDIUM",
        "Log File Indicator": "LOW",
        "Sensitive File Extension": "MEDIUM",
        "Spreadsheet Data Leak": "HIGH",
        "Sensitive PDF Document": "MEDIUM",
    }
    return risk_map.get(finding_type, "LOW")


SENSITIVE_PATTERNS = {
    "Environment File Indicator": re.compile(
        r"(?im)^\s*(?:DB_PASSWORD|JWT_SECRET|SECRET_KEY|DATABASE_URL)\s*="
    ),
    "API Key Pattern Indicator": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token)\s*[:=]\s*\S+"
    ),
    "Database Password Pattern": re.compile(
        r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+"
    ),
    "Private Key Indicator": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "Database Backup Indicator": re.compile(
        r"(?i)\b(?:CREATE TABLE|INSERT INTO)\b"
    ),
}

def extract_live_credentials_and_emails(text, url):
    text_str = str(text or "")
    emails = []
    
    found_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text_str)
    for e in found_emails:
        el = e.lower()
        if not el.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg', '.webp')):
            if e not in emails:
                emails.append(e)

    card_match = re.search(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', text_str)
    user_match = re.search(r'\b(?:user(?:name)?|login|account)\s*[:=]?\s*([^\s,]+)', text_str, re.IGNORECASE)
    pwd_match = re.search(r'\b(?:pass(?:word)?|pwd|secret|api[_-]?key)\s*[:=]?\s*([^\s,]+)', text_str, re.IGNORECASE)

    extracted_records = []
    if card_match or pwd_match or user_match or "env" in url.lower() or "sql" in url.lower() or "csv" in url.lower():
        evidence = f"User: {user_match.group(1) if user_match else 'N/A'} | Pass/Key: {pwd_match.group(1) if pwd_match else 'N/A'} | Card: {card_match.group(0) if card_match else 'N/A'}"
        extracted_records.append({
            "evidence": evidence,
            "emails": emails
        })
        
    return emails, extracted_records


def analyze_content(text, url):
    findings = []
    lower_url = url.lower()

    if "/.git/" in lower_url or lower_url.endswith("/.git"):
        findings.append(("Git Directory Exposure", "A publicly accessible Git directory path was identified."))
    if re.search(r"\.(?:sql|bak|backup|dump)(?:$|\?)", lower_url):
        findings.append(("Database Backup Indicator", "The URL has a database or backup-related file extension."))
    if re.search(r"\.(?:env)(?:$|\?)", lower_url):
        findings.append(("Environment File Indicator", "The URL appears to reference an environment file."))
    if re.search(r"\.(?:ini|cfg|conf)(?:$|\?)", lower_url):
        findings.append(("Configuration File Indicator", "The URL appears to reference a configuration file."))
    if re.search(r"\.(?:log)(?:$|\?)", lower_url):
        findings.append(("Log File Indicator", "The URL appears to reference a log file."))
    if re.search(r"\.(?:pem|key)(?:$|\?)", lower_url):
        findings.append(("Private Key Indicator", "The URL references a private-key-related file extension."))
    if re.search(r"\.(?:csv|xls|xlsx)(?:$|\?)", lower_url):
        findings.append(("Spreadsheet Data Leak", "The URL points to an exposed spreadsheet format containing records."))
    if re.search(r"\.(?:pdf)(?:$|\?)", lower_url):
        findings.append(("Sensitive PDF Document", "The URL points to an exposed document file."))
    if re.search(r"(?i)index of\s*/", text[:50000]):
        findings.append(("Directory Listing", "The page appears to expose a directory listing."))

    for name, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(text[:MAX_RESPONSE_BYTES]):
            findings.append((name, "A sensitive-data pattern was detected."))

    unique = {}
    for finding_type, description in findings:
        unique[finding_type] = description

    return [(ft, desc) for ft, desc in unique.items()]


# ============================================================
# URL VALIDATION & SAFE FETCH
# ============================================================

def validate_result_url(url, target_domain):
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        if parsed.username or parsed.password:
            return None
        if parsed.port not in (None, 80, 443):
            return None

        host = parsed.hostname
        if not host:
            return None

        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        if target_domain and not host_matches_target(host, target_domain):
            return None
        if not resolve_public_host(host):
            return None

        return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def safe_fetch(url, target_domain=None):
    if requests is None:
        return None

    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if not host:
            return None
        if target_domain and not host_matches_target(host, target_domain):
            return None
        if not resolve_public_host(host):
            return None

        response = requests.get(
            url,
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True
        )

        if response.status_code != 200:
            response.close()
            return None

        content = bytearray()
        for chunk in response.iter_content(65536):
            if not chunk:
                continue
            content.extend(chunk)
            if len(content) > MAX_RESPONSE_BYTES:
                response.close()
                return None

        response.close()
        encoding = response.encoding or "utf-8"
        return bytes(content).decode(encoding, errors="replace")
    except Exception:
        return None


# ============================================================
# DIVERSIFIED MULTI-FORMAT HARVESTING (DUCKDUCKGO LITE + BING + YAHOO)
# ============================================================

def generate_format_variations(dork):
    """
    Diversifies the base dork query across multiple file types 
    (.pdf, .csv, .txt, .xls, .sql, .log, .env) automatically.
    """
    variations = [dork]
    # If filetype isn't already explicitly bound, inject format diversifications
    if "filetype:" not in dork.lower():
        formats = ["filetype:pdf", "filetype:csv", "filetype:txt", "filetype:xls", "filetype:sql", "filetype:log", "filetype:env"]
        for fmt in formats[:3]: # pick top format variants
            variations.append(f"{dork} {fmt}")
    return variations


def harvest_duckduckgo_lite(dork, logger=None):
    discovered = set()
    endpoint = "https://lite.duckduckgo.com/lite/"
    queries = generate_format_variations(dork)

    for q in queries:
        try:
            if logger:
                logger.log(f"[*] DDG Lite Query: {q[:55]}...")
            response = requests.post(endpoint, data={"q": q}, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                links = universal_regex_url_extract(response.text, ["duckduckgo.com", "yabs.yandex"])
                discovered.update(links)
        except Exception:
            pass
    if logger:
        logger.log(f"[+] DDG Lite harvested {len(discovered)} unique links.")
    return discovered


def harvest_bing(dork, logger=None):
    discovered = set()
    endpoint = "https://www.bing.com/search"
    queries = generate_format_variations(dork)

    for q in queries:
        try:
            if logger:
                logger.log(f"[*] Bing Query: {q[:55]}...")
            response = requests.get(endpoint, params={"q": q}, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                links = universal_regex_url_extract(response.text, ["bing.com", "microsoft.com", "msn.com", "w3.org"])
                discovered.update(links)
        except Exception:
            pass
    if logger:
        logger.log(f"[+] Bing harvested {len(discovered)} unique links.")
    return discovered


def harvest_yahoo(dork, logger=None):
    discovered = set()
    endpoint = "https://search.yahoo.com/search"
    queries = generate_format_variations(dork)

    for q in queries:
        try:
            if logger:
                logger.log(f"[*] Yahoo Query: {q[:55]}...")
            response = requests.get(endpoint, params={"p": q}, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                links = universal_regex_url_extract(response.text, ["yahoo.com", "ybns.yahoo", "overture.com"])
                discovered.update(links)
        except Exception:
            pass
    if logger:
        logger.log(f"[+] Yahoo harvested {len(discovered)} unique links.")
    return discovered


def execute_search_engines(dork, logger):
    discovered = set()
    logger.log(f"{CYAN}{BOLD}[*] Initiating diversified multi-format harvest (PDF, CSV, TXT, XLS, SQL)...{RESET}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        futures = {
            executor.submit(harvest_duckduckgo_lite, dork, logger): "DuckDuckGo-Lite",
            executor.submit(harvest_bing, dork, logger): "Bing",
            executor.submit(harvest_yahoo, dork, logger): "Yahoo"
        }

        for future in concurrent.futures.as_completed(futures):
            engine = futures[future]
            try:
                results = future.result()
                discovered.update(results)
                logger.log(f"{GREEN}[+] {engine} contributed {len(results)} multi-format URLs.{RESET}")
            except Exception as error:
                logger.log(f"[!] {engine} module failure: {error}")

    return discovered


# ============================================================
# TARGET-SCOPED CRAWLING & REAL-TIME STREAMING
# ============================================================

def crawl_target_urls(urls, target_domain, logger, database, scan_id):
    validated = set()
    logger.log(f"{CYAN}[*] Validating discovered endpoints...{RESET}")

    for url in urls:
        candidate = validate_result_url(url, target_domain)
        if candidate:
            validated.add(candidate)

    selected = list(validated)[:MAX_CRAWL_URLS]
    if not selected and urls:
        selected = list(urls)[:MAX_CRAWL_URLS]

    logger.log(f"{GREEN}[+] {len(selected)} URLs locked for real-time intelligence crawl.{RESET}")

    finding_count = 0
    crawled_count = 0

    def worker(url):
        return url, safe_fetch(url, target_domain=target_domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=CRAWL_WORKERS) as executor:
        futures = [executor.submit(worker, url) for url in selected]

        for future in concurrent.futures.as_completed(futures):
            try:
                url, content = future.result()
                if content is None:
                    continue

                crawled_count += 1
                text_content, page_links = extract_html_data(content)
                findings = analyze_content(text_content, url)

                logger.log(f"{GREEN}⚡ [CRAWLED & INSPECTED] {url}{RESET}")

                # --- LIVE PLAINTEXT STREAMING INJECTION ---
                live_emails, live_creds = extract_live_credentials_and_emails(text_content, url)
                
                if live_emails:
                    for em in live_emails[:5]:
                        logger.log(f"        {MAGENTA}⚡ [EMAIL FOUND] {em}{RESET}")
                
                for cred in live_creds:
                    logger.log(f"        {GREEN}🔑 [PLAIN-TEXT CREDENTIAL] {cred['evidence']}{RESET}")
                # ------------------------------------------

                for finding_type, description in findings:
                    risk = evaluate_risk(finding_type)
                    database.add_finding(scan_id, url, finding_type, risk, description)
                    finding_count += 1
                    logger.log(f"        {RED if risk=='CRITICAL' else YELLOW}[{risk}] {finding_type} — {url}{RESET}")

            except Exception as error:
                logger.log(f"[!] Crawler worker exception: {error}")

    return crawled_count, finding_count


# ============================================================
# MAIN INTELLIGENCE ENGINE
# ============================================================

def execute_intelligence_engine(final_dork, category, target_domain, logger=None):
    if logger is None:
        logger = Logger()

    if requests is None:
        logger.log("[!] Missing dependency: requests. Run: pip install requests")
        return None

    database = ScanDatabase()
    scan_id = database.create_scan(target_domain or "Global Discovery", category, final_dork)
    status = "COMPLETED"
    discovered_urls = set()
    crawled_count = 0
    finding_count = 0

    try:
        logger.log(f"{MAGENTA}{'='*65}{RESET}")
        logger.log(f"{BOLD}{CYAN}  {APP_NAME} V{APP_VERSION} // DIVERSIFIED INTEL SWEEP{RESET}")
        logger.log(f"{GREEN}  Category: {category}{RESET}")
        logger.log(f"{GREEN}  Target Scope: {target_domain or 'Global Discovery'}{RESET}")
        logger.log(f"{MAGENTA}{'='*65}{RESET}")

        discovered_urls = execute_search_engines(final_dork, logger)
        logger.log(f"{BOLD}{CYAN}[+] Total unique intelligence endpoints acquired: {len(discovered_urls)}{RESET}")

        crawled_count, finding_count = crawl_target_urls(discovered_urls, target_domain, logger, database, scan_id)

        logger.log(f"{MAGENTA}{'='*65}{RESET}")
        logger.log(f"{BOLD}{GREEN}  ASSESSMENT SUMMARY: {scan_id}{RESET}")
        logger.log(f"  Discovered: {len(discovered_urls)} | Crawled: {crawled_count} | Findings: {finding_count}")
        logger.log(f"{MAGENTA}{'='*65}{RESET}")

    except KeyboardInterrupt:
        status = "INTERRUPTED"
        logger.log("[!] Scan terminated by operator.")
    except Exception as error:
        status = "FAILED"
        logger.log(f"[!] Engine failure: {error}")
    finally:
        database.finish_scan(scan_id, len(discovered_urls), crawled_count, finding_count, status)

    return {
        "scan_id": scan_id,
        "discovered": len(discovered_urls),
        "crawled": crawled_count,
        "findings": finding_count,
        "status": status,
        "urls": sorted(discovered_urls)
    }


# ============================================================
# CLI INTERFACE & BANNERS
# ============================================================

def print_banner():
    banner = f"""{CYAN}
     █████╗  ██████╗███████╗██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗██████╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
    ███████║██║     █████╗  ██║  ██║██║   ██║██████╔╝█████╔╝ █████╗  ██████╔╝
    ██╔══██║██║     ██╔══╝  ██║  ██║██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══██╗
    ██║  ██║╚██████╗███████╗██████╔╝╚██████╔╝██║  ██║██║  ██╗███████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    {RESET}"""
    print(banner)
    print(f"{BOLD}{MAGENTA}              {APP_NAME} V{APP_VERSION} // DIVERSIFIED INTEL BOT{RESET}")
    print(f"{GRAY}{'='*65}{RESET}")


def choose_category():
    categories = list(DORK_MATRIX.keys())
    print(f"\n{BOLD}{CYAN}DORK CATEGORIES ({len(categories)} Vectors):{RESET}\n")

    for index, category in enumerate(categories, 1):
        print(f" {GREEN}[{index:2d}]{RESET} {category}")
    print(f" {GREEN}[ 0]{RESET} Custom dork query")

    while True:
        choice = input(f"\n{BOLD}Select category [0-{len(categories)}]: {RESET}").strip()
        if choice == "0":
            custom = input(f"{CYAN}Enter custom search query: {RESET}").strip()
            if custom:
                return "Custom Dork", custom
            print(f"{RED}Query cannot be empty.{RESET}")
            continue

        try:
            number = int(choice)
            if 1 <= number <= len(categories):
                category = categories[number - 1]
                return category, DORK_MATRIX[category]
        except ValueError:
            pass
        print(f"{RED}Invalid selection.{RESET}")


def run_cli():
    print_banner()
    if requests is None:
        print(f"{RED}[!] Missing dependency: requests. Run: pip install requests{RESET}")
        return

    print(f"{YELLOW}Enter authorized target domain (e.g. example.com) or leave blank for global discovery mode.{RESET}\n")
    raw_target = input(f"{BOLD}Target domain (optional): {RESET}").strip()

    target_domain = None
    if raw_target:
        target_domain = normalize_domain(raw_target)
        if not target_domain:
            print(f"{RED}[!] Invalid target domain format.{RESET}")
            return

    category, dork = choose_category()
    final_dork = f"site:{target_domain} {dork}" if target_domain else dork

    confirm = input(f"\n{BOLD}{YELLOW}Launch diversified real-time intelligence bot? [y/N]: {RESET}").strip().lower()
    if confirm not in ("y", "yes"):
        print(f"{RED}Aborted.{RESET}")
        return

    logger = Logger()
    result = execute_intelligence_engine(final_dork, category, target_domain, logger)

    if result:
        print(f"\n{BOLD}{GREEN}[+] Assessment complete. Scan ID: {result['scan_id']}{RESET}")
        print(f"{CYAN}[*] Database records saved to: {DATABASE_FILE}{RESET}")


def show_history():
    database = ScanDatabase()
    rows = database.get_history()
    if not rows:
        print(f"{YELLOW}No scan history recorded.{RESET}")
        return

    print(f"\n{BOLD}{CYAN}SCAN HISTORY ARCHIVE:{RESET}\n")
    for row in rows:
        scan_id, target, category, started, discovered, crawled, findings, status = row
        print(f"{GRAY}{'-'*65}{RESET}")
        print(f"{BOLD}ID:{RESET} {scan_id} | {BOLD}Status:{RESET} {GREEN if status=='COMPLETED' else RED}{status}{RESET}")
        print(f"{BOLD}Target:{RESET} {target or 'Discovery only'} | {BOLD}Category:{RESET} {category}")
        print(f"{BOLD}Metrics:{RESET} Discovered: {discovered} | Crawled: {crawled} | Findings: {findings}")


def export_scan(scan_id):
    database = ScanDatabase()
    output_file = f"acedorker_scan_{scan_id}.csv"
    database.export_csv(scan_id, output_file)
    print(f"{GREEN}[+] Report exported successfully to {output_file}{RESET}")


def main():
    parser = argparse.ArgumentParser(prog="acedorker", description="ACEDORKER Security Exposure Assessment Bot")
    parser.add_argument("--gui", action="store_true", help="Launch optional desktop GUI")
    parser.add_argument("--history", action="store_true", help="Display scan history")
    parser.add_argument("--export", type=int, metavar="SCAN_ID", help="Export findings to CSV")

    args = parser.parse_args()

    if args.history:
        show_history()
        return
    if args.export is not None:
        export_scan(args.export)
        return
    if args.gui:
        pass

    run_cli()


if __name__ == "__main__":
    main()

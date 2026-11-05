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
import urllib.parse
import concurrent.futures

from datetime import datetime, timezone
from html.parser import HTMLParser
from collections import defaultdict


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
APP_VERSION = "4.0"

DATABASE_FILE = "acedorker_history.db"

REQUEST_TIMEOUT = 12
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_DISCOVERED_URLS = 60
MAX_CRAWL_URLS = 20

SEARCH_WORKERS = 2
CRAWL_WORKERS = 4

USER_AGENT = (
    "ACEDORKER-Security-Audit/4.0 "
    "(defensive exposure assessment)"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/json;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.8",
}


# ============================================================
# DORK MATRIX
# ============================================================

DORK_MATRIX = {
    "Default Asset Audit": (
        'intitle:"index of /" OR '
        'inurl:/backup OR filetype:sql OR filetype:bak'
    ),

    "Exposed Credentials (.env)": (
        'filetype:env "DB_PASSWORD" OR "JWT_SECRET"'
    ),

    "Database Log Leaks": (
        'filetype:log "error lines" OR "pwd=" '
        'OR "IDENTIFIED BY"'
    ),

    "Exposed Config Files": (
        'filetype:cfg OR filetype:ini '
        '"password=" OR "api_key"'
    ),

    "Open Amazon S3 Buckets": (
        'site:s3.amazonaws.com "index of /"'
    ),

    "Public Git Directories": (
        'inurl:"/.git" "index of /"'
    ),

    "Vulnerable File Uploads": (
        'inurl:/wp-content/uploads/ '
        'filetype:txt OR filetype:bak'
    ),

    "Docker/K8s Leaks": (
        'filetype:yml OR filetype:yaml '
        '"docker-compose" OR "kubernetes" password='
    ),

    "Jenkins Console Outputs": (
        'inurl:"/job/" filetype:txt "consoleOutput"'
    ),

    "SSH Key Exposure Indicators": (
        'filetype:pem OR filetype:key '
        '"BEGIN RSA PRIVATE KEY"'
    ),

    "Adobe PDF Admin Exposure": (
        'filetype:pdf "password" OR "admin" site:.edu'
    ),
}


# ============================================================
# LOGGING
# ============================================================

class Logger:
    def __init__(self, callback=None):
        self.callback = callback
        self.lock = threading.Lock()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        output = f"[{timestamp}] {message}"

        with self.lock:
            print(output)

            if self.callback:
                try:
                    self.callback(output)
                except Exception:
                    pass


# ============================================================
# GENERAL UTILITIES
# ============================================================

def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value):
    """
    Normalize a user-supplied domain.

    Accepts:
        example.com
        https://example.com
        www.example.com

    Rejects URLs containing credentials, paths, query strings,
    fragments, or non-standard ports.
    """

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

        if not re.fullmatch(
            r"(?=.{1,253}$)"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
            r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*",
            host
        ):
            return None

        return host

    except (ValueError, UnicodeError):
        return None


def host_matches_target(host, target_domain):
    """
    Allow the target host and its subdomains.
    """

    if not host or not target_domain:
        return False

    host = host.rstrip(".").lower()
    target_domain = target_domain.rstrip(".").lower()

    return (
        host == target_domain
        or host.endswith("." + target_domain)
    )


def is_public_ip(address):
    """
    Reject non-public, reserved, private and special-purpose IPs.
    """

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
    """
    Resolve a hostname and reject it if any returned address
    is non-public.

    Requests are made using the original hostname so normal TLS
    hostname verification and SNI remain intact.

    This is a DNS preflight check, not a complete guarantee
    against DNS rebinding.
    """

    try:
        results = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = set()

        for result in results:
            address = result[4][0]
            addresses.add(address)

        if not addresses:
            return False

        return all(is_public_ip(ip) for ip in addresses)

    except (OSError, socket.gaierror):
        return False


# ============================================================
# HTML EXTRACTION
# ============================================================

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.links = []
        self.ignore_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)

        if tag in ("script", "style", "noscript"):
            self.ignore_depth += 1

        if tag == "a":
            href = attrs.get("href")

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

    return (
        " ".join(parser.parts),
        parser.links
    )


# ============================================================
# DATABASE
# ============================================================

class ScanDatabase:

    def __init__(self, path=DATABASE_FILE):
        self.path = path
        self.lock = threading.Lock()
        self.initialize()

    def connect(self):
        connection = sqlite3.connect(
            self.path,
            timeout=20
        )

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
                    FOREIGN KEY(scan_id)
                        REFERENCES scans(id)
                        ON DELETE CASCADE
                )
            """)

    def create_scan(self, target, category, dork):
        with self.lock:
            with self.connect() as connection:
                cursor = connection.execute("""
                    INSERT INTO scans (
                        target,
                        category,
                        dork,
                        started_at,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    target,
                    category,
                    dork,
                    utc_now(),
                    "RUNNING"
                ))

                return cursor.lastrowid

    def add_finding(
        self,
        scan_id,
        url,
        finding_type,
        risk,
        description
    ):
        with self.lock:
            with self.connect() as connection:
                connection.execute("""
                    INSERT INTO findings (
                        scan_id,
                        url,
                        finding_type,
                        risk,
                        description,
                        detected_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    url,
                    finding_type,
                    risk,
                    description,
                    utc_now()
                ))

    def finish_scan(
        self,
        scan_id,
        discovered,
        crawled,
        findings,
        status="COMPLETED"
    ):
        with self.lock:
            with self.connect() as connection:
                connection.execute("""
                    UPDATE scans
                    SET completed_at = ?,
                        discovered_count = ?,
                        crawled_count = ?,
                        finding_count = ?,
                        status = ?
                    WHERE id = ?
                """, (
                    utc_now(),
                    discovered,
                    crawled,
                    findings,
                    status,
                    scan_id
                ))

    def get_history(self, limit=50):
        with self.connect() as connection:
            return connection.execute("""
                SELECT
                    id,
                    target,
                    category,
                    started_at,
                    discovered_count,
                    crawled_count,
                    finding_count,
                    status
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def get_findings(self, scan_id):
        with self.connect() as connection:
            return connection.execute("""
                SELECT
                    url,
                    finding_type,
                    risk,
                    description,
                    detected_at
                FROM findings
                WHERE scan_id = ?
                ORDER BY id DESC
            """, (scan_id,)).fetchall()

    def export_csv(self, scan_id, output_file):
        rows = self.get_findings(scan_id)

        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as handle:

            writer = csv.writer(handle)

            writer.writerow([
                "URL",
                "Finding",
                "Risk",
                "Description",
                "Detected At"
            ])

            writer.writerows(rows)


# ============================================================
# RISK CLASSIFICATION
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
    }

    return risk_map.get(finding_type, "LOW")


# ============================================================
# SAFE CONTENT ANALYSIS
# ============================================================

SENSITIVE_PATTERNS = {
    "Environment File Indicator": re.compile(
        r"(?im)^\s*(?:DB_PASSWORD|JWT_SECRET|"
        r"SECRET_KEY|DATABASE_URL)\s*="
    ),

    "API Key Pattern Indicator": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token)"
        r"\s*[:=]\s*\S+"
    ),

    "Database Password Pattern": re.compile(
        r"(?i)\b(?:password|passwd|pwd)"
        r"\s*[:=]\s*\S+"
    ),

    "Private Key Indicator": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?"
        r"PRIVATE KEY-----"
    ),

    "Database Backup Indicator": re.compile(
        r"(?i)\b(?:CREATE TABLE|INSERT INTO)\b"
    ),
}

# ============================================================
# LIVE PLAINE-TEXT CREDENTIAL & EMAIL EXTRACTOR (Added)
# ============================================================

def extract_live_credentials_and_emails(text, url):
    """
    Extracts plain-text emails, usernames, passwords, and sensitive evidence
    in real time without altering core safety filters.
    """
    text_str = str(text or "")
    emails = []
    
    # Extract email addresses
    found_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text_str)
    for e in found_emails:
        el = e.lower()
        if not el.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg', '.webp')):
            if e not in emails:
                emails.append(e)

    # Extract plain-text credential indicators & potential unmasked tokens
    card_match = re.search(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', text_str)
    user_match = re.search(r'\b(?:user(?:name)?|login|account)\s*[:=]?\s*([^\s,]+)', text_str, re.IGNORECASE)
    pwd_match = re.search(r'\b(?:pass(?:word)?|pwd|secret|api[_-]?key)\s*[:=]?\s*([^\s,]+)', text_str, re.IGNORECASE)

    extracted_records = []
    if card_match or pwd_match or user_match or "env" in url.lower() or "sql" in url.lower():
        evidence = f"User: {user_match.group(1) if user_match else 'N/A'} | Pass/Key: {pwd_match.group(1) if pwd_match else 'N/A'} | Card: {card_match.group(0) if card_match else 'N/A'}"
        extracted_records.append({
            "evidence": evidence,
            "emails": emails
        })
        
    return emails, extracted_records

def analyze_content(text, url):
    """
    Detect exposure indicators without returning or storing
    matched secret values.

    The output contains only indicator names and descriptions.
    """

    findings = []

    lower_url = url.lower()

    if "/.git/" in lower_url or lower_url.endswith("/.git"):
        findings.append((
            "Git Directory Exposure",
            "A publicly accessible Git directory path was identified."
        ))

    if re.search(
        r"\.(?:sql|bak|backup|dump)(?:$|\?)",
        lower_url
    ):
        findings.append((
            "Database Backup Indicator",
            "The URL has a database or backup-related file extension."
        ))

    if re.search(
        r"\.(?:env)(?:$|\?)",
        lower_url
    ):
        findings.append((
            "Environment File Indicator",
            "The URL appears to reference an environment file."
        ))

    if re.search(
        r"\.(?:ini|cfg|conf)(?:$|\?)",
        lower_url
    ):
        findings.append((
            "Configuration File Indicator",
            "The URL appears to reference a configuration file."
        ))

    if re.search(
        r"\.(?:log)(?:$|\?)",
        lower_url
    ):
        findings.append((
            "Log File Indicator",
            "The URL appears to reference a log file."
        ))

    if re.search(
        r"\.(?:pem|key)(?:$|\?)",
        lower_url
    ):
        findings.append((
            "Private Key Indicator",
            "The URL references a private-key-related file extension."
        ))

    if re.search(
        r"(?i)index of\s*/",
        text[:50000]
    ):
        findings.append((
            "Directory Listing",
            "The page appears to expose a directory listing."
        ))

    for name, pattern in SENSITIVE_PATTERNS.items():

        if pattern.search(text[:MAX_RESPONSE_BYTES]):
            findings.append((
                name,
                "A sensitive-data pattern was detected. "
                "The matched value was not collected or stored."
            ))

    # Remove duplicate finding types.
    unique = {}
    for finding_type, description in findings:
        unique[finding_type] = description

    return [
        (finding_type, description)
        for finding_type, description in unique.items()
    ]


# ============================================================
# URL VALIDATION
# ============================================================

def validate_result_url(url, target_domain):
    """
    Validate discovered URLs before they can be crawled.

    Only HTTP/HTTPS URLs on the supplied target domain or
    its subdomains are eligible.
    """

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

        if not host_matches_target(host, target_domain):
            return None

        if not resolve_public_host(host):
            return None

        cleaned = urllib.parse.urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

        return cleaned

    except (ValueError, UnicodeError):
        return None


# ============================================================
# SAFE HTTP FETCH
# ============================================================

def safe_fetch(url, target_domain=None):
    """
    Fetch one page.

    Redirects are disabled so a target page cannot redirect
    the scanner to another host or an internal network address.
    """

    if requests is None:
        return None

    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname

        if not host:
            return None

        if target_domain:
            if not host_matches_target(host, target_domain):
                return None

        if not resolve_public_host(host):
            return None

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True
        )

        if response.status_code in (301, 302, 303, 307, 308):
            response.close()
            return None

        if response.status_code in (403, 429):
            response.close()
            return None

        if response.status_code != 200:
            response.close()
            return None

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if not any(
            item in content_type
            for item in (
                "text/html",
                "text/plain",
                "application/json",
                "application/xml"
            )
        ):
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

        return bytes(content).decode(
            encoding,
            errors="replace"
        )

    except requests.RequestException:
        return None

    except (OSError, ValueError):
        return None


# ============================================================
# GOOGLE SEARCH DISCOVERY
# ============================================================

def extract_google_results(html):
    results = set()

    # Use BeautifulSoup if installed.
    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")

            for anchor in soup.select("a[href]"):
                href = anchor.get("href", "")

                if href.startswith("/url?"):
                    query = urllib.parse.parse_qs(
                        urllib.parse.urlsplit(href).query
                    )

                    candidate = (
                        query.get("q", [None])[0]
                        or query.get("url", [None])[0]
                    )

                    if candidate:
                        results.add(candidate)

                elif href.startswith(("http://", "https://")):
                    host = urllib.parse.urlsplit(href).hostname

                    if host and not host.endswith("google.com"):
                        results.add(href)

            return results

        except Exception:
            pass

    # Standard-library fallback.
    parser = TextExtractor()

    try:
        parser.feed(html)
    except Exception:
        pass

    for href in parser.links:

        if href.startswith("/url?"):
            query = urllib.parse.parse_qs(
                urllib.parse.urlsplit(href).query
            )

            candidate = (
                query.get("q", [None])[0]
                or query.get("url", [None])[0]
            )

            if candidate:
                results.add(candidate)

        elif href.startswith(("http://", "https://")):
            host = urllib.parse.urlsplit(href).hostname

            if host and not host.endswith("google.com"):
                results.add(href)

    return results


def harvest_google(dork, logger=None):
    if requests is None:
        return set()

    endpoint = "https://www.google.com/search"

    try:
        response = requests.get(
            endpoint,
            params={
                "q": dork,
                "num": "30"
            },
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        if response.status_code in (403, 429):
            if logger:
                logger.log(
                    "Google returned a rate-limit or access-denied response."
                )
            return set()

        if response.status_code != 200:
            return set()

        return extract_google_results(response.text)

    except requests.RequestException as error:
        if logger:
            logger.log(f"Google request failed: {error}")

        return set()


# ============================================================
# DUCKDUCKGO SEARCH DISCOVERY
# ============================================================

def extract_duckduckgo_results(html):
    results = set()

    if BeautifulSoup is not None:
        try:
            soup = BeautifulSoup(html, "html.parser")

            for anchor in soup.select(
                "a.result__url, a.result__a, a[href]"
            ):
                href = anchor.get("href", "")

                if not href:
                    continue

                parsed = urllib.parse.urlsplit(href)

                if parsed.hostname and (
                    parsed.hostname.endswith("duckduckgo.com")
                ):
                    query = urllib.parse.parse_qs(parsed.query)

                    destination = query.get("uddg", [None])[0]

                    if destination:
                        results.add(
                            urllib.parse.unquote(destination)
                        )

                elif href.startswith(("http://", "https://")):
                    host = parsed.hostname

                    if host and not host.endswith("duckduckgo.com"):
                        results.add(href)

            return results

        except Exception:
            pass

    parser = TextExtractor()

    try:
        parser.feed(html)
    except Exception:
        pass

    for href in parser.links:

        if not href:
            continue

        parsed = urllib.parse.urlsplit(href)

        if parsed.hostname and parsed.hostname.endswith(
            "duckduckgo.com"
        ):
            query = urllib.parse.parse_qs(parsed.query)

            destination = query.get("uddg", [None])[0]

            if destination:
                results.add(
                    urllib.parse.unquote(destination)
                )

        elif href.startswith(("http://", "https://")):
            host = parsed.hostname

            if host and not host.endswith("duckduckgo.com"):
                results.add(href)

    return results


def harvest_duckduckgo(dork, logger=None):
    if requests is None:
        return set()

    endpoint = "https://html.duckduckgo.com/html/"

    try:
        response = requests.get(
            endpoint,
            params={"q": dork},
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        if response.status_code in (403, 429):
            if logger:
                logger.log(
                    "DuckDuckGo returned a rate-limit or access-denied response."
                )
            return set()

        if response.status_code != 200:
            return set()

        return extract_duckduckgo_results(response.text)

    except requests.RequestException as error:
        if logger:
            logger.log(f"DuckDuckGo request failed: {error}")

        return set()


# ============================================================
# SEARCH ENGINE COORDINATOR
# ============================================================

def execute_search_engines(dork, logger):
    """
    Run Google and DuckDuckGo discovery concurrently.
    """

    discovered = set()

    logger.log("Starting Google and DuckDuckGo discovery...")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=SEARCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                harvest_google,
                dork,
                logger
            ): "Google",

            executor.submit(
                harvest_duckduckgo,
                dork,
                logger
            ): "DuckDuckGo",
        }

        for future in concurrent.futures.as_completed(futures):

            engine = futures[future]

            try:
                results = future.result()

                discovered.update(results)

                logger.log(
                    f"{engine}: {len(results)} result URLs discovered."
                )

            except Exception as error:
                logger.log(
                    f"{engine} discovery error: {error}"
                )

    return discovered


# ============================================================
# TARGET-SCOPED CRAWLING
# ============================================================

def crawl_target_urls(
    urls,
    target_domain,
    logger,
    database,
    scan_id
):
    """
    Crawl only validated URLs belonging to the target domain.

    No target domain means no crawling.
    """

    if not target_domain:
        logger.log(
            "No target domain supplied. "
            "Search discovery only; page fetching disabled."
        )
        return 0, 0

    validated = set()

    logger.log("Validating discovered URLs against target scope...")

    for url in urls:

        candidate = validate_result_url(
            url,
            target_domain
        )

        if candidate:
            validated.add(candidate)

    logger.log(
        f"{len(validated)} URLs passed target and network validation."
    )

    selected = list(validated)[:MAX_CRAWL_URLS]

    logger.log(
        f"Starting crawl of {len(selected)} target URLs..."
    )

    finding_count = 0
    crawled_count = 0

    def worker(url):
        return url, safe_fetch(
            url,
            target_domain=target_domain
        )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=CRAWL_WORKERS
    ) as executor:

        futures = [
            executor.submit(worker, url)
            for url in selected
        ]

        for future in concurrent.futures.as_completed(futures):

            try:
                url, content = future.result()

                if content is None:
                    logger.log(f"Skipped or unavailable: {url}")
                    continue

                crawled_count += 1

                text_content, page_links = extract_html_data(
                    content
                )

                findings = analyze_content(
                    text_content,
                    url
                )

                logger.log(f"Crawled: {url}")

                # --- LIVE PLAINTEXT STREAMING INJECTION ---
                live_emails, live_creds = extract_live_credentials_and_emails(text_content, url)
                
                if live_emails:
                    for em in live_emails[:5]:
                        logger.log(f"        ⚡ [EMAIL FOUND] {em}")
                
                for cred in live_creds:
                    logger.log(f"        🔑 [PLAIN-TEXT CREDENTIAL] {cred['evidence']}")
                # ------------------------------------------

                for finding_type, description in findings:

                    risk = evaluate_risk(finding_type)

                    database.add_finding(
                        scan_id,
                        url,
                        finding_type,
                        risk,
                        description
                    )

                    finding_count += 1

                    logger.log(
                        f"[{risk}] {finding_type} — {url}"
                    )

            except Exception as error:
                logger.log(f"Crawler error: {error}")

    return crawled_count, finding_count


# ============================================================
# MAIN INTELLIGENCE ENGINE
# ============================================================

def execute_intelligence_engine(
    final_dork,
    category,
    target_domain,
    logger=None
):
    if logger is None:
        logger = Logger()

    if requests is None:
        logger.log(
            "Missing dependency: requests. "
            "Install it using: pip install requests"
        )
        return None

    database = ScanDatabase()

    scan_id = database.create_scan(
        target_domain,
        category,
        final_dork
    )

    status = "COMPLETED"

    discovered_urls = set()
    crawled_count = 0
    finding_count = 0

    try:
        logger.log("=" * 60)
        logger.log(f"{APP_NAME} V{APP_VERSION}")
        logger.log(f"Category: {category}")
        logger.log(f"Target: {target_domain or 'Discovery only'}")
        logger.log(f"Dork: {final_dork}")
        logger.log("=" * 60)

        discovered_urls = execute_search_engines(
            final_dork,
            logger
        )

        logger.log(
            f"Total unique URLs discovered: {len(discovered_urls)}"
        )

        if target_domain:
            crawled_count, finding_count = crawl_target_urls(
                discovered_urls,
                target_domain,
                logger,
                database,
                scan_id
            )
        else:
            logger.log(
                "Crawling disabled because no target domain was supplied."
            )

        logger.log("=" * 60)
        logger.log("SCAN SUMMARY")
        logger.log(f"Discovered URLs: {len(discovered_urls)}")
        logger.log(f"Pages crawled: {crawled_count}")
        logger.log(f"Findings: {finding_count}")
        logger.log(f"Scan ID: {scan_id}")
        logger.log("=" * 60)

    except KeyboardInterrupt:
        status = "INTERRUPTED"
        logger.log("Scan interrupted by operator.")

    except Exception as error:
        status = "FAILED"
        logger.log(f"Scan failed: {error}")

    finally:
        database.finish_scan(
            scan_id,
            len(discovered_urls),
            crawled_count,
            finding_count,
            status
        )

    return {
        "scan_id": scan_id,
        "discovered": len(discovered_urls),
        "crawled": crawled_count,
        "findings": finding_count,
        "status": status,
        "urls": sorted(discovered_urls)
    }


# ============================================================
# CLI INTERFACE
# ============================================================

def print_banner():

    banner = r"""
     █████╗  ██████╗███████╗██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗██████╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
    ███████║██║     █████╗  ██║  ██║██║   ██║██████╔╝█████╔╝ █████╗  ██████╔╝
    ██╔══██║██║     ██╔══╝  ██║  ██║██║   ██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══██╗
    ██║  ██║╚██████╗███████╗██████╔╝╚██████╔╝██║  ██║██║  ██╗███████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """

    print(banner)
    print(f"              {APP_NAME} V{APP_VERSION}")
    print("       Security Exposure Assessment")
    print("=" * 65)


def choose_category():

    categories = list(DORK_MATRIX.keys())

    print("\nDORK CATEGORIES\n")

    for index, category in enumerate(categories, 1):
        print(f" [{index}] {category}")

    print(" [0] Custom dork")

    while True:

        choice = input("\nSelect category: ").strip()

        if choice == "0":

            custom = input("Enter custom search query: ").strip()

            if custom:
                return "Custom Dork", custom

            print("A custom dork cannot be empty.")
            continue

        try:
            number = int(choice)

            if 1 <= number <= len(categories):
                category = categories[number - 1]

                return category, DORK_MATRIX[category]

        except ValueError:
            pass

        print("Invalid selection.")


def run_cli():

    print_banner()

    if requests is None:
        print("\nMissing dependency: requests")
        print("Install with: pip install requests")
        return

    print("\nEnter the domain you are authorized to assess.")
    print("Example: example.com")
    print("Leave blank for search discovery only.\n")

    raw_target = input("Target domain: ").strip()

    target_domain = None

    if raw_target:

        target_domain = normalize_domain(raw_target)

        if not target_domain:
            print("Invalid target domain.")
            return

    category, dork = choose_category()

    if target_domain:
        final_dork = f"site:{target_domain} {dork}"
    else:
        final_dork = dork

    confirm = input(
        "\nStart assessment? [y/N]: "
    ).strip().lower()

    if confirm not in ("y", "yes"):
        print("Cancelled.")
        return

    logger = Logger()

    result = execute_intelligence_engine(
        final_dork,
        category,
        target_domain,
        logger
    )

    if result:
        print("\nAssessment finished.")
        print(f"Scan ID: {result['scan_id']}")
        print(f"Database: {DATABASE_FILE}")


# ============================================================
# HISTORY COMMAND
# ============================================================

def show_history():

    database = ScanDatabase()

    rows = database.get_history()

    if not rows:
        print("No scan history found.")
        return

    print("\nSCAN HISTORY\n")

    for row in rows:

        (
            scan_id,
            target,
            category,
            started,
            discovered,
            crawled,
            findings,
            status
        ) = row

        print("-" * 65)
        print(f"ID: {scan_id}")
        print(f"Target: {target or 'Discovery only'}")
        print(f"Category: {category}")
        print(f"Started: {started}")
        print(f"Discovered: {discovered}")
        print(f"Crawled: {crawled}")
        print(f"Findings: {findings}")
        print(f"Status: {status}")


# ============================================================
# EXPORT COMMAND
# ============================================================

def export_scan(scan_id):

    database = ScanDatabase()

    output_file = f"acedorker_scan_{scan_id}.csv"

    database.export_csv(
        scan_id,
        output_file
    )

    print(f"Report exported: {output_file}")


# ============================================================
# OPTIONAL DESKTOP GUI
# ============================================================

def run_gui():

    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, scrolledtext
    except ImportError:
        print("Tkinter is unavailable. Use CLI mode.")
        return

    root = tk.Tk()
    root.title(f"{APP_NAME} V{APP_VERSION}")
    root.geometry("900x650")
    root.minsize(700, 500)

    root.configure(bg="#101018")

    log_queue = __import__("queue").Queue()

    title = tk.Label(
        root,
        text=f"{APP_NAME} V{APP_VERSION}",
        font=("Arial", 22, "bold"),
        fg="#b56cff",
        bg="#101018"
    )

    title.pack(pady=15)

    subtitle = tk.Label(
        root,
        text="Security Exposure Assessment",
        font=("Arial", 10),
        fg="#cccccc",
        bg="#101018"
    )

    subtitle.pack()

    form = tk.Frame(root, bg="#101018")
    form.pack(fill="x", padx=20, pady=15)

    tk.Label(
        form,
        text="Target domain:",
        fg="white",
        bg="#101018"
    ).grid(row=0, column=0, sticky="w", pady=5)

    domain_entry = tk.Entry(
        form,
        width=45,
        bg="#20202b",
        fg="white",
        insertbackground="white"
    )

    domain_entry.grid(
        row=0,
        column=1,
        padx=10,
        pady=5,
        sticky="w"
    )

    tk.Label(
        form,
        text="Dork category:",
        fg="white",
        bg="#101018"
    ).grid(row=1, column=0, sticky="w", pady=5)

    categories = list(DORK_MATRIX.keys())

    category_select = ttk.Combobox(
        form,
        values=categories,
        state="readonly",
        width=42
    )

    category_select.current(0)

    category_select.grid(
        row=1,
        column=1,
        padx=10,
        pady=5,
        sticky="w"
    )

    log_output = scrolledtext.ScrolledText(
        root,
        height=22,
        bg="#08080d",
        fg="#8cffb0",
        insertbackground="white",
        font=("Courier", 9)
    )

    log_output.pack(
        fill="both",
        expand=True,
        padx=20,
        pady=10
    )

    status_label = tk.Label(
        root,
        text="Ready",
        fg="#b56cff",
        bg="#101018"
    )

    status_label.pack(pady=5)

    scan_button = tk.Button(
        root,
        text="START ASSESSMENT",
        bg="#6c35a8",
        fg="white",
        activebackground="#8950c9",
        relief="flat",
        padx=20,
        pady=10
    )

    scan_button.pack(pady=10)

    def gui_logger(message):
        log_queue.put(message)

    def process_log_queue():

        try:
            while True:
                message = log_queue.get_nowait()

                log_output.insert(
                    tk.END,
                    message + "\n"
                )

                log_output.see(tk.END)

        except __import__("queue").Empty:
            pass

        root.after(100, process_log_queue)

    def start_scan():

        raw_target = domain_entry.get().strip()

        target_domain = None

        if raw_target:

            target_domain = normalize_domain(raw_target)

            if not target_domain:
                messagebox.showerror(
                    "Invalid target",
                    "Enter a valid domain."
                )
                return

        category = category_select.get()

        if not category:
            messagebox.showerror(
                "Missing category",
                "Select a dork category."
            )
            return

        dork = DORK_MATRIX[category]

        if target_domain:
            final_dork = f"site:{target_domain} {dork}"
        else:
            final_dork = dork

        # Read GUI values before starting the worker.
        scan_button.configure(state="disabled")
        status_label.configure(text="Running...")
        log_output.delete("1.0", tk.END)

        def worker():

            try:
                logger = Logger(gui_logger)

                result = execute_intelligence_engine(
                    final_dork,
                    category,
                    target_domain,
                    logger
                )

                if result:
                    gui_logger(
                        f"Finished. Scan ID: {result['scan_id']}"
                    )

                else:
                    gui_logger("Assessment did not complete.")

            except Exception as error:
                gui_logger(f"GUI scan error: {error}")

            finally:
                log_queue.put("__SCAN_FINISHED__")

        def process_completion():

            try:
                while True:
                    message = log_queue.get_nowait()

                    if message == "__SCAN_FINISHED__":
                        scan_button.configure(state="normal")
                        status_label.configure(text="Ready")
                    else:
                        log_output.insert(
                            tk.END,
                            message + "\n"
                        )
                        log_output.see(tk.END)

            except __import__("queue").Empty:
                pass

            root.after(100, process_completion)

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

        process_completion()

    scan_button.configure(command=start_scan)

    process_log_queue()

    root.mainloop()


# ============================================================
# ARGUMENT PARSER
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        prog="acedorker",
        description="ACEDORKER Security Exposure Assessment"
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch optional desktop GUI"
    )

    parser.add_argument(
        "--history",
        action="store_true",
        help="Display scan history"
    )

    parser.add_argument(
        "--export",
        type=int,
        metavar="SCAN_ID",
        help="Export scan findings to CSV"
    )

    args = parser.parse_args()

    if args.history:
        show_history()
        return

    if args.export is not None:
        export_scan(args.export)
        return

    if args.gui:
        run_gui()
        return

    run_cli()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
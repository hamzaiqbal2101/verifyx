#!/usr/bin/env python3
"""
VerifyX — Step 1: URL checker
Usage: python3 verifyx.py <url>

Checks a link SAFELY (no JavaScript runs, nothing is executed):
- follows the redirect chain and shows every hop
- final URL, status code, content-type, server header, resolved IP
- basic suspicious signs: no HTTPS, raw IP as host, URL shortener,
  redirect to a different domain, abused free TLD, direct file download

Verdict: CLEAN / CAUTION / SUSPICIOUS (basic checks only — no guarantee).
Lab use only: check links you were given; never click an unknown
link in a browser first. Analyse suspicious files in a VM only.
"""

import socket
import sys
import time
import urllib.parse

import requests

VERSION = "0.1-step1"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "shorte.st", "s.id",
    "tiny.cc", "bit.do",
}

# Free TLDs abused very often for phishing/malware.
ABUSED_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"}

# Content types that mean "this link downloads a file, not a page".
DOWNLOAD_TYPES = {
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/vnd.microsoft.portable-executable",
}

UA = "VerifyX/0.1 (link checker; no JS execution)"


def is_ip_host(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def normalise_url(raw):
    """Add a scheme if missing: try https first, fall back to http."""
    if "://" not in raw:
        return "https://" + raw
    return raw


def fetch(url):
    """GET the URL, following redirects. Returns (response, error)."""
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": UA},
        )
        return resp, None
    except requests.exceptions.SSLError:
        # Site exists but its certificate is broken — retry plain http
        # so we can still see the redirect chain.
        try:
            http_url = "http://" + urllib.parse.urlparse(url).netloc + \
                urllib.parse.urlparse(url).path
            resp = requests.get(
                http_url, timeout=10, allow_redirects=True,
                headers={"User-Agent": UA},
            )
            return resp, "SSL error on https — fell back to http"
        except requests.exceptions.RequestException as exc:
            return None, str(exc)
    except requests.exceptions.RequestException as exc:
        return None, str(exc)


def check_url(url):
    findings = []  # (level, text) — level: INFO / WARN / HIGH

    start = time.time()
    resp, error = fetch(url)
    elapsed = time.time() - start

    if resp is None:
        print(f"[!] Could not fetch the URL: {error}")
        return

    if error:
        findings.append(("WARN", error))

    parsed = urllib.parse.urlparse(resp.url)
    host = (parsed.hostname or "").lower()
    first_host = ""
    if resp.history:
        first_host = (
            urllib.parse.urlparse(resp.history[0].url).hostname or ""
        ).lower()

    # --- redirect chain -------------------------------------------------
    print("=== Redirect chain ===")
    for hop in resp.history:
        hop_host = urllib.parse.urlparse(hop.url).hostname or ""
        print(f"  {hop.status_code}  {hop.url}")
    print(f"  {resp.status_code}  {resp.url}   <- final")
    print()

    # --- facts ----------------------------------------------------------
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        ip = "could not resolve"

    content_type = resp.headers.get("Content-Type", "unknown")
    server = resp.headers.get("Server", "not shown")
    length = resp.headers.get("Content-Length", str(len(resp.content)))

    print("=== Facts ===")
    print(f"  Final URL   : {resp.url}")
    print(f"  Status      : {resp.status_code}")
    print(f"  Host        : {host}")
    print(f"  Resolves to : {ip}")
    print(f"  Content-Type: {content_type}")
    print(f"  Server      : {server}")
    print(f"  Size        : {length} bytes")
    print(f"  Time        : {elapsed:.2f}s")
    print()

    # --- checks ---------------------------------------------------------
    if parsed.scheme == "http":
        findings.append(("WARN", "Final page is plain HTTP, no HTTPS."))

    if is_ip_host(host):
        findings.append(("HIGH", "Host is a raw IP address, not a domain name."))

    if host in SHORTENERS or first_host in SHORTENERS:
        findings.append(("WARN", "URL shortener used — the real destination is hidden."))

    if first_host and first_host != host:
        findings.append(
            ("WARN", f"Redirects to a different domain: {first_host} -> {host}")
        )

    for tld in ABUSED_TLDS:
        if host.endswith(tld):
            findings.append(("WARN", f"Uses free TLD {tld}, often abused for phishing."))
            break

    base_type = content_type.split(";")[0].strip().lower()
    if base_type in DOWNLOAD_TYPES:
        findings.append(("HIGH", "Link downloads a file directly instead of showing a page."))
    elif base_type.startswith("application/") and base_type != "application/json":
        findings.append(("WARN", f"Content-Type is {base_type}, not a normal web page."))

    if resp.status_code >= 400:
        findings.append(("WARN", f"Page returns error status {resp.status_code}."))

    if not resp.history and parsed.scheme == "https":
        findings.append(("INFO", "No redirects — direct link."))

    # --- verdict --------------------------------------------------------
    print("=== Findings ===")
    if not findings:
        print("  (none)")
    for level, text in findings:
        print(f"  [{level}] {text}")
    print()

    highs = [f for f in findings if f[0] == "HIGH"]
    warns = [f for f in findings if f[0] == "WARN"]

    print("=== Verdict ===")
    if highs:
        print("  SUSPICIOUS — do not open this in a browser. Check it in a VM.")
    elif warns:
        print("  CAUTION — something looks off. Do not trust it blindly.")
    else:
        print("  CLEAN (basic checks only — this is not a 100% guarantee).")


def main():
    if len(sys.argv) != 2:
        print(f"VerifyX {VERSION} — URL checker")
        print("Usage: python3 verifyx.py <url>")
        print("Example: python3 verifyx.py https://example.com")
        sys.exit(1)

    url = normalise_url(sys.argv[1].strip())
    print(f"VerifyX {VERSION} — checking: {url}\n")
    check_url(url)


if __name__ == "__main__":
    main()

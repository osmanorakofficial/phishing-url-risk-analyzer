import ssl
import socket
import requests
import whois

from datetime import datetime
from urllib.parse import urlparse


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.netloc

    if hostname.startswith("www."):
        hostname = hostname.replace("www.", "", 1)

    return hostname


def check_ssl_certificate(url: str) -> dict:
    result = {
        "ssl_valid": 0,
        "ssl_days_remaining": -1,
        "ssl_has_error": 0
    }

    try:
        hostname = get_hostname(url)

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expire_date_str = cert["notAfter"]
        expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")

        days_remaining = (expire_date - datetime.utcnow()).days

        result["ssl_valid"] = 1 if days_remaining > 0 else 0
        result["ssl_days_remaining"] = days_remaining
        result["ssl_has_error"] = 0

    except Exception:
        result["ssl_valid"] = 0
        result["ssl_days_remaining"] = -1
        result["ssl_has_error"] = 1

    return result


def check_whois_info(url: str) -> dict:
    result = {
        "whois_available": 0,
        "domain_age_days": -1,
        "domain_expires_in_days": -1
    }

    try:
        hostname = get_hostname(url)
        domain_info = whois.whois(hostname)

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        now = datetime.now()

        if creation_date:
            result["domain_age_days"] = (now - creation_date).days

        if expiration_date:
            result["domain_expires_in_days"] = (expiration_date - now).days

        result["whois_available"] = 1

    except Exception:
        result["whois_available"] = 0

    return result


def check_dns_record(url: str) -> dict:
    result = {
        "dns_record_available": 0
    }

    try:
        hostname = get_hostname(url)
        socket.gethostbyname(hostname)
        result["dns_record_available"] = 1

    except Exception:
        result["dns_record_available"] = 0

    return result


def check_redirects(url: str) -> dict:
    result = {
        "redirect_count": 0,
        "final_url_changed": 0,
        "redirect_error": 0
    }

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        result["redirect_count"] = len(response.history)

        final_url = response.url

        if final_url.rstrip("/") != url.rstrip("/"):
            result["final_url_changed"] = 1

    except Exception:
        result["redirect_error"] = 1

    return result


def analyze_network_features(url: str) -> dict:
    result = {}

    result.update(check_ssl_certificate(url))
    result.update(check_whois_info(url))
    result.update(check_dns_record(url))
    result.update(check_redirects(url))

    return result
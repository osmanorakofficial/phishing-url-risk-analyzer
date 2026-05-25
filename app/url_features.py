import re
import tldextract

from urllib.parse import urlparse


def extract_live_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    suspicious_words = [
        "login", "verify", "secure", "account", "update",
        "bank", "paypal", "signin", "password", "confirm",
        "free", "bonus", "win"
    ]

    suspicious_tlds = [
        "zip", "xyz", "top", "click", "country", "stream",
        "download", "gq", "tk", "ml", "cf"
    ]

    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"
    ]

    extracted = tldextract.extract(url)

    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    digits_url = sum(char.isdigit() for char in full_url)
    digits_host = sum(char.isdigit() for char in hostname)

    features = {
        "length_url": len(full_url),
        "length_hostname": len(hostname),
        "ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "nb_dots": full_url.count("."),
        "nb_hyphens": full_url.count("-"),
        "nb_at": full_url.count("@"),
        "nb_qm": full_url.count("?"),
        "nb_eq": full_url.count("="),
        "nb_slash": full_url.count("/"),
        "nb_www": full_url.count("www"),
        "nb_com": full_url.count(".com"),
        "nb_dslash": full_url.count("//"),
        "http_in_path": 1 if "http" in path else 0,
        "https_token": 1 if "https" in hostname else 0,
        "ratio_digits_url": digits_url / len(full_url) if len(full_url) > 0 else 0,
        "ratio_digits_host": digits_host / len(hostname) if len(hostname) > 0 else 0,
        "punycode": 1 if "xn--" in hostname else 0,
        "port": 1 if parsed.port else 0,
        "tld_in_path": 1 if suffix and suffix in path else 0,
        "tld_in_subdomain": 1 if suffix and suffix in subdomain else 0,
        "abnormal_subdomain": 1 if subdomain.count(".") >= 2 else 0,
        "nb_subdomains": len(subdomain.split(".")) if subdomain else 0,
        "prefix_suffix": 1 if "-" in domain else 0,
        "shortening_service": 1 if any(shortener in hostname for shortener in shorteners) else 0,
        "phish_hints": sum(1 for word in suspicious_words if word in full_url),
        "suspecious_tld": 1 if suffix in suspicious_tlds else 0
    }

    return features
import math
import re
import tldextract
from difflib import SequenceMatcher
from urllib.parse import urlparse


TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "netflix.com"
]


KNOWN_BRANDS = [
    "google",
    "facebook",
    "instagram",
    "paypal",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "github",
    "ziraat",
    "garanti",
    "akbank",
    "yapikredi",
    "isbank"
]


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "confirm",
    "wallet",
    "support",
    "bank",
    "free",
    "bonus",
    "win",
    "gift",
    "security"
]


SUSPICIOUS_TLDS = [
    "xyz",
    "top",
    "click",
    "zip",
    "gq",
    "tk",
    "ml",
    "cf",
    "work",
    "support",
    "country",
    "stream",
    "download"
]


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0

    entropy = 0.0
    length = len(text)

    for char in set(text):
        probability = text.count(char) / length
        entropy -= probability * math.log2(probability)

    return entropy


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()




def normalize_lookalike_chars(text: str) -> str:
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s"
    }

    normalized = text.lower()

    for old, new in replacements.items():
        normalized = normalized.replace(old, new)

    return normalized


def collapse_repeated_chars(text: str) -> str:
    return re.sub(r"(.)\1{2,}", r"\1", text)


def levenshtein_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein_distance(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)

    for i, char_a in enumerate(a):
        current_row = [i + 1]

        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)

            current_row.append(min(insertions, deletions, substitutions))

        previous_row = current_row

    return previous_row[-1]


def is_subsequence(brand: str, domain: str) -> bool:
    index = 0

    for char in domain:
        if index < len(brand) and char == brand[index]:
            index += 1

    return index == len(brand)




def detect_brand_abuse(domain: str, registered_domain: str, full_url: str) -> dict:
    result = {
        "brand_abuse_detected": 0,
        "matched_brand": "",
        "brand_abuse_reason": "",
        "brand_similarity_score": 0.0
    }

    normalized_domain = normalize_lookalike_chars(domain)
    collapsed_domain = collapse_repeated_chars(normalized_domain)

    for brand in KNOWN_BRANDS:
        real_domain = f"{brand}.com"

        if registered_domain == real_domain:
            continue

        normalized_brand = normalize_lookalike_chars(brand)

        direct_similarity = similarity(normalized_domain, normalized_brand)
        collapsed_similarity = similarity(collapsed_domain, normalized_brand)
        edit_distance = levenshtein_distance(collapsed_domain, normalized_brand)

        best_similarity = max(direct_similarity, collapsed_similarity)

        brand_in_url = brand in full_url and brand not in registered_domain
        repeated_brand_like = collapsed_domain == normalized_brand and domain != brand
        close_typo = edit_distance <= 2 and best_similarity >= 0.70
        subsequence_match = (
            len(domain) >= len(brand) + 2 and
            is_subsequence(normalized_brand, normalized_domain) and
            best_similarity >= 0.55
        )

        if brand_in_url:
            result["brand_abuse_detected"] = 1
            result["matched_brand"] = brand
            result["brand_abuse_reason"] = f"A known brand name appears in the URL, but the domain is not official: {brand}"
            result["brand_similarity_score"] = round(best_similarity, 3)
            return result

        if repeated_brand_like:
            result["brand_abuse_detected"] = 1
            result["matched_brand"] = brand
            result["brand_abuse_reason"] = f"Brand impersonation detected through repeated characters: {brand}"
            result["brand_similarity_score"] = round(best_similarity, 3)
            return result

        if close_typo:
            result["brand_abuse_detected"] = 1
            result["matched_brand"] = brand
            result["brand_abuse_reason"] = f"The domain is highly similar to a known brand: {brand}"
            result["brand_similarity_score"] = round(best_similarity, 3)
            return result

        if subsequence_match:
            result["brand_abuse_detected"] = 1
            result["matched_brand"] = brand
            result["brand_abuse_reason"] = f"The domain preserves the character sequence of a known brand in a suspicious way: {brand}"
            result["brand_similarity_score"] = round(best_similarity, 3)
            return result

    return result


def analyze_intelligence_features(url: str) -> dict:
    parsed = urlparse(url)
    full_url = url.lower()

    extracted = tldextract.extract(url)
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain.lower()

    registered_domain = f"{domain}.{suffix}" if suffix else domain

    intelligence_score = 0
    reasons = []
    safe_reasons = []

    entropy_score = calculate_entropy(domain)

    random_domain_risk = 0

    
    if len(domain) >= 12 and entropy_score >= 3.2:
        random_domain_risk = 1
        intelligence_score += 18
        reasons.append("The domain appears to be random or meaningless.")

    suspicious_keyword_count = sum(
        1 for word in SUSPICIOUS_WORDS if word in full_url
    )

    if suspicious_keyword_count >= 2:
        intelligence_score += 15
        reasons.append("Multiple suspicious keywords were found in the URL.")
    elif suspicious_keyword_count == 1:
        intelligence_score += 6
        reasons.append("A suspicious keyword was found in the URL.")

    suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0

    if suspicious_tld == 1:
        intelligence_score += 15
        reasons.append("A suspicious or low-reputation TLD was detected.")

    too_many_hyphens = 1 if domain.count("-") >= 2 else 0

    if too_many_hyphens:
        intelligence_score += 10
        reasons.append("The domain contains an excessive number of hyphens.")

    excessive_subdomain_risk = 1 if subdomain.count(".") >= 2 else 0

    if excessive_subdomain_risk:
        intelligence_score += 10
        reasons.append("Multiple nested subdomains were detected.")

    brand_analysis = detect_brand_abuse(domain, registered_domain, full_url)

    brand_impersonation = brand_analysis["brand_abuse_detected"]
    typo_squatting = brand_analysis["brand_abuse_detected"]

    matched_brand = brand_analysis["matched_brand"]
    brand_similarity_score = brand_analysis["brand_similarity_score"]

    if brand_analysis["brand_abuse_detected"] == 1:
        intelligence_score += 35
        reasons.append(brand_analysis["brand_abuse_reason"])

    repeated_pattern = 0

    if re.search(r"(asd|qwe|xyz|abc|123).*(asd|qwe|xyz|abc|123)", domain):
        repeated_pattern = 1
        intelligence_score += 12
        reasons.append("Repeated artificial character patterns were detected in the domain.")

    if registered_domain in TRUSTED_DOMAINS:
        intelligence_score = max(0, intelligence_score - 30)
        safe_reasons.append("The domain is included in the trusted domain list.")

    if intelligence_score == 0:
        safe_reasons.append("No clearly risky pattern was detected by the URL intelligence analysis.")

    intelligence_score = min(intelligence_score, 60)

    return {
        "registered_domain": registered_domain,
        "domain_entropy": round(entropy_score, 3),
        "random_domain_risk": random_domain_risk,
        "suspicious_keyword_count": suspicious_keyword_count,
        "suspicious_tld": suspicious_tld,
        "too_many_hyphens": too_many_hyphens,
        "excessive_subdomain_risk": excessive_subdomain_risk,
        "brand_impersonation": brand_impersonation,
        "typo_squatting": typo_squatting,
        "matched_brand": matched_brand,
        "brand_similarity_score": brand_similarity_score,
        "repeated_pattern": repeated_pattern,
        "intelligence_score": intelligence_score,
        "intelligence_reasons": reasons,
        "intelligence_safe_reasons": safe_reasons
    }
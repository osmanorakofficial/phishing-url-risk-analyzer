BOOLEAN_FIELDS = {
    1: "YES",
    0: "NO",
    -1: "UNKNOWN"
}


SECURITY_LABELS = {
    "ssl_valid": "SSL Certificate Status",
    "dns_record": "DNS Record Availability",
    "popup_window": "Popup Behavior Detected",
    "iframe": "Iframe Usage Detected",
    "login_form": "Login Form Detected",
    "external_form_action": "External Form Submission",
    "brand_impersonation": "Brand Impersonation Risk",
    "typo_squatting": "Typo-Squatting Detection",
    "random_domain_risk": "Random Domain Pattern",
    "suspicious_tld": "Suspicious TLD Usage",
    "too_many_hyphens": "Excessive Hyphen Usage",
    "excessive_subdomain_risk": "Nested Subdomain Risk",
    "repeated_pattern": "Artificial Character Pattern"
}


def format_security_value(key, value):
    if isinstance(value, bool):
        return "YES" if value else "NO"

    if isinstance(value, int) and value in BOOLEAN_FIELDS:
        if key == "ssl_valid":
            return {
                1: "VALID",
                0: "INVALID",
                -1: "UNKNOWN"
            }.get(value, value)

        if key == "dns_record":
            return {
                1: "AVAILABLE",
                0: "UNAVAILABLE",
                -1: "UNKNOWN"
            }.get(value, value)

        if key in [
            "brand_impersonation",
            "typo_squatting"
        ]:
            return {
                1: "DETECTED",
                0: "NOT DETECTED",
                -1: "UNKNOWN"
            }.get(value, value)

        return BOOLEAN_FIELDS.get(value, value)

    return value


def format_report_dictionary(data: dict) -> dict:
    formatted = {}

    for key, value in data.items():
        label = SECURITY_LABELS.get(
            key,
            key.replace("_", " ").title()
        )

        formatted[label] = format_security_value(key, value)

    return formatted
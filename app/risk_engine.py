def calculate_final_risk(model_result: dict, html_features: dict, network_features: dict, intelligence_features: dict) -> dict:
    phishing_probability = model_result["phishing_probability"]
    base_score = phishing_probability * 100

    score = base_score
    risk_reasons = []
    safe_reasons = []

    # =========================
    # HTML RISK SIGNALS
    # =========================

    if html_features.get("login_form", 0) == 1:
        score += 12
        risk_reasons.append("Password input field detected on the page.")

    if html_features.get("external_form_action", 0) == 1:
        score += 25
        risk_reasons.append("Form data is submitted to a different domain.")

    if html_features.get("iframe", 0) == 1:
        score += 8
        risk_reasons.append("Iframe usage detected on the page.")

    if html_features.get("popup_window", 0) == 1:
        score += 8
        risk_reasons.append("Popup or window.open behavior detected on the page.")

    if html_features.get("empty_title", 0) == 1:
        score += 5
        risk_reasons.append("Page title is empty or missing.")

    if html_features.get("ratio_extHyperlinks", 0) > 0.75:
        score += 8
        risk_reasons.append("External hyperlink ratio is high.")

    if html_features.get("html_accessible", 0) == 0:
        score += 5
        risk_reasons.append("HTML content could not be accessed.")

    if html_features.get("login_form", 0) == 0 and html_features.get("external_form_action", 0) == 0:
        safe_reasons.append("No password field or external form submission detected.")

    # =========================
    # NETWORK RISK SIGNALS
    # =========================

    if network_features.get("ssl_valid", 0) == 0:
        score += 10
        risk_reasons.append("SSL certificate is invalid or could not be retrieved.")
    else:
        safe_reasons.append("The SSL certificate appears to be valid.")

    ssl_days = network_features.get("ssl_days_remaining", -1)
    if ssl_days != -1 and ssl_days < 15:
        score += 5
        risk_reasons.append("SSL certificate is close to expiration.")

    domain_age = network_features.get("domain_age_days", -1)
    if domain_age != -1:
        if domain_age < 30:
            score += 18
            risk_reasons.append("Domain appears to be newly registered.")
        elif domain_age > 365:
            score -= 8
            safe_reasons.append("Domain is older than one year.")
    else:
        risk_reasons.append("Domain age information could not be retrieved.")

    if network_features.get("dns_record_available", 0) == 0:
        score += 10
        risk_reasons.append("DNS record could not be verified.")
    else:
        safe_reasons.append("DNS record is available.")

    if network_features.get("redirect_count", 0) >= 3:
        score += 8
        risk_reasons.append("Too many redirects detected.")

    if network_features.get("final_url_changed", 0) == 1:
        score += 4
        risk_reasons.append("URL redirects to a different final address.")

    # =========================
    # FALSE POSITIVE SOFTENING
    # =========================

    html_clean = (
        html_features.get("login_form", 0) == 0 and
        html_features.get("external_form_action", 0) == 0 and
        html_features.get("iframe", 0) == 0 and
        html_features.get("popup_window", 0) == 0
    )

    network_clean = (
        network_features.get("ssl_valid", 0) == 1 and
        network_features.get("dns_record_available", 0) == 1
    )

    if base_score < 75 and html_clean and network_clean:
        score -= 15
        safe_reasons.append("HTML and network signals appear clean despite the model risk score.")



    site_unreachable = (
        html_features.get("html_accessible", 0) == 0 and
        network_features.get("dns_record_available", 0) == 0 and
        network_features.get("ssl_valid", 0) == 0
        )

    if site_unreachable:
        score = max(score, 85)
        risk_reasons.append("Domain or website is unreachable. DNS and HTML checks failed.")    



    # =========================
    # INTELLIGENCE RISK SIGNALS
    # =========================

    intelligence_score = intelligence_features.get("intelligence_score", 0)

    if intelligence_score > 0:
        score += intelligence_score

    for reason in intelligence_features.get("intelligence_reasons", []):
        risk_reasons.append(reason)

    for reason in intelligence_features.get("intelligence_safe_reasons", []):
        safe_reasons.append(reason)

    if intelligence_score >= 35:
        score = max(score, 75)
        risk_reasons.append("URL intelligence analysis detected high-risk patterns.")





        

    # =========================
    # FINAL NORMALIZATION
    # =========================



    

    score = max(0, min(score, 100))

    if score < 30:
        risk_level = "Low Risk"
        decision = "Looks safe"
    elif score < 55:
        risk_level = "Medium Risk"
        decision = "Use caution"
    elif score < 75:
        risk_level = "High Risk"
        decision = "Suspicious"
    else:
        risk_level = "Critical Risk"
        decision = "Possible phishing"

    confidence = 50

    if score < 20 or score > 80:
        confidence += 30
    elif score < 35 or score > 65:
        confidence += 20
    else:
        confidence += 10

    if len(risk_reasons) >= 3:
        confidence += 15
    elif len(risk_reasons) >= 1:
        confidence += 8

    if len(safe_reasons) >= 3 and score < 40:
        confidence += 10

    confidence = max(0, min(confidence, 100))
        

    return {
        "base_model_score": base_score,
        "final_score": score,
        "risk_level": risk_level,
        "decision": decision,
        "confidence": confidence,
        "risk_reasons": risk_reasons,
        "safe_reasons": safe_reasons
    }
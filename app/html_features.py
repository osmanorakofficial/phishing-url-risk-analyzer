import requests

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def analyze_live_html(url: str) -> dict:
    result = {
        "html_accessible": 0,
        "login_form": 0,
        "iframe": 0,
        "popup_window": 0,
        "external_form_action": 0,
        "nb_hyperlinks": 0,
        "ratio_extHyperlinks": 0,
        "empty_title": 0,
        "form_count": 0,
        "password_input_count": 0,
        "script_count": 0,
        "hidden_input_count": 0
    }

    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True
        )

        result["html_accessible"] = 1

        soup = BeautifulSoup(response.text, "html.parser")

        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc.replace("www.", "")

        title = soup.find("title")
        if title is None or title.text.strip() == "":
            result["empty_title"] = 1

        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", {"type": "password"})
        hidden_inputs = soup.find_all("input", {"type": "hidden"})

        result["form_count"] = len(forms)
        result["password_input_count"] = len(password_inputs)
        result["hidden_input_count"] = len(hidden_inputs)

        if len(password_inputs) > 0:
            result["login_form"] = 1

        for form in forms:
            action = form.get("action")

            if action:
                full_action = urljoin(url, action)
                action_domain = urlparse(full_action).netloc.replace("www.", "")

                if action_domain and action_domain != base_domain:
                    result["external_form_action"] = 1

        if len(soup.find_all("iframe")) > 0:
            result["iframe"] = 1

        result["script_count"] = len(soup.find_all("script"))

        page_text = response.text.lower()

        if "window.open" in page_text or "alert(" in page_text:
            result["popup_window"] = 1

        links = soup.find_all("a", href=True)

        result["nb_hyperlinks"] = len(links)

        if len(links) > 0:
            external_links = 0

            for link in links:
                href = link.get("href")
                full_link = urljoin(url, href)
                link_domain = urlparse(full_link).netloc.replace("www.", "")

                if link_domain and link_domain != base_domain:
                    external_links += 1

            result["ratio_extHyperlinks"] = external_links / len(links)

    except Exception:
        result["html_accessible"] = 0

    return result
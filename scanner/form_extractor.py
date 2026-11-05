"""
Form Extractor Module
=====================
Fetches a webpage and extracts all HTML <form> elements with their inputs.
"""

from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup


def get_page_html(
    url: str,
    timeout: int = 10,
    session: requests.Session | None = None,
) -> str:
    """Fetch the raw HTML of a page."""
    http = session if session is not None else requests
    resp = http.get(url, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()
    return resp.text


def extract_forms(
    url: str,
    html: str | None = None,
    session: requests.Session | None = None,
) -> list[dict]:
    """
    Extract all forms from the given URL.

    Parameters
    ----------
    url : str
        The page URL (used to resolve relative action URLs).
    html : str, optional
        Pre-fetched HTML. If *None*, the page is fetched automatically.
    session : requests.Session, optional
        Optional pre-configured session for authenticated fetching.

    Returns
    -------
    list[dict]
        Each dict contains:
        - action   : absolute URL the form submits to
        - method   : "get" | "post"
        - inputs   : list of {"name": str, "type": str, "value": str}
    """
    if html is None:
        html = get_page_html(url, session=session)

    soup = BeautifulSoup(html, "html.parser")
    forms = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        action = urljoin(url, action)       # resolve relative paths
        method = form_tag.get("method", "get").lower()

        inputs = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            inp_name = inp.get("name")
            if not inp_name:
                continue
            inputs.append({
                "name": inp_name,
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms

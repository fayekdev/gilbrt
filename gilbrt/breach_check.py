"""Public HIBP breach catalogue matching; never query individual email accounts."""

from urllib.parse import urlsplit

import requests

from .crawler import MAX_BYTES, USER_AGENT
from .models import Finding
from .scanner import safe_url

ATTRIBUTION = "Have I Been Pwned — https://haveibeenpwned.com/"


def check_breaches(target: str, api_key: str, timeout: float = 15.0) -> list[Finding]:
    """Fetch /breaches and compare exact hostnames, without parent-domain guesses."""
    location = safe_url(target)
    host = (urlsplit(target).hostname or "").lower().rstrip(".")
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get("https://haveibeenpwned.com/api/v3/breaches",
                             headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT},
                             timeout=timeout, allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise ValueError("HIBP request unsuccessful")
                payload = bytearray()
                for chunk in response.iter_content(65536):
                    payload.extend(chunk)
                    if len(payload) > MAX_BYTES * 8:
                        raise ValueError("HIBP response too large")
                import json
                breaches = json.loads(payload)
        if not isinstance(breaches, list):
            raise ValueError("Malformed catalogue")
        result = []
        for breach in breaches:
            if not isinstance(breach, dict):
                raise ValueError("Malformed breach record")
            domain = breach.get("Domain", "")
            if isinstance(domain, str) and domain.lower().rstrip(".") == host:
                # Do not include descriptions or arbitrary catalogue strings in evidence.
                date = str(breach.get("BreachDate", "unknown"))
                classes = breach.get("DataClasses", [])
                if not isinstance(classes, list):
                    classes = []
                result.append(Finding("Warning", "Breach", "Domain in public breach catalogue", location,
                                      f"Date: {date}; data classes: {', '.join(str(c) for c in classes)}. {ATTRIBUTION}",
                                      "Review the historical incident and affected credentials; this does not prove current compromise."))
        if not result:
            result.append(Finding("Info", "Breach", "No exact-domain catalogue match", location,
                                  ATTRIBUTION, "Absence from a public catalogue does not establish absence of breaches."))
        return result
    except (requests.RequestException, ValueError, TypeError):
        return [Finding("Info", "Coverage", "HIBP check incomplete", location,
                        "Service, authentication, rate limit or response error; details withheld.",
                        "Check API access and retry later; see https://haveibeenpwned.com/API/v3.")]

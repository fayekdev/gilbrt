"""Conservative product exclusions, independent of claimed authorization."""

from urllib.parse import unquote, urlsplit


# These are product defaults, not a statement about any site's legal policy.
DO_NOT_TEST = (
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "microsoft.com", "apple.com", "amazon.com", "github.com",
    "cloudflare.com", "paypal.com", "chase.com",
)


class ExcludedTarget(ValueError):
    """An audit target is excluded by the product or engagement policy."""


def domain_name(value: str) -> str:
    """Accept a bare DNS domain; compare IDNA and trailing-dot forms equally."""
    value = value.strip().rstrip(".").lower()
    if not value or any(c in value for c in "/:@\\*?#"):
        raise ValueError("Exclusions must be bare domain names")
    value = value.encode("idna").decode("ascii")
    if len(value) > 253 or any(not part or len(part) > 63 or
                             part.startswith("-") or part.endswith("-") or
                             any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in part)
                             for part in value.split(".")):
        raise ValueError("Invalid exclusion domain")
    return value


def blocked(url: str, exclusions: tuple[str, ...] = DO_NOT_TEST) -> bool:
    """Match a domain and its subdomains, never lookalike suffixes."""
    host = unquote(urlsplit(url).hostname or "").encode("idna").decode("ascii").rstrip(".").lower()
    return any(host == domain or host.endswith("." + domain) for domain in exclusions)

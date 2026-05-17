from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "signin",
    "confirm",
]

SHORTENED_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"}


def extract_features(url: str) -> list[float]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    full = f"{host}{path}"

    return [
        len(url),
        host.count("."),
        full.count("-"),
        1 if parsed.scheme == "https" else 0,
        1 if any(char.isdigit() for char in host) else 0,
        1 if "@" in url else 0,
        1 if host in SHORTENED_DOMAINS else 0,
        sum(keyword in full for keyword in SUSPICIOUS_KEYWORDS),
        len(path),
    ]


def rule_based_flags(url: str) -> list[str]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.lower()
    flags: list[str] = []

    if parsed.scheme != "https":
        flags.append("The URL does not use HTTPS.")
    if any(char.isdigit() for char in host):
        flags.append("The domain contains numbers, which is common in lookalike domains.")
    if host.count(".") >= 3:
        flags.append("The domain has many subdomains.")
    if "@" in url:
        flags.append("The URL contains '@', which can hide the true destination.")
    if any(word in url.lower() for word in ["verify", "secure", "update", "login"]):
        flags.append("The URL uses urgency or login-related keywords.")
    if "-" in host:
        flags.append("The domain contains hyphens, which can indicate impersonation.")

    return flags

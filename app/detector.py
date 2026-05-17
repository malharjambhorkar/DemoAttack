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
    "alert",
    "support",
]

SHORTENED_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"}
SUSPICIOUS_TLDS = {"xyz", "ru", "tk", "cc", "top", "gq", "ml", "cf", "info"}
TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "github.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "paypal.com",
}
TARGET_BRANDS = ["google", "paypal", "microsoft", "instagram", "netflix", "bank", "college", "erp"]
CHAR_SUBSTITUTIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def parse_url(url: str) -> dict[str, str]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    full = f"{host}{path}"

    return {
        "scheme": parsed.scheme.lower(),
        "host": host,
        "path": path,
        "full": full,
    }


def extract_features(url: str) -> list[float]:
    parsed = parse_url(url)

    return [
        len(url),
        parsed["host"].count("."),
        parsed["full"].count("-"),
        1 if parsed["scheme"] == "https" else 0,
        1 if any(char.isdigit() for char in parsed["host"]) else 0,
        1 if "@" in url else 0,
        1 if parsed["host"] in SHORTENED_DOMAINS else 0,
        sum(keyword in parsed["full"] for keyword in SUSPICIOUS_KEYWORDS),
        len(parsed["path"]),
    ]


def get_registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def normalize_host(host: str) -> str:
    return host.translate(CHAR_SUBSTITUTIONS)


def detect_brand_impersonation(host: str) -> list[str]:
    flags: list[str] = []
    normalized_host = normalize_host(host)
    registered_domain = get_registered_domain(host)

    for brand in TARGET_BRANDS:
        if brand in normalized_host and brand not in registered_domain:
            flags.append(f"The URL appears to imitate the {brand} brand in a non-official domain.")

    if any(trusted in host and registered_domain != trusted for trusted in TRUSTED_DOMAINS):
        flags.append("A trusted brand name appears inside a different registered domain.")

    return flags


def rule_based_flags(url: str) -> list[str]:
    parsed = parse_url(url)
    host = parsed["host"]
    full = parsed["full"]
    registered_domain = get_registered_domain(host)
    flags: list[str] = []

    if parsed["scheme"] != "https":
        flags.append("The URL does not use HTTPS.")
    if any(char.isdigit() for char in host):
        flags.append("The domain contains numbers, which is common in lookalike domains.")
    if host.count(".") >= 3:
        flags.append("The domain has many subdomains.")
    if "@" in url:
        flags.append("The URL contains '@', which can hide the true destination.")
    if any(word in full for word in SUSPICIOUS_KEYWORDS):
        flags.append("The URL uses urgency or login-related keywords.")
    if "-" in host:
        flags.append("The domain contains hyphens, which can indicate impersonation.")
    if registered_domain.split(".")[-1] in SUSPICIOUS_TLDS:
        flags.append("The top-level domain is commonly seen in phishing campaigns.")
    if host in SHORTENED_DOMAINS:
        flags.append("The link uses a URL shortener, which hides the destination.")

    flags.extend(detect_brand_impersonation(host))
    return flags


def risk_score_from_rules(url: str) -> dict[str, object]:
    parsed = parse_url(url)
    host = parsed["host"]
    registered_domain = get_registered_domain(host)
    normalized_host = normalize_host(host)
    flags = rule_based_flags(url)
    score = 8

    if parsed["scheme"] != "https":
        score += 18
    if any(char.isdigit() for char in host):
        score += 14
    if host.count(".") >= 3:
        score += 16
    if "@" in url:
        score += 25
    if "-" in host:
        score += 10
    if any(word in parsed["full"] for word in SUSPICIOUS_KEYWORDS):
        score += 14
    if registered_domain.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 18
    if host in SHORTENED_DOMAINS:
        score += 12

    impersonation_hits = detect_brand_impersonation(host)
    if impersonation_hits:
        score += 28

    if registered_domain in TRUSTED_DOMAINS or host in TRUSTED_DOMAINS:
        score -= 24

    if normalized_host == "google.com" and host != "google.com":
        score += 24
    if normalized_host == "paypal.com" and host != "paypal.com":
        score += 24

    score = max(1, min(score, 99))
    return {"score": score, "flags": flags}


def classify_risk(score: float) -> tuple[str, str]:
    if score >= 85:
        return "Critical risk", "Avoid immediately"
    if score >= 65:
        return "High risk", "Very likely phishing"
    if score >= 40:
        return "Medium risk", "Needs manual verification"
    return "Low risk", "Likely legitimate"


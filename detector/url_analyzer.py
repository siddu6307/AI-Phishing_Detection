"""Rule-based URL checks. Returns a score (0-100) and the reasons behind it."""
import ipaddress
import re
from urllib.parse import urlparse

# brand keyword -> its real domains
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga",
                   "work", "support", "country", "buzz", "rest", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rb.gy"}
KEYWORDS = ("login", "signin", "verify", "secure", "update", "account",
            "confirm", "password", "banking", "wallet")

# turns look-alike characters back into letters: paypa1 -> paypal
LEET = str.maketrans("013458$@", "oleasbsa")


def registered_domain(host):
    labels = host.lower().strip(".").split(".")
    if (len(labels) >= 3 and len(labels[-1]) == 2
            and labels[-2] in {"co", "com", "org", "net", "gov", "ac"}):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)", host))


def analyze_url(url):
    url = url.strip()
    score, reasons = 0, []

    def flag(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    had_scheme = "://" in url
    try:
        parsed = urlparse(url if had_scheme else "http://" + url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        host, port, parsed = "", None, None

    if not host:
        flag(30, "Could not read a valid web address")
        return {"url": url, "host": "", "score": score, "reasons": reasons}

    reg = registered_domain(host)
    labels = host.split(".")

    if _is_ip(host):
        flag(40, "Uses an IP address instead of a domain name")
    else:
        # brand impersonation (paypa1-login.com, paypal.com.evil.xyz ...)
        normalized = host.translate(LEET)
        tokens = [t for lab in normalized.split(".") for t in lab.split("-")]
        for brand, official in BRANDS.items():
            if reg in official:
                continue
            if any(t == brand or t.startswith(brand) for t in tokens):
                flag(35, f"Looks like it is pretending to be {brand.title()}")
                break

        if "xn--" in host:
            flag(25, "Uses punycode (can hide look-alike characters)")
        if labels[-1] in SUSPICIOUS_TLDS:
            flag(15, f"Uses a risky domain ending (.{labels[-1]})")
        if host in SHORTENERS or reg in SHORTENERS:
            flag(25, "Shortened link hides the real destination")
        if len(labels) - len(reg.split(".")) >= 3:
            flag(10, "Has too many subdomains")
        if reg.split(".")[0].count("-") >= 2:
            flag(10, "Domain has several hyphens")

    if "@" in parsed.netloc:
        flag(30, "Contains '@' which hides the real destination")
    if had_scheme and parsed.scheme == "http":
        flag(10, "Does not use HTTPS")
    if port not in (None, 80, 443):
        flag(10, f"Uses an unusual port ({port})")
    if len(url) > 75:
        flag(10, "Very long URL")

    haystack = (host + parsed.path + parsed.query).lower()
    found = [k for k in KEYWORDS if k in haystack]
    if found:
        flag(10, "Contains sensitive words: " + ", ".join(found[:3]))

    return {"url": url, "host": host, "score": min(score, 100), "reasons": reasons}

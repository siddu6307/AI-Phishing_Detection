"""Turns raw check results into Low / Medium / High with advice."""
import re

from config import ADVICE, LOW_MAX, MEDIUM_MAX
from .email_checker import analyze_email
from .url_analyzer import analyze_url


def risk_level(score):
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def _result(kind, score, reasons, links=None):
    level = risk_level(score)
    return {
        "type": kind,
        "score": score,
        "level": level,
        "advice": ADVICE[level],
        "reasons": reasons or ["No obvious warning signs found"],
        "links": links or [],
    }


def check_link(url):
    r = analyze_url(url)
    return _result("link", r["score"], r["reasons"])


def check_email(raw):
    e = analyze_email(raw)
    reasons = list(e["reasons"])
    for link in e["links"]:
        if link["score"] >= 25:
            reasons += [f"Link {link['host']}: {why}" for why in link["reasons"]]
    total = min(100, e["score"] + e["max_link_score"])
    return _result("email", total, reasons, e["links"])


def check(content):
    """Single word with no spaces -> link, anything else -> email."""
    text = content.strip()
    return check_link(text) if re.fullmatch(r"\S+", text) else check_email(text)

"""Email checks: sender, headers, wording, attachments and the links inside."""
import re
from email import message_from_string
from email.utils import parseaddr
from urllib.parse import urlparse

from .url_analyzer import BRANDS, LEET, analyze_url, registered_domain

URGENCY = ("urgent", "immediately", "act now", "within 24 hours", "suspended",
           "verify your account", "final notice", "limited time",
           "unusual activity", "will be closed", "expires", "account locked")
CREDENTIALS = re.compile(
    r"\b(password|pin|otp|cvv|ssn|social security|card number|bank account|"
    r"login details|credentials|confirm your identity)\b", re.I)
GREETINGS = ("dear customer", "dear user", "dear member",
             "dear account holder", "dear valued")
DANGEROUS_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar",
                 ".iso", ".lnk", ".docm", ".xlsm", ".html", ".htm")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
ANCHOR_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
HEADER_START = re.compile(
    r"\s*(from|to|subject|received|return-path|message-id|date|mime-version|"
    r"reply-to|authentication-results):", re.I)


def _parse(raw):
    """Return (headers_msg_or_None, text_parts, html_parts, attachment_names)."""
    if not HEADER_START.match(raw):
        return None, [raw], ([raw] if "<a " in raw.lower() else []), []
    msg = message_from_string(raw)
    texts, htmls, files = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_filename():
            files.append(part.get_filename())
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        ctype = part.get_content_type()
        if ctype == "text/html":
            htmls.append(text)
        elif ctype == "text/plain":
            texts.append(text)
    return msg, texts, htmls, files


def _anchor_mismatch(htmls):
    for html in htmls:
        for href, label in ANCHOR_RE.findall(html):
            label = re.sub(r"<[^>]+>", "", label).strip()
            m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", label, re.I)
            if m and href.lower().startswith("http"):
                shown = registered_domain(m.group(1))
                real = registered_domain(urlparse(href).hostname or "")
                if shown != real:
                    return shown, real
    return None


def analyze_email(raw):
    score, reasons = 0, []

    def flag(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    msg, texts, htmls, files = _parse(raw.strip())
    subject = str(msg.get("Subject", "")) if msg else ""

    if msg:
        name, addr = parseaddr(str(msg.get("From", "")))
        domain = addr.rpartition("@")[2].lower()
        if domain:
            reg = registered_domain(domain)
            m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
            if m and registered_domain(m.group(1)) != reg:
                flag(30, "Sender name shows one email address but the real one is different")
            norm_name = name.lower().translate(LEET)
            for brand, official in BRANDS.items():
                if brand in norm_name and reg not in official:
                    flag(35, f'Sender claims to be "{name}" but the email comes from {domain}')
                    break
            reply = parseaddr(str(msg.get("Reply-To", "")))[1].rpartition("@")[2].lower()
            if reply and registered_domain(reply) != reg:
                flag(20, f"Replies go to a different domain ({reply})")

        auth = " ".join(str(v) for k, v in msg.items()
                        if k.lower() == "authentication-results")
        failed = {k for k in ("spf", "dkim", "dmarc")
                  if re.search(rf"\b{k}=(fail|softfail)", auth, re.I)}
        if re.match(r"\s*(fail|softfail)\b", str(msg.get("Received-SPF", "")), re.I):
            failed.add("spf")
        for key, pts in (("spf", 20), ("dkim", 15), ("dmarc", 25)):
            if key in failed:
                flag(pts, f"{key.upper()} check failed - the sender may be spoofed")

    body = " ".join(texts + [re.sub(r"<[^>]+>", " ", h) for h in htmls])
    text_all = (subject + " " + body).lower()

    hits = [w for w in URGENCY if w in text_all]
    if hits:
        flag(8 if len(hits) == 1 else 15 if len(hits) == 2 else 20,
             "Pressure/urgent wording: " + ", ".join(hits[:3]))
    if CREDENTIALS.search(text_all):
        flag(20, "Asks for passwords, codes or payment details")
    if any(g in text_all[:400] for g in GREETINGS):
        flag(8, "Generic greeting instead of your name")
    for f in files:
        if f.lower().endswith(DANGEROUS_EXT):
            flag(30, f"Risky attachment type: {f}")
            break
    mismatch = _anchor_mismatch(htmls)
    if mismatch:
        flag(30, f"A link shows {mismatch[0]} but really goes to {mismatch[1]}")

    urls = []
    for chunk in texts + htmls:
        for u in URL_RE.findall(chunk):
            u = u.rstrip(".,;:!?)\"'")
            if u not in urls:
                urls.append(u)
    links = [analyze_url(u) for u in urls[:20]]

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "links": links,
        "max_link_score": max((l["score"] for l in links), default=0),
    }

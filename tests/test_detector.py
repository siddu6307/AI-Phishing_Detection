import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector import check

PHISH_EMAIL = """From: "PayPal Support" <security@paypa1-alerts.xyz>
Reply-To: help@collect-data.top
Subject: Urgent: account suspended
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<p>Dear customer, verify your account immediately and confirm your password.</p>
<a href="http://paypa1-alerts.xyz/login">www.paypal.com</a>
"""

GOOD_EMAIL = """From: Alice <alice@example.com>
Subject: Lunch tomorrow?

Hi Sam, here is the menu: https://example.com/menu
"""

CASES = [
    ("https://www.google.com", "Low"),
    ("https://bit.ly/abc123", "Medium"),
    ("http://paypa1-secure-login.xyz/verify", "High"),
    ("http://192.168.1.5/login", "High"),
    (PHISH_EMAIL, "High"),
    (GOOD_EMAIL, "Low"),
]

for content, expected in CASES:
    r = check(content)
    status = "OK  " if r["level"] == expected else "FAIL"
    print(f"{status} {r['level']:<6} {r['score']:>3}  {content.strip().splitlines()[0][:45]}")
    for why in r["reasons"]:
        print("       -", why)
    assert r["level"] == expected
print("\nAll tests passed")

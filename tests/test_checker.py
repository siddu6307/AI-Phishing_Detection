import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app


def post(client, url, **data):
    client.get("/login")
    with client.session_transaction() as s:
        data["csrf_token"] = s["csrf_token"]
    return client.post(url, data=data)


def new_user(app, email):
    c = app.test_client()
    post(c, "/signup", email=email, password="password1", confirm="password1")
    post(c, "/login", email=email, password="password1")
    return c


fd, path = tempfile.mkstemp(suffix=".db")
os.close(fd)
app = create_app(database=path)
u1, u2 = new_user(app, "one@x.com"), new_user(app, "two@x.com")

# bad input
assert b"Paste a link" in post(u1, "/dashboard", kind="link", content="  ").data
assert b"one link only" in post(u1, "/dashboard", kind="link", content="a.com b.com").data

# phishing link -> High
r = post(u1, "/dashboard", kind="link", content="http://paypa1-secure-login.xyz/verify")
assert r.status_code == 302 and r.headers["Location"].endswith("/result/1")
page = u1.get("/result/1").data
assert b"High risk" in page and b"Don&#39;t open" in page

# good link -> Low, email -> works and lists links as plain text
assert b"Low risk" in u1.get(post(u1, "/dashboard", kind="link", content="https://www.google.com").headers["Location"]).data
mail = "From: Bad <x@paypa1-help.xyz>\nSubject: Urgent\n\nVerify your password at http://paypa1-help.xyz/login now"
page = u1.get(post(u1, "/dashboard", kind="email", content=mail).headers["Location"]).data
assert b"High risk" in page and b"Links found" in page and b"<a href=\"http://paypa1" not in page

# history + privacy
assert u1.get("/history").data.count(b"View") == 3
assert u2.get("/result/1").status_code == 404
assert b"No checks yet" in u2.get("/history").data

# script in content is escaped
post(u2, "/dashboard", kind="email", content="<script>alert(1)</script> hello there")
assert b"<script>alert(1)</script>" not in u2.get("/result/4").data

# clear history only affects the current user
post(u1, "/history/clear")
assert b"No checks yet" in u1.get("/history").data
assert u2.get("/result/4").status_code == 200
os.remove(path)
print("All checker tests passed")

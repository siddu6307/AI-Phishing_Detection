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


fd, path = tempfile.mkstemp(suffix=".db")
os.close(fd)
app = create_app(database=path)
c = app.test_client()

assert c.get("/dashboard").status_code == 302                      # must log in first
assert c.post("/login", data={"email": "a@b.com", "password": "x"}).status_code == 400  # no CSRF token
r = post(c, "/signup", email="bad", password="password1", confirm="password1"); assert r.status_code == 200 and b"valid email" in r.data
r = post(c, "/signup", email="a@b.com", password="short", confirm="short"); assert b"at least 8" in r.data
r = post(c, "/signup", email="a@b.com", password="password1", confirm="nope"); assert b"do not match" in r.data
r = post(c, "/signup", email="A@b.com", password="password1", confirm="password1"); assert r.status_code == 302
r = post(c, "/signup", email="a@b.com", password="password1", confirm="password1"); assert b"already registered" in r.data
r = post(c, "/login", email="a@b.com", password="wrongpass"); assert b"Invalid email or password" in r.data
r = post(c, "/login", email="a@b.com", password="password1"); assert r.status_code == 302
r = c.get("/dashboard"); assert r.status_code == 200 and b"a@b.com" in r.data
r = post(c, "/logout"); assert r.status_code == 302
assert c.get("/dashboard").status_code == 302                      # logged out again
os.remove(path)
print("All auth tests passed")

# Phishing Checker

A Flask web app that checks links and emails for phishing signs and rates them
**Low** (safe to open), **Medium** (check the sender details first) or **High** (don't open).

## Features
- Sign up, log in and log out (hashed passwords, CSRF protection)
- Check a link or a full email (headers + body)
- Risk rating with the reasons behind it
- Per-user history of checked links and emails

## Run locally
```
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Tests
```
python tests/test_detector.py
python tests/test_auth.py
python tests/test_checker.py
```

## Project structure
- `detector/` - URL and email checks, risk scoring
- `auth/` - signup, login, logout
- `database/` - SQLite helpers
- `templates/`, `static/` - pages, styles, background image

## Note
This is a rule-based checker, so it can miss new phishing tricks. Use it as a helper, not a guarantee.
Set a real `SECRET_KEY` environment variable before deploying.

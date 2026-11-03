# Risk thresholds (score is 0-100)
LOW_MAX = 24      # 0-24   -> Low
MEDIUM_MAX = 54   # 25-54  -> Medium, 55+ -> High

ADVICE = {
    "Low": "Safe to open",
    "Medium": "Check the sender details first",
    "High": "Don't open",
}

# --- App settings ---
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")  # set a real one in production
DATABASE = os.path.join(BASE_DIR, "phishing_app.db")

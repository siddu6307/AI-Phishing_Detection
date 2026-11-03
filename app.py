import json
import secrets

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

import config
from auth.routes import auth_bp, login_required
from database.db import add_check, clear_checks, close_db, get_check, init_db, list_checks
from detector import check_email, check_link
from detector.scorer import risk_level

MAX_LEN = 20000


def _item(row):
    """Turn a history row into something the templates can show."""
    d = json.loads(row["reasons"])
    return {
        "id": row["id"], "type": row["type"], "content": row["content"],
        "level": row["risk_level"], "advice": config.ADVICE[row["risk_level"]],
        "score": d["score"], "reasons": d["reasons"], "links": d.get("links", []),
        "checked_at": row["checked_at"][:16],
    }


def create_app(database=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        DATABASE=database or config.DATABASE,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
    app.register_blueprint(auth_bp)

    @app.before_request
    def csrf_protect():
        token = session.get("csrf_token")
        if not token:
            token = session["csrf_token"] = secrets.token_hex(16)
            if request.method == "POST":
                abort(400)
        if request.method == "POST":
            if not secrets.compare_digest(request.form.get("csrf_token", ""), token):
                abort(400)

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": session.get("csrf_token", "")}

    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.route("/dashboard", methods=("GET", "POST"))
    @login_required
    def dashboard():
        kind, content = "link", ""
        if request.method == "POST":
            kind = request.form.get("kind", "link")
            content = request.form.get("content", "").strip()
            error = None
            if kind not in ("link", "email"):
                error = "Choose Link or Email."
            elif not content:
                error = "Paste a link or an email to check."
            elif len(content) > MAX_LEN:
                error = "That is too long. Please paste less than 20,000 characters."
            elif kind == "link" and len(content.split()) != 1:
                error = "Paste one link only (no spaces). To check a whole message, choose Email."

            if error:
                flash(error, "error")
            else:
                result = check_link(content) if kind == "link" else check_email(content)
                details = {
                    "score": result["score"],
                    "reasons": result["reasons"],
                    "links": [{"url": l["url"][:200], "host": l["host"], "score": l["score"],
                               "level": risk_level(l["score"])} for l in result["links"]],
                }
                check_id = add_check(g.user["id"], kind, content, result["level"], details)
                return redirect(url_for("result", check_id=check_id))
        return render_template("dashboard.html", kind=kind, content=content)

    @app.route("/result/<int:check_id>")
    @login_required
    def result(check_id):
        row = get_check(g.user["id"], check_id)
        if row is None:
            abort(404)
        return render_template("result.html", item=_item(row))

    @app.route("/history")
    @login_required
    def history():
        return render_template("history.html", items=[_item(r) for r in list_checks(g.user["id"])])

    @app.route("/history/clear", methods=("POST",))
    @login_required
    def history_clear():
        clear_checks(g.user["id"])
        flash("History cleared.", "success")
        return redirect(url_for("history"))

    return app


if __name__ == "__main__":
    create_app().run(debug=False)

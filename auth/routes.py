import re
import sqlite3
from functools import wraps

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import create_user, get_user_by_email, get_user_by_id

auth_bp = Blueprint("auth", __name__)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.before_app_request
def load_user():
    user_id = session.get("user_id")
    g.user = get_user_by_id(user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/signup", methods=("GET", "POST"))
def signup():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not EMAIL_RE.match(email) or len(email) > 254:
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif get_user_by_email(email):
            error = "That email is already registered."

        if not error:
            try:
                create_user(email, generate_password_hash(password))
            except sqlite3.IntegrityError:
                error = "That email is already registered."
        if error:
            flash(error, "error")
        else:
            flash("Account created. Please log in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("signup.html")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_user_by_email(email)
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "error")
        else:
            session.clear()                 # new session on login
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@auth_bp.route("/logout", methods=("POST",))
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))

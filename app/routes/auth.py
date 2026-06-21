from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from functools import wraps
from ..models.database import db, User

auth_bp = Blueprint("auth", __name__)


# ── login_required decorator for view routes ──
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # If it's a JSON/API request, return a JSON error
            if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.path in ('/start-scan', '/stop-scan') or '/scan-status/' in request.path:
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            flash("Please sign in to access SQLGuard.", "error")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("main.dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@auth_bp.route("/signup", methods=["POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not username or not password or not confirm_password:
        flash("All fields are required.", "error")
        return redirect(url_for("auth.login"))

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("auth.login"))

    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for("auth.login"))

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Username is already taken.", "error")
        return redirect(url_for("auth.login"))

    try:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        session["user_id"] = user.id
        session["username"] = user.username
        flash("Account created successfully!", "success")
        return redirect(url_for("main.dashboard"))
    except Exception:
        db.session.rollback()
        flash("An error occurred while creating your account. Please try again.", "error")
        return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))

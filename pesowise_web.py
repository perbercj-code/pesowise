import os
from datetime import date, timedelta
from pathlib import Path
import re
import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-local-demo-secret"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB_PATH = Path(__file__).with_name("pesowise.db")

NEED_CATEGORIES = {
    "Food", "Transportation", "School Supplies", "School Projects",
    "Medicine", "Other Needs"
}
WANT_CATEGORIES = {
    "Entertainment", "Shopping", "Games", "Eating Out",
    "Subscriptions", "Other Wants"
}
CATEGORIES = sorted(NEED_CATEGORIES | WANT_CATEGORIES)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def normalise_email(email):
    return (email or "").strip().lower()


def user_to_dict(user_row):
    if user_row is None:
        return None
    return {
        "id": user_row["id"],
        "name": user_row["name"],
        "email": user_row["email"],
        "allowance": float(user_row["daily_allowance"] or 0),
    }


def get_user_by_email(email):
    email = normalise_email(email)
    if not email:
        return None
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    return row

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                daily_allowance REAL NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                amount REAL NOT NULL CHECK (amount > 0),
                category TEXT NOT NULL,
                expense_type TEXT NOT NULL,
                expense_date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS savings_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                target REAL NOT NULL CHECK (target > 0),
                saved REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def expense_to_dict(expense_row):
    if expense_row is None:
        return None
    expense_type = expense_row["expense_type"]
    return {
        "id": expense_row["id"],
        "description": expense_row["description"],
        "amount": float(expense_row["amount"] or 0),
        "category": expense_row["category"],
        "type": expense_type,
        "date": expense_row["expense_date"],
    }


def goal_to_dict(goal_row):
    if goal_row is None:
        return None
    return {
        "id": goal_row["id"],
        "name": goal_row["name"],
        "target": float(goal_row["target"] or 0),
        "saved": float(goal_row["saved"] or 0),
    }


def get_dashboard_payload(user_id):
    with get_db() as db:
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        expenses = db.execute(
            "SELECT * FROM expenses WHERE user_id = ? ORDER BY expense_date DESC, id DESC",
            (user_id,),
        ).fetchall()
        goals = db.execute(
            "SELECT * FROM savings_goals WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()

    return {
        "allowance": float(user_row["daily_allowance"] or 0),
        "expenses": [expense_to_dict(item) for item in expenses],
        "goals": [goal_to_dict(item) for item in goals],
    }


def get_owned_expense(user_id, expense_id):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, user_id),
        ).fetchone()


def get_owned_goal(user_id, goal_id):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM savings_goals WHERE id = ? AND user_id = ?",
            (goal_id, user_id),
        ).fetchone()


init_db()

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def api_register():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    email = normalise_email(payload.get("email"))
    password = (payload.get("password") or "").strip()
    confirm_password = (payload.get("confirmPassword") or "").strip()
    allowance = float(payload.get("allowance") or 0)

    if not name or len(name) < 2:
        return jsonify({"error": "Please enter your full name."}), 400
    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match. Please confirm your password."}), 400
    if allowance < 0:
        return jsonify({"error": "Allowance cannot be negative."}), 400

    if get_user_by_email(email):
        return jsonify({"error": "An account with this email already exists."}), 409

    hashed_password = generate_password_hash(password)
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO users (name, email, password, daily_allowance) VALUES (?, ?, ?, ?)",
            (name, email, hashed_password, allowance),
        )
        user_id = cursor.lastrowid

    session["user_id"] = user_id
    user = get_user_by_email(email)
    return jsonify({"message": "Account created successfully.", "user": user_to_dict(user)}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    email = normalise_email(payload.get("email"))
    password = payload.get("password") or ""

    user = get_user_by_email(email)
    if user is None or not check_password_hash(user["password"], password):
        return jsonify({"error": "No account found for this email or the password is incorrect."}), 401

    session["user_id"] = user["id"]
    return jsonify({"message": "Login successful.", "user": user_to_dict(user)}), 200


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    payload = request.get_json(silent=True) or {}
    email = normalise_email(payload.get("email"))
    current_password = (payload.get("currentPassword") or "").strip()
    new_password = (payload.get("newPassword") or "").strip()
    confirm_password = (payload.get("confirmPassword") or "").strip()

    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    if not current_password:
        return jsonify({"error": "Current password is required to verify that you own this account before changing it."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match. Please re-enter them."}), 400

    user = get_user_by_email(email)
    if user is None:
        return jsonify({"error": "No account exists for that email."}), 404

    if session.get("user_id") and session["user_id"] != user["id"]:
        return jsonify({"error": "This session is not authorized to change this account."}), 403

    if not check_password_hash(user["password"], current_password):
        return jsonify({"error": "Current password is incorrect. Please verify your identity before resetting the password."}), 401

    with get_db() as db:
        db.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )

    return jsonify({"message": "Password reset successful."}), 200


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    payload = get_dashboard_payload(user["id"])
    return jsonify({
        "allowance": payload["allowance"],
        "expenses": payload["expenses"],
        "goals": payload["goals"],
        "user": user_to_dict(user),
    }), 200


@app.route("/api/allowance", methods=["PUT"])
def api_update_allowance():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    payload = request.get_json(silent=True) or {}
    allowance = float(payload.get("allowance") or 0)
    if allowance < 0:
        return jsonify({"error": "Allowance cannot be negative."}), 400

    with get_db() as db:
        db.execute(
            "UPDATE users SET daily_allowance = ? WHERE id = ?",
            (allowance, user["id"]),
        )

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 200


@app.route("/api/expenses", methods=["POST"])
def api_add_expense():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    payload = request.get_json(silent=True) or {}
    description = (payload.get("description") or "").strip()
    amount = float(payload.get("amount") or 0)
    category = (payload.get("category") or "").strip()
    date_value = (payload.get("date") or date.today().isoformat()).strip()

    if not description:
        return jsonify({"error": "Expense description is required."}), 400
    if amount <= 0:
        return jsonify({"error": "Expense amount must be greater than zero."}), 400
    if not category:
        return jsonify({"error": "Expense category is required."}), 400

    expense_type = "Need" if category in NEED_CATEGORIES else "Want"
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO expenses (user_id, description, amount, category, expense_type, expense_date) VALUES (?, ?, ?, ?, ?, ?)",
            (user["id"], description, amount, category, expense_type, date_value),
        )
        created_id = cursor.lastrowid
        created_row = db.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (created_id, user["id"]),
        ).fetchone()

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "expense": expense_to_dict(created_row),
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 201


@app.route("/api/expenses/<int:expense_id>", methods=["PUT", "DELETE"])
def api_manage_expense(expense_id):
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    existing = get_owned_expense(user["id"], expense_id)
    if existing is None:
        return jsonify({"error": "Expense not found."}), 404

    if request.method == "DELETE":
        with get_db() as db:
            db.execute("DELETE FROM expenses WHERE id = ? AND user_id = ?", (expense_id, user["id"]))
        dashboard = get_dashboard_payload(user["id"])
        return jsonify({
            "allowance": dashboard["allowance"],
            "expenses": dashboard["expenses"],
            "goals": dashboard["goals"],
        }), 200

    payload = request.get_json(silent=True) or {}
    description = (payload.get("description") or existing["description"]).strip()
    amount = float(payload.get("amount") or existing["amount"])
    category = (payload.get("category") or existing["category"]).strip()
    date_value = (payload.get("date") or existing["expense_date"]).strip()

    if not description:
        return jsonify({"error": "Expense description is required."}), 400
    if amount <= 0:
        return jsonify({"error": "Expense amount must be greater than zero."}), 400
    if not category:
        return jsonify({"error": "Expense category is required."}), 400

    expense_type = "Need" if category in NEED_CATEGORIES else "Want"
    with get_db() as db:
        db.execute(
            "UPDATE expenses SET description = ?, amount = ?, category = ?, expense_type = ?, expense_date = ? WHERE id = ? AND user_id = ?",
            (description, amount, category, expense_type, date_value, expense_id, user["id"]),
        )
        updated = db.execute(
            "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
            (expense_id, user["id"]),
        ).fetchone()

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "expense": expense_to_dict(updated),
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 200


@app.route("/api/goals", methods=["GET", "POST"])
def api_manage_goals():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    if request.method == "GET":
        dashboard = get_dashboard_payload(user["id"])
        return jsonify({
            "allowance": dashboard["allowance"],
            "expenses": dashboard["expenses"],
            "goals": dashboard["goals"],
        }), 200

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    target = float(payload.get("target") or 0)
    saved = float(payload.get("saved") or 0)

    if not name:
        return jsonify({"error": "Goal name is required."}), 400
    if target <= 0:
        return jsonify({"error": "Goal target must be greater than zero."}), 400
    if saved < 0:
        return jsonify({"error": "Saved amount cannot be negative."}), 400
    if saved > target:
        return jsonify({"error": "Saved amount cannot exceed the target."}), 400

    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO savings_goals (user_id, name, target, saved) VALUES (?, ?, ?, ?)",
            (user["id"], name, target, saved),
        )
        created_id = cursor.lastrowid
        created_goal = db.execute(
            "SELECT * FROM savings_goals WHERE id = ? AND user_id = ?",
            (created_id, user["id"]),
        ).fetchone()

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "goal": goal_to_dict(created_goal),
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 201


@app.route("/api/goals/<int:goal_id>", methods=["PUT", "DELETE"])
def api_manage_goal(goal_id):
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    existing = get_owned_goal(user["id"], goal_id)
    if existing is None:
        return jsonify({"error": "Savings goal not found."}), 404

    if request.method == "DELETE":
        with get_db() as db:
            db.execute("DELETE FROM savings_goals WHERE id = ? AND user_id = ?", (goal_id, user["id"]))
        dashboard = get_dashboard_payload(user["id"])
        return jsonify({
            "allowance": dashboard["allowance"],
            "expenses": dashboard["expenses"],
            "goals": dashboard["goals"],
        }), 200

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or existing["name"]).strip()
    target = float(payload.get("target") or existing["target"])
    saved = float(payload.get("saved") or existing["saved"])

    if not name:
        return jsonify({"error": "Goal name is required."}), 400
    if target <= 0:
        return jsonify({"error": "Goal target must be greater than zero."}), 400
    if saved < 0:
        return jsonify({"error": "Saved amount cannot be negative."}), 400
    if saved > target:
        return jsonify({"error": "Saved amount cannot exceed the target."}), 400

    with get_db() as db:
        db.execute(
            "UPDATE savings_goals SET name = ?, target = ?, saved = ? WHERE id = ? AND user_id = ?",
            (name, target, saved, goal_id, user["id"]),
        )
        updated = db.execute(
            "SELECT * FROM savings_goals WHERE id = ? AND user_id = ?",
            (goal_id, user["id"]),
        ).fetchone()

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "goal": goal_to_dict(updated),
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 200


@app.route("/api/goals/<int:goal_id>/contribute", methods=["POST"])
def api_contribute_goal(goal_id):
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated."}), 401

    goal = get_owned_goal(user["id"], goal_id)
    if goal is None:
        return jsonify({"error": "Savings goal not found."}), 404

    payload = request.get_json(silent=True) or {}
    contribution = float(payload.get("amount") or 0)
    if contribution <= 0:
        return jsonify({"error": "Contribution amount must be greater than zero."}), 400

    new_saved = min(float(goal["target"]), float(goal["saved"]) + contribution)
    with get_db() as db:
        db.execute(
            "UPDATE savings_goals SET saved = ? WHERE id = ? AND user_id = ?",
            (new_saved, goal_id, user["id"]),
        )
        updated = db.execute(
            "SELECT * FROM savings_goals WHERE id = ? AND user_id = ?",
            (goal_id, user["id"]),
        ).fetchone()

    dashboard = get_dashboard_payload(user["id"])
    return jsonify({
        "goal": goal_to_dict(updated),
        "allowance": dashboard["allowance"],
        "expenses": dashboard["expenses"],
        "goals": dashboard["goals"],
    }), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out successfully."}), 200


@app.route("/api/me", methods=["GET"])
def api_me():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"user": None}), 401

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify({"user": user_to_dict(user)}), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        use_reloader=False,
    )
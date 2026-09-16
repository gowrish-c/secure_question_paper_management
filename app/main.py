from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
from datetime import datetime, timezone
import os
import re
import secrets
import hashlib
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "demo-secret-change-me")

# -------------------------------------------------
# Tier 4: KMS / Encryption
# -------------------------------------------------
# IMPORTANT:
# We do NOT write a key file when deployed on Vercel.
# Vercel serverless functions should not depend on writing
# files into the project directory.
configured_key = os.environ.get("ENCRYPTION_KEY")

if configured_key:
    try:
        FERNET = Fernet(configured_key.encode())
    except Exception:
        FERNET = Fernet(Fernet.generate_key())
else:
    # Good enough for an academic demo.
    # For production, set ENCRYPTION_KEY in Vercel Environment Variables.
    FERNET = Fernet(Fernet.generate_key())


def encrypt_text(text):
    return FERNET.encrypt(text.encode()).decode()


def decrypt_text(text):
    try:
        return FERNET.decrypt(text.encode()).decode()
    except InvalidToken:
        return "[Unable to decrypt]"


# -------------------------------------------------
# Tier 2: WAF
# -------------------------------------------------
def waf_check(value, max_length=3000):
    if value is None or len(value) > max_length:
        return False

    blocked = [
        r"<script\b",
        r"javascript:",
        r"\bonerror\s*=",
        r"\bunion\s+select\b",
        r"\bdrop\s+table\b",
    ]

    return not any(re.search(pattern, value, re.IGNORECASE) for pattern in blocked)


# -------------------------------------------------
# Tier 3: Sharding
# -------------------------------------------------
# Simple in-memory encrypted shards.
# This keeps the project compatible with Vercel's
# serverless environment.
SHARDS = [[], []]


def choose_shard(subject):
    digest = hashlib.sha256(subject.lower().encode()).hexdigest()
    return int(digest[:8], 16) % 2


def get_questions():
    result = []

    for shard_number, shard in enumerate(SHARDS, start=1):
        for item in shard:
            result.append({
                "id": item["id"],
                "subject": item["subject"],
                "difficulty": item["difficulty"],
                "question": decrypt_text(item["question"]),
                "answer": decrypt_text(item["answer"]),
                "shard": shard_number,
                "created_at": item["created_at"]
            })

    return sorted(result, key=lambda x: x["id"], reverse=True)


# -------------------------------------------------
# Tier 5: Immutable-style audit log
# -------------------------------------------------
AUDIT_LOG = []


def audit(action, user="anonymous", details=""):
    AUDIT_LOG.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "details": details
    })


# -------------------------------------------------
# Tier 1: Authentication + MFA
# -------------------------------------------------
USERS = {
    "setter": {
        "password": "setter123",
        "role": "Question Setter"
    },
    "admin": {
        "password": "admin123",
        "role": "Administrator"
    }
}


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))

            if session.get("role") not in roles:
                flash("You do not have permission for this operation.", "error")
                return redirect(url_for("dashboard"))

            return function(*args, **kwargs)

        return wrapper

    return decorator


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)

        if not user or user["password"] != password:
            audit("LOGIN_FAILED", username, "Invalid credentials")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        otp = f"{secrets.randbelow(1000000):06d}"

        session["pending_user"] = username
        session["pending_otp"] = otp

        # In a real system, OTP would be sent by an MFA provider.
        # For this student project, display it on the MFA page.
        audit("MFA_REQUESTED", username, "Demo OTP generated")

        return render_template("mfa.html", demo_otp=otp)

    return render_template("login.html")


@app.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    username = session.get("pending_user")
    otp = request.form.get("otp", "").strip()

    if not username:
        return redirect(url_for("login"))

    if otp != session.get("pending_otp"):
        audit("MFA_FAILED", username, "Invalid OTP")
        flash("Invalid OTP.", "error")
        return render_template("mfa.html", demo_otp=session.get("pending_otp"))

    session["username"] = username
    session["role"] = USERS[username]["role"]

    session.pop("pending_user", None)
    session.pop("pending_otp", None)

    audit("LOGIN_SUCCESS", username, "MFA verified")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    audit("LOGOUT", username, "User logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        questions=get_questions(),
        logs=list(reversed(AUDIT_LOG[-10:])),
        username=session["username"],
        role=session["role"]
    )


@app.route("/questions/add", methods=["POST"])
@role_required("Question Setter", "Administrator")
def add_question():
    subject = request.form.get("subject", "").strip()
    difficulty = request.form.get("difficulty", "").strip()
    question = request.form.get("question", "").strip()
    answer = request.form.get("answer", "").strip()

    values = [subject, difficulty, question, answer]

    if not all(values):
        flash("Please fill all fields.", "error")
        return redirect(url_for("dashboard"))

    if not all(waf_check(value) for value in values):
        audit("WAF_BLOCK", session["username"], "Unsafe input blocked")
        flash("Input blocked by WAF.", "error")
        return redirect(url_for("dashboard"))

    all_ids = [item["id"] for shard in SHARDS for item in shard]
    new_id = max(all_ids, default=0) + 1

    shard_index = choose_shard(subject)

    SHARDS[shard_index].append({
        "id": new_id,
        "subject": subject,
        "difficulty": difficulty,
        "question": encrypt_text(question),
        "answer": encrypt_text(answer),
        "created_at": datetime.now(timezone.utc).isoformat()
    })

    audit(
        "QUESTION_CREATED",
        session["username"],
        f"Question {new_id} stored in encrypted shard {shard_index + 1}"
    )

    flash(
        f"Question added successfully to encrypted shard {shard_index + 1}.",
        "success"
    )

    return redirect(url_for("dashboard"))


@app.route("/questions/delete/<int:question_id>", methods=["POST"])
@role_required("Administrator")
def delete_question(question_id):
    for shard_index in range(len(SHARDS)):
        old_length = len(SHARDS[shard_index])

        SHARDS[shard_index][:] = [
            item for item in SHARDS[shard_index]
            if item["id"] != question_id
        ]

        if len(SHARDS[shard_index]) < old_length:
            audit(
                "QUESTION_DELETED",
                session["username"],
                f"Question {question_id} deleted"
            )
            flash("Question deleted.", "success")
            return redirect(url_for("dashboard"))

    flash("Question not found.", "error")
    return redirect(url_for("dashboard"))


# -------------------------------------------------
# Tier 2: API Gateway simulation
# -------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({
        "status": "running",
        "architecture": "5-tier secure question paper system",
        "waf": "active",
        "api_gateway": "active",
        "encryption": "active",
        "sharding": "active",
        "audit": "active"
    })


@app.route("/api/questions")
@login_required
def api_questions():
    audit("API_ACCESS", session["username"], "GET /api/questions")
    return jsonify(get_questions())


# -------------------------------------------------
# Tier 5: SIEM Dashboard
# -------------------------------------------------
@app.route("/siem")
@role_required("Administrator")
def siem():
    return render_template(
        "siem.html",
        logs=list(reversed(AUDIT_LOG))
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

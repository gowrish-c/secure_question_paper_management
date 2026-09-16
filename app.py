from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
from pathlib import Path
from datetime import datetime, timezone
import json, os, re, secrets, hashlib

from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

KEY_FILE = DATA_DIR / "kms.key"
SHARD_FILES = [DATA_DIR / "shard_1.json", DATA_DIR / "shard_2.json"]
AUDIT_FILE = DATA_DIR / "immutable_ledger.log"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-demo-secret-key")

# -----------------------------
# Tier 4: Cloud KMS simulation
# -----------------------------
def get_encryption_key():
    if not KEY_FILE.exists():
        KEY_FILE.write_bytes(Fernet.generate_key())
    return KEY_FILE.read_bytes()

fernet = Fernet(get_encryption_key())

# -----------------------------
# Tier 5: Immutable audit logs
# -----------------------------
def audit(action, user="anonymous", details=""):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "action": action,
        "details": details,
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

# -----------------------------
# Tier 2: WAF simulation
# -----------------------------
def waf_check(value, max_length=2000):
    if value is None:
        return False
    if len(value) > max_length:
        return False

    # Basic demo checks. This is NOT a replacement for a real WAF.
    blocked_patterns = [
        r"<script\b",
        r"javascript:",
        r"\bonerror\s*=",
        r"\bunion\s+select\b",
        r"\bdrop\s+table\b",
    ]
    return not any(re.search(p, value, re.IGNORECASE) for p in blocked_patterns)

def waf_required_fields(data):
    for value in data.values():
        if isinstance(value, str) and not waf_check(value):
            return False
    return True

# -----------------------------
# Tier 3: Sharding service
# -----------------------------
def choose_shard(subject):
    digest = hashlib.sha256(subject.lower().encode()).hexdigest()
    return 0 if int(digest[:8], 16) % 2 == 0 else 1

def load_shard(index):
    path = SHARD_FILES[index]
    if not path.exists():
        path.write_text("[]", encoding="utf-8")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

def save_shard(index, rows):
    SHARD_FILES[index].write_text(
        json.dumps(rows, indent=2),
        encoding="utf-8"
    )

# -----------------------------
# Dynamic encryption engine
# -----------------------------
def encrypt_text(value):
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")

def decrypt_text(value):
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[Unable to decrypt]"

def all_questions():
    questions = []
    for shard_index in range(len(SHARD_FILES)):
        for row in load_shard(shard_index):
            questions.append({
                "id": row["id"],
                "subject": row["subject"],
                "difficulty": row["difficulty"],
                "question": decrypt_text(row["question"]),
                "answer": decrypt_text(row["answer"]),
                "shard": shard_index + 1,
                "created_at": row["created_at"],
            })
    return sorted(questions, key=lambda x: x["id"], reverse=True)

# -----------------------------
# Authentication / MFA
# -----------------------------
USERS = {
    "setter": {"password": "setter123", "role": "Question Setter"},
    "admin": {"password": "admin123", "role": "Administrator"},
}

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("You do not have permission for this operation.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapper
    return decorator

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)
        if not user or user["password"] != password:
            audit("LOGIN_FAILED", username, "Invalid username or password")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # Simulated MFA: OTP is generated and shown in the terminal.
        otp = f"{secrets.randbelow(1000000):06d}"
        session["pending_user"] = username
        session["pending_otp"] = otp
        print(f"[DEMO MFA] OTP for {username}: {otp}")

        audit("MFA_REQUESTED", username, "Demo OTP generated")
        return redirect(url_for("verify_mfa"))

    return render_template("login.html")

@app.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        username = session.get("pending_user")

        if otp == session.get("pending_otp"):
            session["username"] = username
            session["role"] = USERS[username]["role"]
            session.pop("pending_user", None)
            session.pop("pending_otp", None)
            audit("LOGIN_SUCCESS", username, "MFA verified")
            return redirect(url_for("dashboard"))

        audit("MFA_FAILED", username, "Invalid OTP")
        flash("Invalid OTP. Check the terminal running Flask.", "error")

    return render_template("mfa.html")

@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    audit("LOGOUT", username, "User logged out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    questions = all_questions()
    logs = []
    if AUDIT_FILE.exists():
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-10:]
        for line in reversed(lines):
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return render_template(
        "dashboard.html",
        questions=questions,
        logs=logs,
        username=session["username"],
        role=session["role"],
    )

@app.route("/questions/add", methods=["POST"])
@role_required("Question Setter", "Administrator")
def add_question():
    data = {
        "subject": request.form.get("subject", "").strip(),
        "difficulty": request.form.get("difficulty", "").strip(),
        "question": request.form.get("question", "").strip(),
        "answer": request.form.get("answer", "").strip(),
    }

    if not waf_required_fields(data):
        audit("WAF_BLOCK", session["username"], "Potentially unsafe input blocked")
        flash("Input blocked by the demo WAF.", "error")
        return redirect(url_for("dashboard"))

    if not all(data.values()):
        flash("All question fields are required.", "error")
        return redirect(url_for("dashboard"))

    shard = choose_shard(data["subject"])
    rows = load_shard(shard)

    new_id = max([r["id"] for i in range(2) for r in load_shard(i)] or [0]) + 1

    rows.append({
        "id": new_id,
        "subject": data["subject"],
        "difficulty": data["difficulty"],
        "question": encrypt_text(data["question"]),
        "answer": encrypt_text(data["answer"]),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    save_shard(shard, rows)
    audit("QUESTION_CREATED", session["username"],
          f"Question {new_id} stored in encrypted shard {shard + 1}")
    flash(f"Question added successfully to encrypted shard {shard + 1}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/questions/delete/<int:question_id>", methods=["POST"])
@role_required("Administrator")
def delete_question(question_id):
    found = False
    for shard_index in range(2):
        rows = load_shard(shard_index)
        new_rows = [r for r in rows if r["id"] != question_id]
        if len(new_rows) != len(rows):
            save_shard(shard_index, new_rows)
            found = True
            break

    if found:
        audit("QUESTION_DELETED", session["username"], f"Question {question_id} deleted")
        flash("Question deleted.", "success")
    else:
        flash("Question not found.", "error")

    return redirect(url_for("dashboard"))

# -----------------------------
# Tier 2: API Gateway simulation
# -----------------------------
@app.route("/api/questions", methods=["GET"])
@login_required
def api_questions():
    audit("API_ACCESS", session["username"], "GET /api/questions")
    return jsonify(all_questions())

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "running",
        "security_layers": 5,
        "encrypted_shards": 2,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route("/siem")
@role_required("Administrator")
def siem():
    entries = []
    if AUDIT_FILE.exists():
        for line in AUDIT_FILE.read_text(encoding="utf-8").splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return render_template("siem.html", logs=list(reversed(entries)))

if __name__ == "__main__":
    print("Starting Secure Question Paper Management System")
    print("Demo accounts: setter / setter123 and admin / admin123")
    print("MFA OTP will be printed in this terminal after login.")
    app.run(host="0.0.0.0", port=5000, debug=True)

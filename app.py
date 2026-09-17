import os, sqlite3, secrets, string, hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "tefvx-secret-2026")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "tefvx@admin")
DB_PATH = os.environ.get("DB_PATH", "keys.db")

# ─── Banco de dados ───────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS license_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                duration_days INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                expires_at TEXT,
                device_id TEXT,
                status TEXT DEFAULT 'inactive',
                note TEXT
            )
        """)
        db.commit()

init_db()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def generate_key(prefix="TEFVX"):
    chars = string.ascii_uppercase + string.digits
    part = lambda n: ''.join(secrets.choice(chars) for _ in range(n))
    return f"{prefix}-{part(4)}-{part(4)}-{part(4)}"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── API endpoints ────────────────────────────────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip().upper()
    device_id = (data.get("device_id") or "").strip()

    if not key:
        return jsonify({"valid": False, "message": "Key inválida"}), 400

    with get_db() as db:
        row = db.execute("SELECT * FROM license_keys WHERE key = ?", (key,)).fetchone()

    if not row:
        return jsonify({"valid": False, "message": "Key não encontrada"}), 404

    if row["status"] == "revoked":
        return jsonify({"valid": False, "message": "Key revogada"}), 403

    now = datetime.utcnow()

    # Ativa se for a primeira vez
    if row["status"] == "inactive":
        expires = now + timedelta(days=row["duration_days"])
        with get_db() as db:
            db.execute("""
                UPDATE license_keys SET
                    status = 'active',
                    activated_at = ?,
                    expires_at = ?,
                    device_id = ?
                WHERE key = ?
            """, (now.isoformat(), expires.isoformat(), device_id, key))
            db.commit()
        return jsonify({
            "valid": True,
            "message": "Key ativada com sucesso!",
            "expires_at": expires.isoformat(),
            "days_remaining": row["duration_days"]
        })

    # Verifica expiração
    expires_at = datetime.fromisoformat(row["expires_at"])
    if now > expires_at:
        with get_db() as db:
            db.execute("UPDATE license_keys SET status = 'expired' WHERE key = ?", (key,))
            db.commit()
        return jsonify({"valid": False, "message": "Key expirada"}), 403

    days_remaining = (expires_at - now).days
    return jsonify({
        "valid": True,
        "message": "Key válida",
        "expires_at": row["expires_at"],
        "days_remaining": days_remaining
    })

# ─── Painel Admin ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Senha incorreta!")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        keys = db.execute("SELECT * FROM license_keys ORDER BY created_at DESC").fetchall()
    stats = {
        "total": len(keys),
        "active": sum(1 for k in keys if k["status"] == "active"),
        "inactive": sum(1 for k in keys if k["status"] == "inactive"),
        "expired": sum(1 for k in keys if k["status"] == "expired"),
        "revoked": sum(1 for k in keys if k["status"] == "revoked"),
    }
    return render_template("dashboard.html", keys=keys, stats=stats)

@app.route("/generate", methods=["POST"])
@login_required
def generate():
    duration = int(request.form.get("duration", 30))
    quantity = min(int(request.form.get("quantity", 1)), 100)
    note = request.form.get("note", "")
    now = datetime.utcnow().isoformat()

    with get_db() as db:
        for _ in range(quantity):
            key = generate_key()
            db.execute("""
                INSERT INTO license_keys (key, duration_days, created_at, status, note)
                VALUES (?, ?, ?, 'inactive', ?)
            """, (key, duration, now, note))
        db.commit()

    flash(f"{quantity} key(s) gerada(s) com sucesso!")
    return redirect(url_for("dashboard"))

@app.route("/revoke/<key>")
@login_required
def revoke(key):
    with get_db() as db:
        db.execute("UPDATE license_keys SET status = 'revoked' WHERE key = ?", (key,))
        db.commit()
    flash(f"Key {key} revogada!")
    return redirect(url_for("dashboard"))

@app.route("/delete/<key>")
@login_required
def delete(key):
    with get_db() as db:
        db.execute("DELETE FROM license_keys WHERE key = ?", (key,))
        db.commit()
    flash(f"Key {key} deletada!")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

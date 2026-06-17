from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, send_file, session
)
import sqlite3
import os
import csv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import StringIO, BytesIO
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Email config (replace with your Gmail and App Password)
GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")

print("Email loaded from .env")

app = Flask(__name__)
app.secret_key = "receiptkeeper_secret"

BASE_DIR = os.path.dirname(__file__)
DATABASE = os.path.join(BASE_DIR, "receipts.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
CATEGORIES = ["Food", "Transport", "School", "Data", "Shopping"]

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── DATABASE ──────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            date TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            image_path TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS budgets (
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            monthly_limit REAL NOT NULL,
            PRIMARY KEY (user_id, category),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
    conn.commit()
    conn.close()


init_db()


# ── AUTH HELPERS ──────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def current_user_id():
    return session.get("user_id")


# ── FILE HELPERS ──────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_image(file):
    if not file or file.filename == "":
        return None
    if not allowed_file(file.filename):
        return None
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{timestamp}_{secure_filename(file.filename)}"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return f"uploads/{filename}"


# ── DASHBOARD STATS ───────────────────────────────
def dashboard_stats(user_id):
    conn = get_db()
    total_receipts = conn.execute(
        "SELECT COUNT(*) FROM receipts WHERE user_id=?", (user_id,)).fetchone()[0]
    total_amount = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE user_id=?", (user_id,)).fetchone()[0]
    curr_month = datetime.now().strftime("%Y-%m")
    month_amount = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE user_id=? AND substr(date,1,7)=?", (user_id, curr_month)).fetchone()[0]
    conn.close()
    return {
        "total_receipts": total_receipts,
        "total_amount":   round(total_amount, 2),
        "month_amount":   round(month_amount, 2)
    }


# ── BUDGET DATA ───────────────────────────────────
def get_budget_data(user_id):
    conn = get_db()
    curr_month = datetime.now().strftime("%Y-%m")
    budgets = conn.execute(
        "SELECT * FROM budgets WHERE user_id=?", (user_id,)).fetchall()
    result = []
    for b in budgets:
        spent = float(conn.execute("SELECT COALESCE(SUM(amount),0) FROM receipts WHERE user_id=? AND category=? AND substr(date,1,7)=?",
                      (user_id, b["category"], curr_month)).fetchone()[0])
        limit = float(b["monthly_limit"])
        raw_percent = round((spent / limit) * 100, 1) if limit > 0 else 0
        status = "danger" if raw_percent >= 100 else "warning" if raw_percent >= 80 else "ok"
        result.append({
            "category":    b["category"],
            "spent":       round(spent, 2),
            "limit":       limit,
            "percent":     min(raw_percent, 100),
            "raw_percent": raw_percent,
            "status":      status
        })
    conn.close()
    return sorted(result, key=lambda x: x["raw_percent"], reverse=True)


# ── MONTHLY CHART ─────────────────────────────────
def monthly_chart_data(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT substr(date,1,7) as month, SUM(amount) as total FROM receipts WHERE user_id=? GROUP BY month ORDER BY month", (user_id,)).fetchall()
    conn.close()
    return [r["month"] for r in rows], [float(r["total"]) for r in rows]


# ── AUTH ROUTES ───────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm = request.form["confirm"]
        if not username or not password:
            flash("Username and password are required.", "over_budget")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "over_budget")
            return render_template("register.html")
        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            conn.close()
            flash("Username already taken.", "over_budget")
            return render_template("register.html")
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                     (username, generate_password_hash(password)))
        conn.commit()
        conn.close()
        flash("Account created! Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "over_budget")
            return render_template("login.html")
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── HOME ──────────────────────────────────────────
@app.route("/")
@login_required
def index():
    uid = current_user_id()
    search = request.args.get("search", "")
    category = request.args.get("category", "")
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")

    query = "SELECT * FROM receipts WHERE user_id=?"
    params = [uid]
    if search:
        query += " AND description LIKE ?"
        params.append(f"%{search}%")
    if category:
        query += " AND category=?"
        params.append(category)
    if start_date:
        query += " AND date>=?"
        params.append(start_date)
    if end_date:
        query += " AND date<=?"
        params.append(end_date)
    query += " ORDER BY date DESC"

    conn = get_db()
    receipts = conn.execute(query, params).fetchall()
    conn.close()

    labels, values = monthly_chart_data(uid)
    return render_template("index.html",
                           receipts=receipts,
                           stats=dashboard_stats(uid),
                           chart_labels=labels,
                           chart_values=values,
                           search=search, category=category,
                           start_date=start_date, end_date=end_date,
                           budget_data=get_budget_data(uid),
                           categories=CATEGORIES,
                           username=session.get("username")
                           )


# ── ADD RECEIPT ───────────────────────────────────
@app.route("/add", methods=["POST"])
@login_required
def add_receipt():
    uid = current_user_id()
    amount = float(request.form["amount"])
    date = request.form["date"]
    description = request.form["description"]
    category = request.form["category"]
    image_path = save_image(request.files.get("receipt_image"))

    conn = get_db()
    budget_row = conn.execute(
        "SELECT monthly_limit FROM budgets WHERE user_id=? AND category=?", (uid, category)).fetchone()
    if budget_row:
        spent = float(conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE user_id=? AND category=? AND substr(date,1,7)=?", (uid, category, date[:7])).fetchone()[0])
        new_total = spent + amount
        limit = float(budget_row["monthly_limit"])
        if new_total > limit:
            flash(
                f"⚠️ Over budget! {category} limit is ₦{limit:,.2f} but you've now spent ₦{new_total:,.2f} this month.", "over_budget")
        elif new_total / limit >= 0.8:
            flash(
                f"⚠️ Heads up! You've used {round((new_total/limit)*100)}% of your {category} budget.", "near_budget")

    conn.execute("INSERT INTO receipts (user_id, amount, date, description, category, image_path) VALUES (?,?,?,?,?,?)",
                 (uid, amount, date, description, category, image_path))
    conn.commit()
    conn.close()
    flash("Receipt added successfully")
    return redirect(url_for("index"))


# ── EDIT RECEIPT ──────────────────────────────────
@app.route("/edit/<int:receipt_id>", methods=["GET", "POST"])
@login_required
def edit_receipt(receipt_id):
    uid = current_user_id()
    conn = get_db()
    receipt = conn.execute(
        "SELECT * FROM receipts WHERE id=? AND user_id=?", (receipt_id, uid)).fetchone()
    if not receipt:
        conn.close()
        flash("Receipt not found.", "over_budget")
        return redirect(url_for("index"))
    if request.method == "POST":
        image_path = receipt["image_path"]
        image_file = request.files.get("receipt_image")
        if image_file and image_file.filename:
            new_image = save_image(image_file)
            if new_image:
                if image_path:
                    old = os.path.join(BASE_DIR, "static", image_path)
                    if os.path.exists(old):
                        os.remove(old)
                image_path = new_image
        conn.execute("UPDATE receipts SET amount=?,date=?,description=?,category=?,image_path=? WHERE id=? AND user_id=?",
                     (request.form["amount"], request.form["date"], request.form["description"], request.form["category"], image_path, receipt_id, uid))
        conn.commit()
        conn.close()
        flash("Receipt updated successfully")
        return redirect(url_for("index"))
    conn.close()
    return render_template("edit.html", receipt=receipt)


# ── DELETE RECEIPT ────────────────────────────────
@app.route("/delete/<int:receipt_id>")
@login_required
def delete_receipt(receipt_id):
    uid = current_user_id()
    conn = get_db()
    receipt = conn.execute(
        "SELECT * FROM receipts WHERE id=? AND user_id=?", (receipt_id, uid)).fetchone()
    if receipt:
        if receipt["image_path"]:
            f = os.path.join(BASE_DIR, "static", receipt["image_path"])
            if os.path.exists(f):
                os.remove(f)
        conn.execute(
            "DELETE FROM receipts WHERE id=? AND user_id=?", (receipt_id, uid))
        conn.commit()
    conn.close()
    flash("Receipt deleted")
    return redirect(url_for("index"))


# ── SET BUDGET ────────────────────────────────────
@app.route("/set-budget", methods=["POST"])
@login_required
def set_budget():
    uid = current_user_id()
    cat = request.form["category"]
    lim = request.form["monthly_limit"]
    conn = get_db()
    conn.execute("INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?,?,?) ON CONFLICT(user_id, category) DO UPDATE SET monthly_limit=excluded.monthly_limit", (uid, cat, lim))
    conn.commit()
    conn.close()
    flash(f"Budget for {cat} set to ₦{float(lim):,.2f}")
    return redirect(url_for("index"))


# ── REMOVE BUDGET ─────────────────────────────────
@app.route("/remove-budget/<category>")
@login_required
def remove_budget(category):
    uid = current_user_id()
    conn = get_db()
    conn.execute(
        "DELETE FROM budgets WHERE user_id=? AND category=?", (uid, category))
    conn.commit()
    conn.close()
    flash(f"Budget for {category} removed")
    return redirect(url_for("index"))


# ── SEND MONTHLY REPORT ───────────────────────────
@app.route("/send-report", methods=["POST"])
@login_required
def send_report():
    uid = current_user_id()
    to_email = request.form["email"].strip()
    curr_month = datetime.now().strftime("%Y-%m")
    month_label = datetime.now().strftime("%B %Y")

    conn = get_db()
    total = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE user_id=? AND substr(date,1,7)=?", (uid, curr_month)).fetchone()[0]
    rows = conn.execute(
        "SELECT category, COUNT(*) as cnt, SUM(amount) as subtotal FROM receipts WHERE user_id=? AND substr(date,1,7)=? GROUP BY category ORDER BY subtotal DESC", (uid, curr_month)).fetchall()
    budgets = {b["category"]: b["monthly_limit"] for b in conn.execute(
        "SELECT * FROM budgets WHERE user_id=?", (uid,)).fetchall()}
    conn.close()

    cat_rows = ""
    for r in rows:
        limit = budgets.get(r["category"])
        pct = round((r["subtotal"] / limit) * 100, 1) if limit else None
        if pct is None:
            status = ""
        elif pct >= 100:
            status = '<span style="color:#dc3545;font-weight:bold">⚠ OVER BUDGET</span>'
        elif pct >= 80:
            status = '<span style="color:#e6a817;font-weight:bold">⚠ Near limit</span>'
        else:
            status = '<span style="color:#28a745">✓ On track</span>'
        cat_rows += f"<tr><td>{r['category']}</td><td>{r['cnt']}</td><td>₦{r['subtotal']:,.2f}</td><td>{'₦'+f'{limit:,.2f}' if limit else 'No limit'}</td><td>{
            f'{pct}%' if pct else '—'}</td><td>{status}</td></tr>"

    if not cat_rows:
        cat_rows = '<tr><td colspan="6">No receipts this month.</td></tr>'

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:auto">
      <div style="background:#007bff;color:white;padding:25px;text-align:center">
        <h1>🧾 ReceiptKeeper</h1>
        <p>Monthly Spending Report — {month_label}</p>
      </div>
      <div style="background:#f9f9f9;padding:25px">
        <div style="background:white;border-radius:8px;padding:20px;text-align:center">
          <p>Total Spent in {month_label}</p>
          <p style="font-size:36px;font-weight:bold;color:#007bff">₦{total:,.2f}</p>
        </div>
        <h3>Category Breakdown</h3>
        <table style="width:100%;border-collapse:collapse;background:white">
          <thead><tr><th>Category</th><th>Receipts</th><th>Spent</th><th>Budget</th><th>Used</th><th>Status</th></tr></thead>
          <tbody>{cat_rows}</tbody>
        </table>
        <p style="font-size:12px;color:#aaa;margin-top:20px;text-align:center">
          Sent by ReceiptKeeper · {datetime.now().strftime("%d %b %Y %H:%M")}
        </p>
      </div>
    </div>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"ReceiptKeeper — {month_label} Spending Report"
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = to_email
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, to_email, msg.as_string())
        flash(f"✅ Report sent to {to_email}!")
    except Exception as e:
        flash(f"Failed to send email: {str(e)}", "over_budget")

    return redirect(url_for("index"))


# ── EXPORT CSV ────────────────────────────────────
@app.route("/export")
@login_required
def export_csv():
    uid = current_user_id()
    conn = get_db()
    receipts = conn.execute(
        "SELECT * FROM receipts WHERE user_id=? ORDER BY date DESC", (uid,)).fetchall()
    conn.close()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["ID", "Amount", "Date", "Description", "Category", "Image"])
    for r in receipts:
        writer.writerow([r["id"], r["amount"], r["date"],
                        r["description"], r["category"], r["image_path"]])
    mem = BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="receipts.csv")


if __name__ == "__main__":
    app.run(debug=True)

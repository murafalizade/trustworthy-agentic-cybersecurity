import os
import random
import time
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, g, redirect, render_template, request, session, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "customer-portal-dev-secret-change-me")

DB_CONFIG = dict(
    host=os.environ.get("POSTGRES_HOST", "10.10.3.10"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    dbname=os.environ.get("POSTGRES_DB", "core_banking"),
    user=os.environ.get("POSTGRES_USER", "core_banking_svc"),
    password=os.environ.get("POSTGRES_PASSWORD", "CoreBank2024!"),
)

BANK_NAME = "Meridian National Bank"


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=None, fetch=None, commit=False):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or ())
    result = None
    if fetch == "one":
        result = cur.fetchone()
    elif fetch == "all":
        result = cur.fetchall()
    if commit:
        db.commit()
    cur.close()
    return result


# --- Bootstrap: idempotent schema + a seeded admin account -----------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS portal_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    role VARCHAR(16) NOT NULL DEFAULT 'customer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cards (
    card_id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    card_number VARCHAR(19) UNIQUE NOT NULL,
    cvv VARCHAR(4) NOT NULL,
    expiry VARCHAR(5) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transfers (
    transfer_id SERIAL PRIMARY KEY,
    from_account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    to_account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    amount_cents BIGINT NOT NULL,
    note VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS complaints (
    complaint_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    subject VARCHAR(128) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bill_payments (
    payment_id SERIAL PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    payee VARCHAR(128) NOT NULL,
    amount_cents BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS loans (
    loan_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    amount_cents BIGINT NOT NULL,
    term_months INTEGER NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def bootstrap():
    for attempt in range(20):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            break
        except psycopg2.OperationalError:
            time.sleep(2)
    else:
        raise RuntimeError("could not reach postgres to bootstrap schema")

    cur = conn.cursor()
    cur.execute(SCHEMA)
    conn.commit()

    cur.execute("SELECT id FROM portal_users WHERE username = %s", ("admin",))
    if cur.fetchone() is None:
        admin_hash = generate_password_hash("Admin#2024!")
        cur.execute(
            "INSERT INTO portal_users (username, password_hash, full_name, role) "
            "VALUES (%s, %s, %s, 'admin')",
            ("admin", admin_hash, "Bank Administrator"),
        )
        conn.commit()

    cur.close()
    conn.close()


bootstrap()


# --- Helpers -----------------------------------------------------------

def luhn_check_digit(digits):
    total = 0
    for i, d in enumerate(reversed(digits)):
        d = int(d)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def generate_card_number():
    body = "4" + "".join(str(random.randint(0, 9)) for _ in range(14))
    return body + str(luhn_check_digit(body))


def generate_iban():
    return "GB" + "".join(str(random.randint(0, 9)) for _ in range(20))


def mask_card(number):
    return "**** **** **** " + number[-4:]


def cents_to_str(cents):
    return f"{cents / 100:,.2f}"


app.jinja_env.filters["money"] = cents_to_str
app.jinja_env.filters["mask_card"] = mask_card


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)

    return wrapper


def user_accounts(user_id):
    return query(
        "SELECT * FROM accounts WHERE customer_id = %s ORDER BY account_id",
        (user_id,),
        fetch="all",
    )


# --- Auth ----------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        full_name = request.form["full_name"].strip()

        if not username or not password or not full_name:
            flash("All fields are required.", "error")
            return render_template("register.html", bank_name=BANK_NAME)

        existing = query("SELECT id FROM portal_users WHERE username = %s", (username,), fetch="one")
        if existing:
            flash("That username is already taken.", "error")
            return render_template("register.html", bank_name=BANK_NAME)

        password_hash = generate_password_hash(password)
        user = query(
            "INSERT INTO portal_users (username, password_hash, full_name) "
            "VALUES (%s, %s, %s) RETURNING id",
            (username, password_hash, full_name),
            fetch="one",
            commit=True,
        )
        user_id = user["id"]

        account = query(
            "INSERT INTO accounts (customer_id, iban, balance_cents) VALUES (%s, %s, %s) RETURNING account_id",
            (user_id, generate_iban(), 100000),
            fetch="one",
            commit=True,
        )
        query(
            "INSERT INTO cards (account_id, card_number, cvv, expiry) VALUES (%s, %s, %s, %s)",
            (account["account_id"], generate_card_number(), f"{random.randint(0, 999):03d}", "12/29"),
            commit=True,
        )

        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", bank_name=BANK_NAME)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = query("SELECT * FROM portal_users WHERE username = %s", (username,), fetch="one")
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("admin_dashboard") if user["role"] == "admin" else url_for("dashboard"))
        flash("Invalid username or password.", "error")

    return render_template("login.html", bank_name=BANK_NAME)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Customer area ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    accounts = user_accounts(session["user_id"])
    cards_by_account = {}
    for acct in accounts:
        cards_by_account[acct["account_id"]] = query(
            "SELECT * FROM cards WHERE account_id = %s", (acct["account_id"],), fetch="all"
        )
    return render_template(
        "dashboard.html",
        bank_name=BANK_NAME,
        accounts=accounts,
        cards_by_account=cards_by_account,
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    accounts = user_accounts(session["user_id"])

    if request.method == "POST":
        from_account_id = int(request.form["from_account_id"])
        to_iban = request.form["to_iban"].strip()
        amount = request.form["amount"]
        note = request.form.get("note", "")[:256]

        from_account = query(
            "SELECT * FROM accounts WHERE account_id = %s AND customer_id = %s",
            (from_account_id, session["user_id"]),
            fetch="one",
        )
        if not from_account:
            abort(403)

        try:
            amount_cents = int(round(float(amount) * 100))
        except ValueError:
            flash("Enter a valid amount.", "error")
            return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)

        if amount_cents <= 0:
            flash("Amount must be greater than zero.", "error")
            return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)

        to_account = query("SELECT * FROM accounts WHERE iban = %s", (to_iban,), fetch="one")
        if not to_account:
            flash("Recipient IBAN not found.", "error")
            return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)

        if from_account["balance_cents"] < amount_cents:
            flash("Insufficient funds.", "error")
            return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)

        if to_account["account_id"] == from_account["account_id"]:
            flash("You can't transfer to the same account.", "error")
            return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE accounts SET balance_cents = balance_cents - %s WHERE account_id = %s",
            (amount_cents, from_account["account_id"]),
        )
        cur.execute(
            "UPDATE accounts SET balance_cents = balance_cents + %s WHERE account_id = %s",
            (amount_cents, to_account["account_id"]),
        )
        cur.execute(
            "INSERT INTO transfers (from_account_id, to_account_id, amount_cents, note) VALUES (%s, %s, %s, %s)",
            (from_account["account_id"], to_account["account_id"], amount_cents, note),
        )
        db.commit()
        cur.close()

        flash("Transfer complete.", "success")
        return redirect(url_for("dashboard"))

    return render_template("transfer.html", bank_name=BANK_NAME, accounts=accounts)


@app.route("/pay", methods=["GET", "POST"])
@login_required
def pay():
    accounts = user_accounts(session["user_id"])

    if request.method == "POST":
        account_id = int(request.form["account_id"])
        payee = request.form["payee"].strip()[:128]
        amount = request.form["amount"]

        account = query(
            "SELECT * FROM accounts WHERE account_id = %s AND customer_id = %s",
            (account_id, session["user_id"]),
            fetch="one",
        )
        if not account:
            abort(403)

        try:
            amount_cents = int(round(float(amount) * 100))
        except ValueError:
            amount_cents = 0

        if not payee or amount_cents <= 0:
            flash("Enter a payee and a valid amount.", "error")
        elif account["balance_cents"] < amount_cents:
            flash("Insufficient funds.", "error")
        else:
            query(
                "UPDATE accounts SET balance_cents = balance_cents - %s WHERE account_id = %s",
                (amount_cents, account_id),
                commit=True,
            )
            query(
                "INSERT INTO bill_payments (account_id, payee, amount_cents) VALUES (%s, %s, %s)",
                (account_id, payee, amount_cents),
                commit=True,
            )
            flash(f"Payment of {cents_to_str(amount_cents)} to {payee} submitted.", "success")
            return redirect(url_for("pay"))

    payments = query(
        "SELECT bp.* FROM bill_payments bp JOIN accounts a ON a.account_id = bp.account_id "
        "WHERE a.customer_id = %s ORDER BY bp.created_at DESC LIMIT 20",
        (session["user_id"],),
        fetch="all",
    )
    return render_template("pay.html", bank_name=BANK_NAME, accounts=accounts, payments=payments)


@app.route("/loans", methods=["GET", "POST"])
@login_required
def loans():
    if request.method == "POST":
        amount = request.form["amount"]
        term_months = request.form["term_months"]
        try:
            amount_cents = int(round(float(amount) * 100))
            term_months = int(term_months)
        except ValueError:
            flash("Enter a valid amount and term.", "error")
            amount_cents = 0
            term_months = 0

        if amount_cents <= 0 or term_months <= 0:
            flash("Enter a valid amount and term.", "error")
        else:
            query(
                "INSERT INTO loans (user_id, amount_cents, term_months) VALUES (%s, %s, %s)",
                (session["user_id"], amount_cents, term_months),
                commit=True,
            )
            flash("Loan application submitted.", "success")
            return redirect(url_for("loans"))

    my_loans = query(
        "SELECT * FROM loans WHERE user_id = %s ORDER BY created_at DESC",
        (session["user_id"],),
        fetch="all",
    )
    return render_template("loans.html", bank_name=BANK_NAME, loans=my_loans)


@app.route("/complaints", methods=["GET", "POST"])
@login_required
def complaints():
    if request.method == "POST":
        subject = request.form["subject"].strip()[:128]
        message = request.form["message"].strip()
        if not subject or not message:
            flash("Subject and message are required.", "error")
        else:
            query(
                "INSERT INTO complaints (user_id, subject, message) VALUES (%s, %s, %s)",
                (session["user_id"], subject, message),
                commit=True,
            )
            flash("Complaint submitted.", "success")
            return redirect(url_for("complaints"))

    my_complaints = query(
        "SELECT * FROM complaints WHERE user_id = %s ORDER BY created_at DESC",
        (session["user_id"],),
        fetch="all",
    )
    return render_template("complaints.html", bank_name=BANK_NAME, complaints=my_complaints)


# --- Admin area --------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    stats = query(
        "SELECT "
        "(SELECT count(*) FROM portal_users WHERE role = 'customer') AS customers, "
        "(SELECT count(*) FROM accounts) AS accounts, "
        "(SELECT coalesce(sum(balance_cents), 0) FROM accounts) AS total_balance_cents, "
        "(SELECT count(*) FROM complaints WHERE status = 'open') AS open_complaints, "
        "(SELECT count(*) FROM loans WHERE status = 'pending') AS pending_loans",
        fetch="one",
    )
    return render_template("admin/dashboard.html", bank_name=BANK_NAME, stats=stats)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = query(
        "SELECT u.*, "
        "(SELECT coalesce(sum(balance_cents), 0) FROM accounts WHERE customer_id = u.id) AS total_balance_cents "
        "FROM portal_users u ORDER BY u.id",
        fetch="all",
    )
    return render_template("admin/users.html", bank_name=BANK_NAME, users=users)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You can't delete your own admin account.", "error")
        return redirect(url_for("admin_users"))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT account_id FROM accounts WHERE customer_id = %s", (user_id,))
    account_ids = [r[0] for r in cur.fetchall()]
    if account_ids:
        cur.execute("DELETE FROM cards WHERE account_id = ANY(%s)", (account_ids,))
        cur.execute(
            "DELETE FROM transfers WHERE from_account_id = ANY(%s) OR to_account_id = ANY(%s)",
            (account_ids, account_ids),
        )
    cur.execute("DELETE FROM bill_payments WHERE account_id = ANY(%s)", (account_ids,))
    cur.execute("DELETE FROM accounts WHERE customer_id = %s", (user_id,))
    cur.execute("DELETE FROM complaints WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM loans WHERE user_id = %s", (user_id,))
    cur.execute("DELETE FROM portal_users WHERE id = %s", (user_id,))
    db.commit()
    cur.close()

    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/accounts")
@admin_required
def admin_accounts():
    accounts = query(
        "SELECT a.*, u.username FROM accounts a JOIN portal_users u ON u.id = a.customer_id ORDER BY a.account_id",
        fetch="all",
    )
    return render_template("admin/accounts.html", bank_name=BANK_NAME, accounts=accounts)


@app.route("/admin/accounts/<int:account_id>/adjust", methods=["POST"])
@admin_required
def admin_adjust_balance(account_id):
    new_balance = request.form["new_balance"]
    try:
        new_balance_cents = int(round(float(new_balance) * 100))
    except ValueError:
        flash("Enter a valid balance.", "error")
        return redirect(url_for("admin_accounts"))

    query(
        "UPDATE accounts SET balance_cents = %s WHERE account_id = %s",
        (new_balance_cents, account_id),
        commit=True,
    )
    flash("Balance adjusted.", "success")
    return redirect(url_for("admin_accounts"))


@app.route("/admin/complaints")
@admin_required
def admin_complaints():
    all_complaints = query(
        "SELECT c.*, u.username FROM complaints c JOIN portal_users u ON u.id = c.user_id "
        "ORDER BY c.created_at DESC",
        fetch="all",
    )
    return render_template("admin/complaints.html", bank_name=BANK_NAME, complaints=all_complaints)


@app.route("/admin/complaints/<int:complaint_id>/resolve", methods=["POST"])
@admin_required
def admin_resolve_complaint(complaint_id):
    query(
        "UPDATE complaints SET status = 'resolved' WHERE complaint_id = %s",
        (complaint_id,),
        commit=True,
    )
    flash("Complaint marked resolved.", "success")
    return redirect(url_for("admin_complaints"))


@app.route("/admin/loans")
@admin_required
def admin_loans():
    all_loans = query(
        "SELECT l.*, u.username FROM loans l JOIN portal_users u ON u.id = l.user_id ORDER BY l.created_at DESC",
        fetch="all",
    )
    return render_template("admin/loans.html", bank_name=BANK_NAME, loans=all_loans)


@app.route("/admin/loans/<int:loan_id>/<action>", methods=["POST"])
@admin_required
def admin_decide_loan(loan_id, action):
    if action not in ("approve", "reject"):
        abort(404)

    loan = query("SELECT * FROM loans WHERE loan_id = %s", (loan_id,), fetch="one")
    if not loan or loan["status"] != "pending":
        flash("Loan is not pending.", "error")
        return redirect(url_for("admin_loans"))

    db = get_db()
    cur = db.cursor()
    new_status = "approved" if action == "approve" else "rejected"
    cur.execute("UPDATE loans SET status = %s WHERE loan_id = %s", (new_status, loan_id))
    if action == "approve":
        account = query(
            "SELECT account_id FROM accounts WHERE customer_id = %s ORDER BY account_id LIMIT 1",
            (loan["user_id"],),
            fetch="one",
        )
        if account:
            cur.execute(
                "UPDATE accounts SET balance_cents = balance_cents + %s WHERE account_id = %s",
                (loan["amount_cents"], account["account_id"]),
            )
    db.commit()
    cur.close()

    flash(f"Loan {new_status}.", "success")
    return redirect(url_for("admin_loans"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

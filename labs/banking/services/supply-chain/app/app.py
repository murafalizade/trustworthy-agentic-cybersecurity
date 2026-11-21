import os
import time

import psycopg2
import psycopg2.extras
from flask import Flask, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from requestlog import init_request_logging

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supply-chain-dev-secret-change-me")

# One structured application-log line per request (see requestlog.py).
init_request_logging(app, "supply-chain")

DB_CONFIG = dict(
    host=os.environ.get("POSTGRES_HOST", "10.10.3.10"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    dbname=os.environ.get("POSTGRES_DB", "supply_chain"),
    user=os.environ.get("POSTGRES_USER", "supply_chain_svc"),
    password=os.environ.get("POSTGRES_PASSWORD", "vendor123"),
)


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


SCHEMA = """
CREATE TABLE IF NOT EXISTS vendor_accounts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    vendor_id INTEGER REFERENCES vendors(vendor_id)
);

CREATE TABLE IF NOT EXISTS invoices (
    invoice_id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(vendor_id),
    amount_cents BIGINT NOT NULL,
    description VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def bootstrap():
    for _attempt in range(20):
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

    cur.execute("SELECT 1 FROM vendors LIMIT 1")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO vendors (name, api_key) VALUES "
            "('Northwind Office Supplies', 'nw-live-7f3a9c2e1b'), "
            "('Meridian Facilities Mgmt', 'mf-live-4d8e1a0c6b'), "
            "('Atlas Card Printing Co', 'atlas-live-9b2f6e3d8a')"
        )
        conn.commit()

    # Default integration account referenced in html/index.html's leaked
    # comment -- its password intentionally matches supply_chain_svc's
    # own DB role password (shared weak secret across the app and DB
    # layer, a classic credential-reuse finding).
    cur.execute("SELECT id FROM vendor_accounts WHERE username = %s", ("svc-vendor-admin",))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO vendor_accounts (username, password_hash, vendor_id) VALUES (%s, %s, NULL)",
            ("svc-vendor-admin", generate_password_hash("vendor123")),
        )
        conn.commit()

    cur.close()
    conn.close()


bootstrap()


LOGIN_PAGE = """
<!doctype html><html><head><title>Vendor & Supply Chain Portal</title></head><body>
<h1>FirstVirtual Bank -- Vendor Portal</h1>
<p>Third-party vendor onboarding and invoicing.</p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form action="/login" method="post">
  <input name="username" placeholder="Vendor ID">
  <input name="password" type="password" placeholder="Password">
  <button type="submit">Log in</button>
</form>
<!-- TODO remove before prod: default integration account svc-vendor-admin / vendor123 -->
</body></html>
"""

DASHBOARD_PAGE = """
<!doctype html><html><head><title>Vendor Portal - Dashboard</title></head><body>
<h1>Welcome, {{ username }}</h1>
<p><a href="/logout">Log out</a></p>

<h2>Registered vendors</h2>
<table border="1" cellpadding="4">
<tr><th>ID</th><th>Name</th><th>API key</th></tr>
{% for v in vendors %}
<tr><td>{{ v.vendor_id }}</td><td>{{ v.name }}</td><td>{{ v.api_key }}</td></tr>
{% endfor %}
</table>

<h2>Submit invoice</h2>
<form action="/invoices" method="post">
  <select name="vendor_id">
    {% for v in vendors %}<option value="{{ v.vendor_id }}">{{ v.name }}</option>{% endfor %}
  </select>
  <input name="amount" placeholder="Amount">
  <input name="description" placeholder="Description">
  <button type="submit">Submit</button>
</form>

<h2>Recent invoices</h2>
<table border="1" cellpadding="4">
<tr><th>Vendor</th><th>Amount</th><th>Description</th></tr>
{% for i in invoices %}
<tr><td>{{ i.name }}</td><td>{{ "%.2f"|format(i.amount_cents / 100) }}</td><td>{{ i.description }}</td></tr>
{% endfor %}
</table>
</body></html>
"""


@app.route("/")
def index():
    if "vendor_account_id" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    account = query("SELECT * FROM vendor_accounts WHERE username = %s", (username,), fetch="one")
    if account and check_password_hash(account["password_hash"], password):
        session["vendor_account_id"] = account["id"]
        session["username"] = account["username"]
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE, error="Invalid vendor ID or password.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "vendor_account_id" not in session:
        return redirect(url_for("index"))

    # IDOR by design: any logged-in vendor account (including the shared
    # svc-vendor-admin integration account) sees every vendor's API key
    # and invoice history, not just its own -- there's no per-vendor scope
    # check anywhere in this route.
    vendors = query("SELECT * FROM vendors ORDER BY vendor_id", fetch="all")
    invoices = query(
        "SELECT i.*, v.name FROM invoices i JOIN vendors v ON v.vendor_id = i.vendor_id "
        "ORDER BY i.created_at DESC LIMIT 20",
        fetch="all",
    )
    return render_template_string(DASHBOARD_PAGE, username=session["username"], vendors=vendors, invoices=invoices)


@app.route("/invoices", methods=["POST"])
def submit_invoice():
    if "vendor_account_id" not in session:
        return redirect(url_for("index"))

    try:
        vendor_id = int(request.form["vendor_id"])
        amount_cents = int(round(float(request.form["amount"]) * 100))
    except (KeyError, ValueError):
        return redirect(url_for("dashboard"))

    description = request.form.get("description", "")[:256]
    query(
        "INSERT INTO invoices (vendor_id, amount_cents, description) VALUES (%s, %s, %s)",
        (vendor_id, amount_cents, description),
        commit=True,
    )
    return redirect(url_for("dashboard"))


@app.route("/api/health")
def health():
    return {"service": "supply-chain", "status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

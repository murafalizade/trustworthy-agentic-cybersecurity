import os
import time

import psycopg2
import psycopg2.extras
from flask import Flask, g, jsonify, request

app = Flask(__name__)

DB_CONFIG = dict(
    host=os.environ.get("POSTGRES_HOST", "10.10.3.10"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    dbname=os.environ.get("POSTGRES_DB", "core_banking"),
    user=os.environ.get("POSTGRES_USER", "core_banking_svc"),
    password=os.environ.get("POSTGRES_PASSWORD", "CoreBank2024!"),
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


def wait_for_db():
    # "accounts" is created by ../../postgres/init.sql, not by this
    # service -- it only ever reads/writes that table, never creates it,
    # so two services booting at once can't race each other on DDL the
    # way customer-portal's own portal_users/cards/... bootstrap would.
    for _attempt in range(20):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            return
        except psycopg2.OperationalError:
            time.sleep(2)
    raise RuntimeError("could not reach postgres")


wait_for_db()


# --- Internal account-management API --------------------------------------
# "Internal network trust" service: app-tier peers (and anyone who's
# pivoted there) call these with no auth, mirroring the trust model the
# transactions service's swagger.json already documents for its own
# internal/ endpoints.

@app.route("/api/health")
def health():
    return jsonify(service="core-banking", status="ok")


@app.route("/api/accounts/<int:account_id>")
def get_account(account_id):
    account = query("SELECT * FROM accounts WHERE account_id = %s", (account_id,), fetch="one")
    if not account:
        return jsonify(error="not found"), 404
    return jsonify(account)


@app.route("/api/accounts")
def list_accounts():
    customer_id = request.args.get("customer_id")
    if customer_id:
        accounts = query(
            "SELECT * FROM accounts WHERE customer_id = %s ORDER BY account_id",
            (customer_id,),
            fetch="all",
        )
    else:
        accounts = query("SELECT * FROM accounts ORDER BY account_id", fetch="all")
    return jsonify(accounts)


@app.route("/api/accounts/<int:account_id>/adjust", methods=["POST"])
def adjust_account(account_id):
    body = request.get_json(silent=True) or {}
    try:
        amount_cents = int(body["amount_cents"])
    except (KeyError, TypeError, ValueError):
        return jsonify(error="amount_cents (int) is required"), 400

    account = query(
        "UPDATE accounts SET balance_cents = balance_cents + %s WHERE account_id = %s RETURNING *",
        (amount_cents, account_id),
        fetch="one",
        commit=True,
    )
    if not account:
        return jsonify(error="not found"), 404
    return jsonify(account)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

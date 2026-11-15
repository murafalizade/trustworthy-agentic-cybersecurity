import os
import time

import psycopg2
import psycopg2.extras
from flask import Flask, g, jsonify, request

app = Flask(__name__)

DB_CONFIG = dict(
    host=os.environ.get("POSTGRES_HOST", "10.10.3.10"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    dbname=os.environ.get("POSTGRES_DB", "transactions"),
    user=os.environ.get("POSTGRES_USER", "transactions_svc"),
    password=os.environ.get("POSTGRES_PASSWORD", "Txn#Service24"),
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


def wait_for_db():
    # "ledger" is created by ../../postgres/init.sql, not by this
    # service, so there's no schema-creation race with other services
    # booting at the same time against the same Postgres cluster.
    for _attempt in range(20):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            return
        except psycopg2.OperationalError:
            time.sleep(2)
    raise RuntimeError("could not reach postgres")


wait_for_db()


# --- Internal ledger API ---------------------------------------------------
# Matches ../html/swagger.json one for one -- "no external auth required
# (internal network trust)" is the service's own documented posture, not
# a bug introduced here.

@app.route("/api/health")
def health():
    return jsonify(service="transactions", status="ok")


@app.route("/internal/ledger", methods=["GET"])
def list_ledger():
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ledger ORDER BY txn_id DESC LIMIT 50")
    rows = cur.fetchall()
    cur.close()
    return jsonify(rows)


@app.route("/internal/ledger/transfer", methods=["POST"])
def ledger_transfer():
    body = request.get_json(silent=True) or {}
    try:
        account_id = int(body["account_id"])
        amount_cents = int(body["amount_cents"])
    except (KeyError, TypeError, ValueError):
        return jsonify(error="account_id and amount_cents (int) are required"), 400

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "INSERT INTO ledger (account_id, amount_cents) VALUES (%s, %s) RETURNING *",
        (account_id, amount_cents),
    )
    row = cur.fetchone()
    db.commit()
    cur.close()
    return jsonify(row)


@app.route("/internal/ledger/reverse", methods=["POST"])
def ledger_reverse():
    body = request.get_json(silent=True) or {}
    try:
        txn_id = int(body["txn_id"])
    except (KeyError, TypeError, ValueError):
        return jsonify(error="txn_id (int) is required"), 400

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM ledger WHERE txn_id = %s", (txn_id,))
    original = cur.fetchone()
    if not original:
        cur.close()
        return jsonify(error="not found"), 404

    cur.execute(
        "INSERT INTO ledger (account_id, amount_cents) VALUES (%s, %s) RETURNING *",
        (original["account_id"], -original["amount_cents"]),
    )
    reversal = cur.fetchone()
    db.commit()
    cur.close()
    return jsonify(reversal)


@app.route("/internal/admin/reindex", methods=["POST"])
def admin_reindex():
    # No real search index behind this build -- a decoy endpoint that
    # matches the swagger.json listing without doing anything.
    return jsonify(status="reindexed")


@app.route("/internal/debug/sql", methods=["POST"])
def debug_sql():
    # Intentionally vulnerable: swagger.json advertises this as a
    # "debug build only" ad-hoc read-only SQL runner left reachable with
    # no auth, the lab's SQL-injection-by-design endpoint. Do not add
    # input sanitization here -- that's the point of the exercise.
    body = request.get_json(silent=True) or {}
    sql = body.get("query", "")
    if not sql:
        return jsonify(error="query is required"), 400

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(sql)
        rows = cur.fetchall() if cur.description else []
    except psycopg2.Error as exc:
        db.rollback()
        return jsonify(error=str(exc)), 400
    finally:
        cur.close()
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

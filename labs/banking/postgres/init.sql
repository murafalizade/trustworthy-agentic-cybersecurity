-- Minimal multi-database layout for a single shared Postgres instance,
-- the way a lot of real banks actually run it: one cluster, several
-- line-of-business databases, separated only by role grants (not network
-- isolation) -- the common "noisy neighbor" finding once you have a foothold.

CREATE DATABASE core_banking;
CREATE DATABASE transactions;
CREATE DATABASE supply_chain;

CREATE ROLE core_banking_svc LOGIN PASSWORD 'CoreBank2024!';
CREATE ROLE transactions_svc LOGIN PASSWORD 'Txn#Service24';
CREATE ROLE supply_chain_svc LOGIN PASSWORD 'vendor123';

-- Legacy reporting account, superuser, never rotated -- classic
-- forgotten-account finding for lateral movement once inside data-tier.
CREATE ROLE legacy_reporting LOGIN PASSWORD 'reporting' SUPERUSER;

GRANT ALL PRIVILEGES ON DATABASE core_banking TO core_banking_svc;
GRANT ALL PRIVILEGES ON DATABASE transactions TO transactions_svc;
GRANT ALL PRIVILEGES ON DATABASE supply_chain TO supply_chain_svc;

\c core_banking
CREATE TABLE IF NOT EXISTS accounts (
    account_id   SERIAL PRIMARY KEY,
    customer_id  INTEGER NOT NULL,
    iban         VARCHAR(34) NOT NULL,
    balance_cents BIGINT NOT NULL DEFAULT 0
);

\c transactions
CREATE TABLE IF NOT EXISTS ledger (
    txn_id       SERIAL PRIMARY KEY,
    account_id   INTEGER NOT NULL,
    amount_cents BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

\c supply_chain
CREATE TABLE IF NOT EXISTS vendors (
    vendor_id    SERIAL PRIMARY KEY,
    name         VARCHAR(128) NOT NULL,
    api_key      VARCHAR(64)
);

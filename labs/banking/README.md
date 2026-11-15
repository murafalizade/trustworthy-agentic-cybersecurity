# Banking Environment Lab

A self-contained, segmented docker-compose environment that *simulates* a
bank's internal network for attack-surface practice. Nothing here processes
real money or real data, but each service is a small real Flask app behind
nginx (not just a static stub) backed by a shared Postgres cluster, wired
together with deliberately realistic (and deliberately weak) configuration.

**Use only against this lab's own containers. Never point tooling at a host
you don't own or lack authorization to test.**

## Topology

Four segmented Docker networks, bridged only through a single router
container — nothing else is multi-homed:

| Segment    | Subnet         | Router IP     | Members                                   |
|------------|-----------------|---------------|--------------------------------------------|
| `dmz`      | 10.10.1.0/24    | 10.10.1.250   | `customer-portal`                           |
| `app-tier` | 10.10.2.0/24    | 10.10.2.250   | `core-banking`, `transactions`, `supply-chain` |
| `data-tier`| 10.10.3.0/24    | 10.10.3.250   | `postgres`                                  |
| `mgmt`     | 10.10.4.0/24    | 10.10.4.250   | `node-exporter`                             |

- **`router`** — Debian + FRR (zebra/ospfd) + iptables, the only container
  attached to all four networks. It's the "Cisco-ish" piece: it presents a
  routing-protocol fingerprint (OSPF, vty) and is where segment-to-segment
  policy would live. **By default its `FORWARD` chain is wide open** — a
  flat-network misconfig, so a foothold in `dmz` can reach `data-tier`
  directly. Tighten `router/entrypoint.sh` to a DROP-by-default allow-list
  to practice against a hardened perimeter instead.
- Every other container only has an interface on its own segment. Each one
  carries `cap_add: NET_ADMIN` and its own entrypoint script runs
  `ip route replace 10.10.0.0/16 via <router-ip-on-its-segment>` on every
  start, before it does anything else. That route is what lets it reach the
  other segments at all through the router's wide-open `FORWARD` chain.
  It's applied by the container itself rather than by a one-shot sidecar so
  that a restart or rebuild of any single service can't silently leave it
  unrouted — that was the actual cause of "DB connection not working" the
  earlier `*-route`-sidecar design was prone to: the sidecar only ran once,
  at the first `docker compose up`, so recreating just one service later
  (a rebuild, a crash-restart, `--force-recreate`) gave it a fresh network
  namespace with no custom route in it, while the stale sidecar kept
  holding the old, discarded one open.

## Services

- **`customer-portal`** (dmz) — public online banking portal: Flask +
  gunicorn behind nginx, backed by the `core_banking` database
  (`core_banking_svc` role). Registration, login, transfers, bill pay,
  loans, complaints, and an admin area. Leaks a `.git/config` under the
  webroot and a version banner via `X-Powered-By`.
- **`core-banking`** (app-tier) — internal accounts API
  (`/api/accounts`, `/api/accounts/<id>/adjust`), unauthenticated by
  design ("internal network trust"), reading/writing the *same*
  `accounts` table as `customer-portal` — the lab's "noisy neighbor"
  theme: separate services, no isolation between what touches the same
  rows. Also exposes an unauthenticated Spring-Boot-Actuator-style
  `/actuator/env` dump with DB credentials and a JWT signing secret
  baked in.
- **`transactions`** (app-tier) — ledger API over the `transactions`
  database (`transactions_svc` role): `/internal/ledger`,
  `/internal/ledger/transfer`, `/internal/ledger/reverse`,
  `/internal/admin/reindex` (decoy), and `/internal/debug/sql` — an
  intentionally vulnerable ad-hoc SQL runner, exactly as advertised by
  the unauthenticated `/swagger.json` endpoint map.
- **`supply-chain`** (app-tier) — third-party vendor/invoicing portal
  (the classic bank supply-chain attack vector) over the `supply_chain`
  database (`supply_chain_svc` role). Any logged-in vendor account —
  including the default integration account leaked in an HTML comment on
  the login page, `svc-vendor-admin` / `vendor123` — can see every other
  vendor's API key and invoice history on `/dashboard` (IDOR by design,
  no per-vendor scoping).
- **`postgres`** (data-tier) — one shared cluster, three databases
  (`core_banking`, `transactions`, `supply_chain`), seeded via
  `postgres/init.sql`. Runs with `POSTGRES_HOST_AUTH_METHOD=trust` (no
  password needed once you can reach :5432) on top of weak per-DB
  credentials, plus a forgotten `legacy_reporting` superuser.
- **`node-exporter`** (mgmt) — Prometheus host/container metrics
  exporter, unauthenticated (realistic default for this stack).

## Run

```bash
cd labs/banking
docker compose up --build
```

Manual access from the host:

- Customer portal: `curl http://localhost:8081/`

Everything else (core-banking, transactions, supply-chain, postgres,
router) is intentionally **not** published to the host — reaching them is
the point of the exercise, either by attaching a tool container to one of
the compose networks or via the attacker container described next.

Each of the four nginx-backed services (`customer-portal`, `core-banking`,
`transactions`, `supply-chain`) does bind-mount its own nginx access/error
log to `logs/<service>/` on the host, as structured JSON
(`log_format json_analytics` in each service's `nginx.conf`; the stock
nginx image otherwise symlinks those to stdout, which a bind mount can't
capture). This is the independent defender-side evidence
`../docker-compose.yml`'s `agent` reads, separate from the attacker's own
campaign log, and is also what `../filebeat/filebeat.yml` ships into
Elasticsearch — see `../README.md` for the `elasticsearch` /
`filebeat` / `kibana` stack.

This compose file has no attacker of its own. `../docker-compose.yml` (one
level up) runs `attacker` + `agent`, attached to this project's
`banking_dmz` network as an `external` network so this file doesn't need
to know about it — see `../README.md`. Its campaign output lands in
`logs/attacker/` here.

## Notes / limitations

- FRR's OSPF process has no peer to form an adjacency with (there's only
  one router) — it's there to be fingerprinted and explored (open vty,
  routing daemon banners), not to perform real multi-router routing.
- `postgres/init.sql` runs as the Postgres superuser, so tables it creates
  (`accounts`, `ledger`, `vendors`) are owned by `postgres`, not by the
  per-database service role — each database's schema-level `GRANT ALL`
  doesn't cover objects it didn't create itself, so each one also needs an
  explicit `GRANT ALL ... ON ALL TABLES/SEQUENCES` for those tables. If
  you add a new table to `init.sql`, remember the matching grant for
  whichever `*_svc` role is meant to use it, or that service will come up
  with a `permission denied for table ...` instead of a connectivity
  error.

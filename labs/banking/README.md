# Banking Environment Lab

A self-contained, segmented docker-compose environment that *simulates* a
bank's internal network for attack-surface practice. Nothing here processes
real money or real data — every "service" is a static nginx stub or an
off-the-shelf infra component (Postgres, Prometheus, Grafana) wired together
with deliberately realistic (and deliberately weak) configuration. There is
no custom banking application logic to run or maintain.

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
| `mgmt`     | 10.10.4.0/24    | 10.10.4.250   | `prometheus`, `grafana`, `node-exporter`    |

- **`router`** — Debian + FRR (zebra/ospfd) + iptables, the only container
  attached to all four networks. It's the "Cisco-ish" piece: it presents a
  routing-protocol fingerprint (OSPF, vty) and is where segment-to-segment
  policy would live. **By default its `FORWARD` chain is wide open** — a
  flat-network misconfig, so a foothold in `dmz` can reach `data-tier`
  directly. Tighten `router/entrypoint.sh` to a DROP-by-default allow-list
  to practice against a hardened perimeter instead.
- Every other container only has an interface on its own segment; a
  `<service>-route` sidecar (tiny alpine container sharing that service's
  network namespace via `network_mode: service:<name>`) installs a static
  route to `10.10.0.0/16` via the router's IP on that segment, then exits.
  No application image had to be rebuilt or modified to make routing work.

## Services

- **`customer-portal`** (dmz) — public online banking portal. Leaks a
  `.git/config` under the webroot and a version banner via `X-Powered-By`.
- **`core-banking`** (app-tier) — internal API gateway. Exposes an
  unauthenticated Spring-Boot-Actuator-style `/actuator/env` dump with DB
  credentials and a JWT signing secret baked in.
- **`transactions`** (app-tier) — ledger service. Exposes `/swagger.json`
  with the full internal endpoint map, including a "debug" SQL endpoint.
- **`supply-chain`** (app-tier) — third-party vendor/invoicing portal
  (the classic bank supply-chain attack vector). Default integration
  credentials are left in an HTML comment on the login page.
- **`postgres`** (data-tier) — one shared cluster, three databases
  (`core_banking`, `transactions`, `supply_chain`), seeded via
  `postgres/init.sql`. Runs with `POSTGRES_HOST_AUTH_METHOD=trust` (no
  password needed once you can reach :5432) on top of weak per-DB
  credentials, plus a forgotten `legacy_reporting` superuser.
- **`prometheus` / `grafana` / `node-exporter`** (mgmt) — observability
  stack. Grafana runs on default `admin`/`admin` credentials. Prometheus
  has no auth in front of it (realistic default for this stack).

## Run

```bash
cd labs/banking
docker compose up --build
```

Manual access from the host:

- Customer portal: `curl http://localhost:8081/`
- Prometheus UI: `http://localhost:9090`
- Grafana UI: `http://localhost:3000` (admin/admin)

Everything else (core-banking, transactions, supply-chain, postgres,
router) is intentionally **not** published to the host — reaching them is
the point of the exercise, either by attaching a tool container to one of
the compose networks or via the attacker container described next.

Each of the four nginx-backed services (`customer-portal`, `core-banking`,
`transactions`, `supply-chain`) does bind-mount its own nginx access/error
log to `logs/<service>/` on the host — see each service's `nginx.conf`
(`access_log`/`error_log` overrides; the stock nginx image otherwise
symlinks those to stdout, which a bind mount can't capture). This is the
independent defender-side evidence `../docker-compose.yml`'s `agent`
reads, separate from the attacker's own campaign log.

This compose file has no attacker of its own. `../docker-compose.yml` (one
level up) runs `attacker` + `agent`, attached to this project's
`banking_dmz` network as an `external` network so this file doesn't need
to know about it — see `../README.md`. Its campaign output lands in
`logs/attacker/` here.

## Notes / limitations

- FRR's OSPF process has no peer to form an adjacency with (there's only
  one router) — it's there to be fingerprinted and explored (open vty,
  routing daemon banners), not to perform real multi-router routing.
- The `*-route` sidecars need outbound internet access at `docker compose
  up` time to `apk add iproute2`; after that they exit and aren't needed
  again unless you recreate the network.

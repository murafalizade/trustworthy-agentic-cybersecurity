# Attack/Defense Labs

Self-contained Docker Compose labs for exercising the cybersecurity agent
against live traffic. Runs entirely on isolated bridge networks with no
path to the outside world besides the ports explicitly published for
manual inspection.

**Use only against these labs' own containers. Never point the attacker
scripts/tools at a host you don't own or lack authorization to test.**

## Layout

- **`banking/`** — the target: a segmented environment that *simulates* a
  bank's internal network (DMZ portal, app-tier microservices, a shared
  Postgres data-tier, a Prometheus/Grafana mgmt-tier, and a router/FRR
  container bridging the segments). See `banking/README.md` for the full
  topology and the list of intentional weaknesses. It has no attacker of
  its own — this directory's `attacker` service (below) is what generates
  traffic against it.
- **`docker-compose.yml`** (this directory) — `attacker` + `agent` from
  the original single-target lab, retargeted at banking's DMZ instead of
  a `target` service of their own (that lab's `system/` target has been
  retired now that banking is the target). They attach to banking's
  `banking_dmz` network as an **external** network rather than owning
  one, so banking's own `docker-compose.yml` doesn't need to change at
  all to support this.
  - `attacker/` — Kali Linux box with nmap, hydra, sqlmap, curl, `ab`,
    `psql`, and `jq`. `scripts/random_campaign.sh` is the container
    entrypoint: it loops forever running a staged kill-chain against
    banking's real topology (not a uniform random pick), with ordinary
    benign traffic mixed in between stages:
    1. `recon_nmap.sh` — dmz recon against `customer-portal` (port scan,
       `.git/config` leak, `/nginx_status`, banner grab).
    2. `pivot_apptier.sh` — adds a static route to `10.10.0.0/16` via
       `bank-router`, the same way each service's own `*-route` sidecar
       does, turning the router's wide-open `FORWARD` policy into an
       actual dmz→app-tier/data-tier/mgmt pivot.
    3. `recon_apptier.sh` — sweeps `core-banking`, `transactions`,
       `supply-chain`, Postgres, Prometheus, and Grafana now that they're
       reachable.
    4. `harvest_credentials.sh` — pulls `core-banking`'s unauthenticated
       `/actuator/env` (DB creds, JWT secret), `transactions`'
       `/swagger.json` endpoint map, and `supply-chain`'s leaked
       HTML-comment creds.
    5. `abuse_debug_sql.sh` — probes the "debug" SQL endpoint
       `swagger.json` advertises.
    6. `lateral_postgres.sh` — connects to the shared Postgres cluster
       with harvested/known creds, including the forgotten
       `legacy_reporting` superuser.
    7. `credential_stuffing.sh` — tries the leaked supply-chain default
       account plus a wordlist against `/login`, and default
       `admin`/`admin`-style guesses against Grafana.

    Noise scripts (`benign_traffic.sh`, `prompt_injection.sh`,
    `load_test_ddos_style.sh`) are interleaved randomly between stages.
    Parameterized by `TARGET_HOST`; set here to `customer-portal`. No
    SSH brute-force script exists anymore — nothing in banking runs
    sshd.
  - `agent` — the ID Agent, tailing each banking service's own nginx
    access/error log (see "Logs" below) for signal.

## Logs

`attacker`'s own campaign/tool output (`attacker-campaign.log` plus
nmap/hydra/sqlmap output files) lands in `labs/banking/logs/attacker` —
that's attacker ground truth for grading, and is deliberately **not**
mounted into `agent`.

`agent` instead tails each banking service's own nginx access/error log,
bind-mounted read-only from `labs/banking/logs/<service>/` (wired up in
`banking/docker-compose.yml` and each service's `nginx.conf`
`access_log`/`error_log` override — the nginx base image otherwise
symlinks those to stdout, which a bind mount can't capture). This is
independent, blind-defender-side evidence: a real detector reading real
target logs, not the attacker's self-report.

## Run

Banking must be up first — this directory's compose file references its
`banking_dmz` network as `external`, so the network has to already exist:

```bash
cd labs/banking
docker compose up --build -d

cd ../
docker compose up --build
```

Manual access to the banking portal from the host: `curl http://localhost:8081/`
(see `banking/README.md` for the rest: Prometheus on 9090, Grafana on 3000).

Tune the random campaign's pacing with `DDOS_DURATION` /
`DDOS_CONCURRENCY` env vars on the `attacker` service.

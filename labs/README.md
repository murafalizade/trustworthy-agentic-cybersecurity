# Attack/Defense Lab

Self-contained Docker Compose lab for exercising the cybersecurity agent
against live traffic. Runs entirely on an isolated bridge network
(`labnet`) with no path to the outside world besides the two ports
explicitly published for manual inspection.

**Use only against this lab's own `target` container. Never point the
attacker scripts at a host you don't own or lack authorization to test.**

## Layout

- `system/` — Ubuntu 24.04 "victim" box: sshd (two seeded users, weak
  passwords, for brute-force practice), nginx reverse-proxying a small
  PHP app with an intentionally SQL-injectable `/login.php`.
- `attacker/` — Kali Linux box with nmap, hydra, sqlmap, curl, and `ab`.
  `scripts/random_campaign.sh` is the container entrypoint: it loops
  forever, picking a random script (benign traffic, recon, SQLi,
  SSH/HTTP brute force, log-based prompt-injection seeding, or a
  bounded internal load test) with a random delay between runs, so
  traffic against the target looks mixed rather than a steady drumbeat.
- `logs/` — bind-mounted into both `target` and `attacker` (and
  read-only into `agent`) as `/var/log/lab`, so nginx access/error logs,
  sshd/auth logs, the PHP app log, sqlmap/nmap/hydra output, and the
  attacker's own campaign log all land in one place for the agent to
  ingest.

## Run

```bash
cd labs
docker compose up --build
```

Manual access to the target from the host: `ssh alice@localhost -p 2222`
(password `summer2024`) or `curl http://localhost:8080/`.

Tune the random campaign's pacing with `DDOS_DURATION` /
`DDOS_CONCURRENCY` env vars on the `attacker` service.

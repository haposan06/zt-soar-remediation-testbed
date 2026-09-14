# Teleport Database-Access Audit Lab (Monash minor thesis)

An isolated, fully local lab that produces **genuine Teleport database-access
audit logs (JSON)** from scripted benign and malicious PostgreSQL sessions.
The resulting logs are the input for the next stage of the thesis: deriving
alerts and asking an LLM to write remediation scripts for them.

Nothing in this lab fabricates an audit record. Every event is emitted by
Teleport itself as it proxies and parses real PostgreSQL wire traffic.

---

## 1. Safety: this lab never touches any other cluster

`tsh` on the operator's machine may be logged into an unrelated cluster. The
lab is isolated from it by three independent measures:

1. **`TELEPORT_HOME` is overridden** to `testbed/tsh-home` for every
   `tsh` invocation (exported in `scripts/setup.sh`, and set in `LAB_ENV` in
   `scripts/traffic.py`). The default `~/.tsh` profile is never read or written.
2. **`--proxy=localhost:3080` is always explicit.** No command relies on the
   current profile to pick a cluster.
3. **`tctl` only ever runs inside the `thesis-teleport` container**
   (`docker exec thesis-teleport /usr/local/bin/tctl ...`), where it talks to
   the lab Auth Service over the container-local admin socket. It cannot reach
   any external cluster.

Because every client call uses `tsh -i <identity>`, `tsh` never writes a profile
at all — `tsh-home/` stays empty in normal operation. Verified after a full run:
`~/.tsh` was unmodified (still pointing at the unrelated cluster) and contained
no reference to `thesis-lab` or `localhost:3080`.

Ports are bound to `127.0.0.1` only. If you add commands, keep these rules.

---

## 2. Prerequisites

| Requirement | Verified on this machine |
|---|---|
| Apple Silicon Mac | M5, 16 GB |
| Docker Desktop **running** | Docker 28.3.2, Compose v2.38.2 |
| `tsh` in `/usr/local/bin` | v17.7.19 (server is v17.7.26; minor skew is fine) |
| Python 3 with `psycopg2` | 3.12.4, psycopg2 2.9.9 |

If `psycopg2` is missing: `python3 -m pip install psycopg2-binary`.

---

## 3. Quick start

```bash
cd testbed
./scripts/setup.sh                                            # bring up + provision (idempotent)
python3 scripts/corpus.py --days 14 --benign-target 48000 --seed 42
python3 scripts/collect_audit.py                              # join audit log to ground truth
python3 scripts/detect.py                                     # rules -> alerts + hit rate
```

`corpus.py` reseeds `procurement` from `postgres/init.sql` before it starts, so
the run is repeatable even though the destructive scenarios really do delete
rows. The reseed goes through `docker exec ... psql` on the container's local
socket, **not** through Teleport, so it emits no audit events.

Total wall clock for the whole pipeline is under four minutes.

The single-day generator `scripts/traffic.py` from the first iteration is kept
for reference; `corpus.py` supersedes it.

Then inspect:

```bash
ls audit/                                # raw Teleport JSON, one file per day
python3 -m json.tool < out/summary.json | head -40
head -3 out/db_events.jsonl
column -s, -t < out/sessions.csv | head
```

Teardown: `./scripts/teardown.sh` (keeps data) or `--purge` (deletes everything,
**including the audit log**).

---

## 4. What gets built

```
testbed/
├── docker-compose.yml        teleport (auth+proxy+db_service) + postgres 16
├── teleport/teleport.yaml    cluster thesis-lab, JSON audit to a bind mount
├── postgres/
│   ├── init.sql              procurement schema, ~23k fake rows, 4 DB roles
│   ├── pg_hba.conf           hostssl ... cert  (Teleport client-cert auth)
│   └── pg-entrypoint.sh      installs Teleport-signed certs with 0600 perms
├── scripts/
│   ├── setup.sh              bring-up, cert signing, users, identity files
│   ├── corpus.py             14-day corpus generator (48k statements)
│   ├── traffic.py            first-iteration single-day driver (superseded)
│   ├── collect_audit.py      audit log -> out/db_events.jsonl + summary.json
│   ├── detect.py             YARA-L rules in Python -> alerts.json + hit rate
│   └── teardown.sh
├── rules/                    *.yaral - canonical YARA-L 2.0 rule sources
├── audit/                    ← Teleport writes JSON audit events here (host)
├── certs/                    server.cas / server.crt / server.key
├── identities/               per-user Teleport identity files (TTL 24h)
├── tsh-home/                 isolated TELEPORT_HOME
└── out/                      ground_truth.jsonl, sessions.csv, change_windows.json,
                              db_events.jsonl, summary.json, alerts.json,
                              detection_hitrate.csv
```

### Data model (`procurement` schema, all values FAKE)

The schema is **mandated by the alert contract** at
`Thesis/lab/harness/alerts_schema.md` and reproduced verbatim in that harness's
`prompts.py`. It must not drift.

| Table | Rows | Notes |
|---|---|---|
| employees | 1200 | **`salary`, `national_id`, `bank_account`** — sensitive-looking, generated |
| vendors | 900 | **`tax_id`, `bank_account`** |
| tenders | 500 | |
| bids | 6000 | **`bid_amount`, `technical_score`** sensitive before `sealed_until` |
| contracts | 600 | |
| payments | 12000 | **`bank_account_snapshot`** |
| audit_log | 2500 | in-database trail, the anti-forensics target |
| bids_archive | ~2400 | `CREATE TABLE AS` copy; the TRUNCATE/DROP target |
| **total** | **~26 100** | all from `generate_series()` |

Views: `employees_public` (masked, no salary/national_id/bank_account) and
`bids_public` (`WHERE sealed_until <= now()`). `analyst_ro` reaches employees
and unsealed bids **only** through these views, which is what makes a read of
the base tables a signal.

Table sizes were chosen so the frozen rule thresholds are meaningful: 500 rows
(PG-EXF-001, PG-TAMP-001), 50 rows (PG-TAMP-004) and 10 000 cumulative rows
(PG-EXF-003) all sit inside the achievable range rather than above it.

The "sensitive" columns contain deterministic filler digits (`NID-100000048`,
account `10004127`). No real personal or financial data exists in this lab.

### PostgreSQL roles ↔ Teleport users

The four PostgreSQL roles are fixed by the alert contract
(`principal.db_role` is an enum of exactly these).

| Teleport user | `--db-users` | Department | PostgreSQL grants |
|---|---|---|---|
| `svc.app@eproc.test` | `app_service` | Platform Engineering | `SELECT, INSERT, UPDATE` on tenders/bids/contracts/payments; `SELECT` on vendors, employees; `INSERT` on audit_log. No `DELETE` anywhere. |
| `rina.hartono@eproc.test` | `analyst_ro` | Finance Reporting | `SELECT` on tenders/contracts/payments/vendors and the masked views |
| `priya.suryani@eproc.test` | `analyst_ro` | Finance Reporting | as above |
| `dave.wijaya@eproc.test` | `proc_officer` | Procurement | `SELECT, INSERT, UPDATE` on tenders/bids; `SELECT` on vendors/contracts; column-scoped `SELECT` on payments |
| `nina.lestari@eproc.test` | `proc_officer` | Procurement | as above |
| `carol.tan@eproc.test` | `dba` | IT Operations | SUPERUSER (break-glass) |
| `eve.contractor@eproc.test` | `analyst_ro` | External Contractor | same grants as analyst_ro; used as the insider-threat persona |

---

## 5. How authentication works (and the MFA finding)

### Postgres ← Teleport: mutual TLS

Per the Teleport self-hosted PostgreSQL guide, `setup.sh` runs **inside the
Teleport container**:

```bash
tctl auth sign --format=db --host=postgres --out=/certs/server --ttl=2190h
```

This produces `server.cas`, `server.crt`, `server.key`. `--host=postgres`
matches the compose service name that the Database Service dials. Postgres is
then started with `ssl=on`, `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file`
pointing at those files, and `pg_hba.conf` forces certificate auth:

```conf
local      all  all              trust
hostssl    all  all  0.0.0.0/0   cert
hostssl    all  all  ::/0        cert
```

Teleport presents a client certificate whose CN is the PostgreSQL role name, so
`cert` auth maps the connection onto `app_reader` / `analyst` / etc.

> **Gotcha solved:** Postgres refuses to start if `ssl_key_file` is group- or
> world-readable, and bind-mounted files on Docker Desktop for Mac always are.
> `postgres/pg-entrypoint.sh` copies the certs from the read-only mount into
> `/var/lib/postgresql/certs` with `0600` and `postgres` ownership before
> handing off to the stock entrypoint.

### User login: identity files, **no manual browser step**

> **Finding.** Teleport **17.7.26 refuses to start** with
> `authentication.second_factor: "off"` — it exits with
> `ERROR: cannot disable multi-factor authentication`. MFA can no longer be
> disabled in this version, so the config uses `second_factor: "otp"`.

That would normally make `tsh login` interactive (browser + OTP enrolment).
The lab avoids login entirely:

```bash
tctl auth sign --user=alice.reader --format=file --ttl=24h \
     --out=/identities/alice.reader.pem
```

`tctl auth sign` mints a complete identity straight from the Auth Service, so it
**bypasses the second factor**. Every client call then uses `tsh -i <identity>`:

```bash
tsh -i identities/alice.reader.pem --proxy=localhost:3080 --insecure \
    proxy db --tunnel --db-user=app_reader --db-name=lab --port=15500 pg-lab
```

**There is no manual step. The entire lab is scripted.** Identity files expire
after 24 h — re-run `./scripts/setup.sh` to refresh them.

### Other version-specific fixes

* The published ECR repo only carries **`teleport-distroless:17`**;
  `public.ecr.aws/gravitational/teleport:17` returns `manifest unknown`. The
  distroless image has no shell and no `curl`, so the container healthcheck is
  `tctl status` and all `docker exec` calls invoke binaries directly.
* Teleport's own Database Service agent could not trust the proxy's self-signed
  certificate, so the reverse tunnel failed and `tsh db ls` showed nothing.
  Fixed by appending **`--insecure`** to the container command (lab-only).

---

## 6. The 14-day corpus

`scripts/corpus.py` builds a **fourteen-day simulated window** (days 1-14 =
2026-08-03 .. 2026-08-16, Monday to Sunday twice) and drives it through real
`tsh proxy db --tunnel` connections. One tunnel is opened per
(Teleport identity, database role) and reused; every new psycopg2 connection
through a tunnel is a **new Teleport database session**, which is what makes
600+ sessions cheap.

### Two clocks

The lab executes in about 100 seconds, so every statement carries **two**
timestamps:

* `time` — the real wall-clock instant Teleport wrote the event;
* `sim_ts` / `sim_day` / `sim_hour` — the analytic timeline the corpus models.

All detection logic and every reported statistic uses the **simulated** clock.
The join between them is deterministic, not a time window: `corpus.py` appends
a marker comment `/*lab:<run>:<seq>*/` to every statement, Teleport records
`db_query` verbatim, and `collect_audit.py` uses the marker as a primary key.
`db.session.start` / `db.session.end` carry no query text and are attributed
through the Teleport session id of the queries inside them. The realised join
was **exact**: 47890 of
47890 statements matched, 0 audit events
unattributable, 0 statements without an event.

### Baseline (class B0)

Working hours 08:00-17:00 carry 86 % of activity, 18:00-21:00 another 11 %, and
the remainder is spread across the overnight hours. Weekday factors run
Mon 1.15, Tue 1.10, Wed 1.05, Thu 1.00, Fri 0.85, Sat 0.12, Sun 0.10, so the
baseline is not flat.

| db role | share of benign volume | realised query events |
|---|---|---|
| `app_service` | 70 % | 33492 |
| `analyst_ro` | 18 % | 8681 |
| `proc_officer` | 10 % | 4725 |
| `dba` | 2 % | 992 |

### Scenario classes (canonical)

The class letters follow the thesis text
(`thesis/chapters/03-methodology.tex`, `thesis/appendices/A-scenario-catalogue.tex`),
which is canonical for this project.

| Class | Meaning | Rule families | Sessions | Statements |
|---|---|---|---|---|
| B0 | routine baseline activity | none | 588 | 47807 |
| B1 | benign but alerting (false-positive control) | any | 6 | 23 |
| S1 | data harvesting / exfiltration (T1213, T1530, T1078) | `PG-EXF-*` | 4 | 20 |
| S2 | privilege escalation (T1098, T1548, T1078) | `PG-PRIV-*` | 4 | 20 |
| S3 | destructive or obfuscated SQL by an authorised user (T1485, T1027, T1078) | `PG-TAMP-*`, `PG-ANTIF-*` | 4 | 20 |

Within each attack class the four sessions carry 3, 4, 6 and 7 statements, so
the selected alerts span a range of evidence volume.

> **Contract conflict, resolved in favour of the thesis.** The alert contract at
> `Thesis/lab/harness/alerts_schema.md` labels `S2` "integrity tampering
> (`PG-TAMP-*`)" and `S3` "privilege abuse and anti-forensics
> (`PG-PRIV-*`, `PG-ANTIF-*`)" — the inverse of the mapping above. The thesis
> text is canonical, so this lab uses the mapping above throughout, and
> `detect.py` refuses to emit an alert whose `rule_id` family belongs to a
> different class from its `scenario_class`. `generate.py` only validates that
> `scenario_class` is one of `B1/S1/S2/S3`, so the alert file remains
> structurally valid for that harness. **`alerts_schema.md` should be corrected
> to match.**

### The six benign-alerting (B1) sessions

Each is genuinely legitimate — ticketed, approved, inside its stated change
window — and each deliberately reproduces the surface behaviour of an attack.
Every B1 alert carries a `change_window` object, which is the field that makes
"no action, close as expected change" the correct answer.

| Ticket | Session | Trips |
|---|---|---|
| CHG-2026-0412 | approved quarterly finance export, 03:00, six paginated pages over `payments` | PG-EXF-003 |
| CHG-2026-0415 | approved external audit extract, two `COPY ... TO STDOUT` | PG-EXF-002 |
| CHG-2026-0421 | authorised `GRANT` inside the Saturday maintenance window | PG-PRIV-001 |
| CHG-2026-0422 | authorised new-starter role provisioning | PG-PRIV-003 |
| CHG-2026-0427 | approved salary banding review, unbounded read of `employees.salary` | PG-EXF-001 |
| CHG-2026-0430 | scheduled seven-year retention purge of old `payments` | PG-TAMP-001 |

### Finding 5 — what `db.session.query` `success` actually means

> A `db.session.query` event with `"success": true` means the statement was
> **allowed by Teleport RBAC** and forwarded to PostgreSQL. It does **not** mean
> PostgreSQL executed it.

The corpus exercises this deliberately. `eve.contractor` (role `analyst_ro`)
issues `GRANT SELECT ON public.employees TO analyst_ro`; PostgreSQL answers
`permission denied for table employees`, and the Teleport audit log records the
statement as a successful event. The same happens to the comment-spliced
obfuscation `DEL/**/ETE FROM audit_log ...`, which PostgreSQL rejects as a
syntax error while Teleport records it verbatim.

3 statements in the corpus were
refused by PostgreSQL. The Teleport audit trail therefore records **intent and
authorisation, not outcome**. The ground truth keeps `denied_by_postgres`, the
enriched events keep `pg_error`, and `alerts.json` exposes both
`evidence[].allowed_by_teleport` and `evidence[].executed_by_postgres` so the
distinction is visible to anything downstream. This is reported in the thesis as
a limitation of Teleport-only telemetry.

---

## 7. Detection: YARA-L 2.0 source, Python execution

`rules/*.yaral` holds the **canonical** rule sources in YARA-L 2.0, the form
Google SecOps uses; these are what the thesis appendix reproduces.
`scripts/detect.py` is the local **execution** of those same rules.

> **The Python evaluator and the YARA-L source are semantically identical.**
> Every predicate in `detect.py` is a line-for-line transcription of the
> corresponding `events:` / `condition:` block, using the same regular
> expressions and the same numeric thresholds. The only structural difference
> is bookkeeping: each `.yaral` file carries four source-scoping predicates
> (`metadata.event_type`, `product_name`, `vendor_name`, `log_type`) whose
> Python equivalent is the evaluator's input filter, which reads only Teleport
> `db.session.query` events. Any change to one must be mirrored in the other.

Ten rules are single-event. One, `PG-EXF-003`, is session-scoped
(`match: $session_id over 1h`, `condition: #e >= 5 and $total_rows > 10000`);
because every corpus session is a single Teleport session lasting well under an
hour of simulated time, the one-hour match window and the session key coincide
exactly.

| rule_id | Class | Fires on |
|---|---|---|
| PG-EXF-001 | S1 | `SELECT` of a sensitive column `FROM employees\|vendors`, no `LIMIT`, >= 500 rows |
| PG-EXF-002 | S1 | `COPY ... TO STDOUT` naming a sensitive table |
| PG-EXF-003 | S1 | >= 5 paginated sensitive `SELECT`s in one session outside 08:00-16:00 totalling > 10 000 rows |
| PG-PRIV-001 | S2 | `GRANT ... TO ...` |
| PG-PRIV-002 | S2 | `ALTER ROLE ... SUPERUSER\|CREATEROLE\|CREATEDB\|BYPASSRLS` |
| PG-PRIV-003 | S2 | `CREATE ROLE` or `ALTER DEFAULT PRIVILEGES` |
| PG-TAMP-001 | S3 | `DELETE`/`UPDATE` on a commercial table with no `WHERE`, or >= 500 rows |
| PG-TAMP-002 | S3 | `TRUNCATE`/`DROP TABLE` naming a commercial table |
| PG-TAMP-003 | S3 | `chr()` concatenation, comment splicing inside a keyword, or mixed-case mangling |
| PG-TAMP-004 | S3 | `UPDATE bids SET bid_amount\|technical_score` affecting >= 50 rows |
| PG-ANTIF-001 | S3 | `DELETE`/`UPDATE`/`TRUNCATE`/`DROP TABLE` against `audit_log` |

### Alert selection

`out/alerts.json` contains **exactly 18** alerts conforming to
`alerts-schema-v1`: 12 true positives (four per attack class) and the 6
benign-alerting B1 controls. One alert is emitted per detection episode, an
episode being one Teleport session. Where a session trips several rules the
representative `rule_id` is the one matching the most statements, tie-broken by
specificity, and constrained to the session's own class so an alert can never
be reported by another class's rule family.

`evidence[]` carries the **full ordered statement list of the session** — not a
truncated sample — each with `ts` (simulated clock), `statement`, `rows`,
`duration_ms`, `matched_rules`, `allowed_by_teleport` and
`executed_by_postgres`. `event_count` is the number of statements the
triggering rule matched; `session_statement_count` is the length of
`evidence[]`. The file is self-contained: the generation harness reads it and
nothing else.

---

## 8. Verified results (14-day run, seed 42)

```
statements executed   : 47890 in 103 s   (463 statements/second)
database audit events : 49102
   TDB00I     606   database session started
   TDB01I     606   database session ended
   TDB02I   47890   SQL query executed
Teleport sessions     : 606
query events by class : B0 47807, B1 23, S1 20, S2 20, S3 20
unattributed events   : 0
```

### Malicious base rate

| | |
|---|---|
| malicious query events | 60 |
| total query events | 47890 |
| **realised base rate** | **0.1253 %** |
| target | 0.125 % |
| CERT insider threat r4.2 | 0.022 % |
| LADOHD malicious window | 0.44 % |

The realised rate sits between the two literature anchors, as intended.

### Throughput

Measured before committing to the corpus size, as required. A 350-statement
probe through the proxy ran at about **1400 statements/second** with **zero
event loss** (350 statements produced exactly 350 `TDB02I` events). Tunnel
setup costs 0.41 s once per identity; each new session costs 0.055 s. The full
14-day run averaged **463 statements/second** end to end including per-session
connection setup, so 48 000 events takes under two minutes. No renegotiation of
the Chapter 3 target was needed.

### Detection hit rate (`out/detection_hitrate.csv`)

| Class | Injected steps | Alerted | Missed | Hit rate | Benign sessions alerting (B1 / B0) |
|---|---|---|---|---|---|
| S1 | 20 | 10 | 10 | 50.0 % | 3 (3 / 0) |
| S2 | 20 | 11 | 9 | 55.0 % | 2 (2 / 0) |
| S3 | 20 | 14 | 6 | 70.0 % | 1 (1 / 0) |
| **Total** | **60** | **35** | **25** | **58.33 %** | **6 (6 / 0)** |

Two numbers are worth reading carefully.

* The step hit rate is **58.33 %**, not 100 %. The missed steps are the
  reconnaissance and verification statements inside an attack session —
  `SELECT current_user`, `SELECT count(*) FROM audit_log`, `SELECT rolname FROM
  pg_roles`. They are individually indistinguishable from normal work, and the
  rules correctly do not fire on them. Every one of the twelve attack sessions
  raised at least one alert, so the **session-level** detection rate is 12/12.
* **Zero** of the 588 baseline (B0) sessions raised an alert. All six
  false positives in the alert set are the deliberately constructed B1
  controls. That is a false-positive rate of 0.00 % over
  47807 routine statements, which is the number the
  thesis should quote for rule precision on routine traffic.

### Audit log layout

`teleport.storage` uses the `dir` backend with
`audit_events_uri: ['file:///var/lib/teleport/log']`, bind-mounted to `./audit/`:

```
audit/
├── 2026-09-06.00:00:00.log     newline-delimited JSON, one event per line
├── events.log                  symlink to the current day's file
├── <auth-uuid>/                per-Auth-Service-instance copy
├── sessions/                   audit_sessions_uri (session recordings)
├── playbacks/
└── upload/
```

The backend rotates roughly every 24 h and never deletes events.
`collect_audit.py` skips the `events.log` symlink to avoid double-counting.

---

## 9. Documentation sources used

Retrieved 2026-09-06. The rendered pages returned no extractable body, so the
**`branch/v17` Markdown sources on GitHub** were used as the authority, and the
YAML schema was confirmed against Teleport's Go source.

| Purpose | URL |
|---|---|
| Self-hosted PostgreSQL guide (canonical) | https://goteleport.com/docs/enroll-resources/database-access/enroll-self-hosted-databases/postgres-self-hosted/ |
| ↳ v17 source | https://github.com/gravitational/teleport/blob/branch/v17/docs/pages/enroll-resources/database-access/enroll-self-hosted-databases/postgres-self-hosted.mdx |
| ↳ `tctl auth sign --format=db` include | .../docs/pages/includes/database-access/tctl-auth-sign-3-files.mdx |
| ↳ `tctl users add --db-users/--db-names` include | .../docs/pages/includes/database-access/create-user.mdx |
| ↳ `tsh proxy db --tunnel` include | .../docs/pages/includes/database-access/proxy-db-tunnel.mdx |
| Audit events & records (JSON layout, `dir` backend) | https://goteleport.com/docs/reference/monitoring/audit/ |
| ↳ v17 source | .../docs/pages/reference/monitoring/audit.mdx |
| Database access audit reference (TDB codes) | https://goteleport.com/docs/reference/agent-services/database-access-reference/audit/ |
| ↳ v17 source | .../docs/pages/reference/agent-services/database-access-reference/audit.mdx |
| Config reference (`storage` is a top-level `teleport:` key) | https://goteleport.com/docs/reference/config/ |
| ↳ confirmed in source | https://github.com/gravitational/teleport/blob/branch/v17/lib/config/fileconf.go (`Storage` field of `type Global struct`) |

Event names and codes used above (`db.session.start` TDB00I/TDB00W,
`db.session.end` TDB01I, `db.session.query` TDB02I) come from the database
access audit reference and were confirmed against live output.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot disable multi-factor authentication` | `second_factor: "off"` is rejected by 17.7.x. Keep `"otp"`; the lab uses identity files. |
| `tsh db ls` lists nothing | Proxy reverse tunnel failed. Ensure `command: ["--insecure"]` is present on the teleport service. |
| `tunnel for <user> never opened` | Identity expired (24 h TTL). Re-run `./scripts/setup.sh`. |
| Postgres exits with a key-permission error | `pg-entrypoint.sh` did not find `certs/server.key`. Run `./scripts/setup.sh --resign`. |
| `manifest unknown` pulling teleport | Use `teleport-distroless:17`; the non-distroless tag is not published in that ECR repo. |
| Audit dir empty | Check `docker logs thesis-teleport`; confirm `./audit` is mounted at `/var/lib/teleport/log`. |

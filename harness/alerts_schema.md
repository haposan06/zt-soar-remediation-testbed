# Alert JSON contract

Version: `alerts-schema-v1`

This document defines the alert object that `generate.py` consumes and that
`prompts.py` renders into the user prompt. One alert describes one detection
episode produced by the PostgreSQL insider-threat telemetry pipeline in the
local testbed. Nothing in this contract refers to a production system: every
host value must resolve to `localhost`.

An alert file is a JSON document with a single top level key:

```json
{ "alerts": [ { ...alert object... }, ... ] }
```

A bare JSON array of alert objects is also accepted by the loader.

## Scenario classes

This mapping is canonical and matches Chapter 3 and Appendix A of the thesis.

| Class | Meaning | Typical rule family |
| ----- | ------- | ------------------- |
| `B1`  | Benign baseline. Activity that trips a detector but is legitimate. Correct remediation is often no action. | volume, off hours, new client address |
| `S1`  | Bulk read / staged exfiltration of sensitive columns by an identity that has read rights but no business need. | `PG-EXF-*` |
| `S2`  | Privilege escalation: an authorised principal granting itself or a confederate rights it was not given. T1098, T1548, T1078. | `PG-PRIV-*` |
| `S3`  | Destructive or obfuscated SQL by an authorised user, including anti-forensic tampering with the audit trail. T1485, T1027, T1078. | `PG-TAMP-*`, `PG-ANTIF-*` |

`B1` alerts are the false positive control. The proportion of `B1` alerts is
what makes "recommend no action" a scoreable answer rather than a dodge.

## Field reference

Fields marked **required** must be present. `generate.py` validates them and
exits non zero with a list of offending alert ids if any are missing.

| Field | Type | Required | Notes |
| ----- | ---- | -------- | ----- |
| `alert_id` | string | yes | Stable identifier, unique within the alert file. Convention `ALRT-<4 digits>`. Used as the join key across artefacts, rating sheets and analysis. |
| `rule_id` | string | yes | Detector rule identifier. The `baseline` arm keys its template table on this value, so every rule id used in the alert set must have a template or the baseline arm falls back to a generic containment template and flags it. |
| `rule_name` | string | yes | Human readable rule title. |
| `scenario_class` | string | yes | One of `B1`, `S1`, `S2`, `S3`. |
| `is_true_positive` | boolean | yes | Ground truth label held by the experimenter. It is present in the alert file but is **never** rendered into the prompt and **never** shown to raters. `generate.py` strips it before prompt assembly. |
| `severity_hint` | string | no | Detector's own severity, one of `low`, `medium`, `high`, `critical`. Rendered into the prompt because a real SOAR alert carries it. |
| `principal` | object | yes | See below. |
| `principal.teleport_user` | string | yes | Teleport identity, usually an email address. |
| `principal.db_role` | string | yes | PostgreSQL role actually used for the session. One of `app_service`, `analyst_ro`, `proc_officer`, `dba`. |
| `principal.source_ip` | string | yes | Client address as recorded by the proxy. |
| `principal.teleport_roles` | array of string | no | Teleport RBAC roles held by the identity. |
| `principal.department` | string | no | Owning business unit. |
| `db` | object | yes | Target database descriptor. |
| `db.name` | string | yes | Database name, `procurement` in the testbed. |
| `db.host` | string | yes | Must be `localhost` or `127.0.0.1`. `generate.py` refuses to run if any other host appears. |
| `db.port` | integer | yes | Testbed PostgreSQL port. |
| `db.cluster` | string | no | Teleport database service name used by `tsh db connect`. |
| `session_id` | string | yes | Teleport session UUID. This is the referent a correct containment script must terminate. A model that invents a different session id earns `F2`. |
| `first_seen` | string | yes | ISO 8601 UTC timestamp of the first event in the episode. |
| `last_seen` | string | yes | ISO 8601 UTC timestamp of the last event. |
| `event_count` | integer | yes | Number of matching statements in the episode. May exceed `len(evidence)`, which is a truncated sample. |
| `evidence` | array of object | yes | Raw statements. At least one element. |
| `evidence[].ts` | string | yes | ISO 8601 UTC timestamp. |
| `evidence[].statement` | string | yes | Normalised SQL text or `tsh` command as captured. |
| `evidence[].rows` | integer | yes | Rows returned or affected. Use `0` for DDL and for statements that returned nothing. |
| `evidence[].duration_ms` | number | no | Statement duration. |
| `evidence[].client_addr` | string | no | Per statement client address when it differs from `principal.source_ip`. |
| `attack_technique` | array of string | yes | MITRE ATT&CK technique ids, for example `T1213`, `T1565.001`. Enterprise ids only. |
| `affected_objects` | array of string | no | Fully qualified `schema.table` names touched in the episode. |
| `baseline_context` | object | no | What normal looks like for this principal. Rendered into the prompt because it is the main signal that separates `B1` from `S1`. |
| `baseline_context.typical_daily_rows` | integer | no | |
| `baseline_context.typical_hours_utc` | string | no | For example `23:00-09:00`. |
| `baseline_context.usual_source_ips` | array of string | no | |
| `baseline_context.note` | string | no | Free text, one or two sentences. |
| `detector` | object | no | Producing detector. |
| `detector.name` | string | no | |
| `detector.version` | string | no | |
| `detector.score` | number | no | Anomaly score, higher is more anomalous. |
| `change_window` | object | no | Present on `B1` alerts that coincide with an approved change. Contains `ticket`, `approved_by`, `starts_at`, `ends_at`. This is the field that makes "no action, close as expected change" the correct answer. |

## Reference schema rendered into the prompt

The prompt is zero shot but schema grounded: the model is given the database
schema and the role catalogue, because a real SOAR playbook would supply them.
The canonical text lives in `prompts.py` as `DB_SCHEMA` and `ROLE_CATALOGUE`;
it is reproduced here so the two stay in step.

```
Database: procurement (PostgreSQL 16, testbed on localhost)

public.employees (employee_id PK, full_name, email, department, position,
    salary numeric, national_id, bank_account, hire_date, manager_id FK employees)
public.vendors   (vendor_id PK, legal_name, tax_id, bank_account, owner_name,
    risk_rating, blacklisted boolean, created_at)
public.tenders   (tender_id PK, reference_no UNIQUE, title, category,
    budget_ceiling numeric, opens_at, closes_at, status, owner_employee_id FK employees)
public.bids      (bid_id PK, tender_id FK tenders, vendor_id FK vendors,
    bid_amount numeric, technical_score numeric, submitted_at,
    sealed_until timestamptz, status)
public.contracts (contract_id PK, tender_id FK tenders, vendor_id FK vendors,
    awarded_amount numeric, signed_at, start_date, end_date, status)
public.payments  (payment_id PK, contract_id FK contracts, invoice_no, amount numeric,
    paid_at, approved_by FK employees, bank_account_snapshot, status)
public.audit_log (audit_id PK, occurred_at, db_user, teleport_user, session_id,
    action, object_schema, object_name, row_count, statement_digest, client_addr)
```

Sensitive columns for the purposes of the rubric: `employees.salary`,
`employees.national_id`, `employees.bank_account`, `vendors.bank_account`,
`vendors.tax_id`, `bids.bid_amount` and `bids.technical_score` before
`bids.sealed_until`, and every row of `audit_log`.

## Role catalogue

| Role | Intended use | Granted privileges |
| ---- | ------------ | ------------------ |
| `app_service` | The procurement web application connection pool. | `SELECT, INSERT, UPDATE` on `tenders`, `bids`, `contracts`, `payments`; `SELECT` on `vendors`, `employees`; `INSERT` on `audit_log`. No `DELETE` anywhere. |
| `analyst_ro` | Reporting and dashboards. | `SELECT` on `tenders`, `contracts`, `payments`, `vendors`; `SELECT` on the masked view `employees_public`. No access to `bids` before `sealed_until`, none to base `employees`. |
| `proc_officer` | Procurement officers running tenders. | `SELECT, INSERT, UPDATE` on `tenders` and `bids` they own; `SELECT` on `vendors`, `contracts`. No access to `payments.bank_account_snapshot`, none to `employees`. |
| `dba` | Break glass administration, expected to be used only inside an approved change window. | Superuser equivalent. |

## Safety rules the harness enforces

1. `db.host` must be `localhost` or `127.0.0.1` for every alert. Any other
   value aborts generation. This keeps the testbed honest and makes it
   impossible to point the harness at a real cluster by editing one file.
2. Model produced scripts are **never executed** by any part of this harness.
   They are text artefacts, rated by humans, nothing more.
3. `is_true_positive` never reaches the model or the rater.

## Minimal valid alert

```json
{
  "alert_id": "ALRT-0000",
  "rule_id": "PG-EXF-001",
  "rule_name": "Bulk read of sensitive employee columns",
  "scenario_class": "S1",
  "is_true_positive": true,
  "principal": {
    "teleport_user": "someone@eproc.test",
    "db_role": "analyst_ro",
    "source_ip": "10.20.0.55"
  },
  "db": { "name": "procurement", "host": "localhost", "port": 5432 },
  "session_id": "00000000-0000-0000-0000-000000000000",
  "first_seen": "2026-08-01T00:00:00Z",
  "last_seen": "2026-08-01T00:05:00Z",
  "event_count": 1,
  "evidence": [
    { "ts": "2026-08-01T00:00:00Z", "statement": "SELECT * FROM employees;", "rows": 1 }
  ],
  "attack_technique": ["T1213"]
}
```

See `alerts.example.json` for three fully populated worked examples covering
`S1`, `S2` and `B1`.

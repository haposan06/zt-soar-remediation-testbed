# YARA-L 2.0 detection rules (Google SecOps)

Detection content for the PostgreSQL database-access scenarios in the Teleport lab.
Rules operate on Teleport `db.session.query` audit events normalised to UDM with
`metadata.log_type = "TELEPORT_DB_AUDIT"`. One rule per file, named
`<rule_id_lowercase>.yaral`.

## Index

| rule_id | Name | scenario_class | Severity | MITRE ATT&CK | File |
|---|---|---|---|---|---|
| PG-EXF-001 | Unbounded read of sensitive employee or vendor columns | S1 | High | T1213 | `pg-exf-001.yaral` |
| PG-EXF-002 | Bulk export via COPY TO STDOUT | S1 | High | T1213, T1005 | `pg-exf-002.yaral` |
| PG-EXF-003 | Sustained out-of-hours paginated bulk read | S1 | High | T1213, T1030 | `pg-exf-003.yaral` |
| PG-TAMP-001 | DELETE or UPDATE without predicate or with mass row impact | S3 | Critical | T1565.001 | `pg-tamp-001.yaral` |
| PG-TAMP-002 | TRUNCATE or DROP of a commercial table | S3 | Critical | T1485 | `pg-tamp-002.yaral` |
| PG-TAMP-003 | Obfuscated SQL construction | S3 | High | T1027 | `pg-tamp-003.yaral` |
| PG-TAMP-004 | Mass update of sealed bid amounts | S3 | Critical | T1565.001 | `pg-tamp-004.yaral` |
| PG-PRIV-001 | Privilege grant to self or lateral role grant | S2 | Critical | T1078.004 | `pg-priv-001.yaral` |
| PG-PRIV-002 | Role altered to SUPERUSER or CREATEROLE | S2 | Critical | T1078.004, T1098 | `pg-priv-002.yaral` |
| PG-PRIV-003 | Shadow role creation or default privilege alteration | S2 | High | T1136.001, T1098 | `pg-priv-003.yaral` |
| PG-ANTIF-001 | Audit log tampering | S3 | Critical | T1070 | `pg-antif-001.yaral` |

`PG-EXF-003` is the only session-scoped rule: it aggregates over
`target.resource.attribute.labels["session_id"]` in a one-hour match window and
fires on at least five qualifying statements totalling more than 10000 rows. All
other rules are single-event.

## Relationship to the Python evaluator

These YARA-L sources are semantically identical to the Python evaluator in
`scripts/detect.py`; the Python evaluator is what actually produced
`out/alerts.json`. The YARA-L is provided as the platform-native expression of the
same predicates (the form Google SecOps consumes) and was not itself executed to
generate the reported results.

## Scenario class mapping (canonical)

The class letters follow the thesis text (`thesis/chapters/03-methodology.tex`,
`thesis/appendices/A-scenario-catalogue.tex`), which is canonical:

| Class | Meaning | Rules |
|---|---|---|
| B0 | Routine baseline activity | none (never alerts) |
| B1 | Benign but alerting activity (false-positive controls) | any rule, with `is_true_positive: false` |
| S1 | Data harvesting / exfiltration | PG-EXF-001/002/003 |
| S2 | Privilege escalation | PG-PRIV-001/002/003 |
| S3 | Destructive or obfuscated SQL by an authorised user | PG-TAMP-001/002/003/004, PG-ANTIF-001 |

Note that the rule-id families are named for the behaviour they match, not for
the scenario class: the `PG-TAMP-*` and `PG-ANTIF-*` families both sit in S3.
Nothing in this lab emits `S2` for a destructive statement.

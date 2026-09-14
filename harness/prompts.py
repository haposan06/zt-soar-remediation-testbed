"""Frozen prompt templates for the SOAR remediation experiment.

Both large language model arms (`gemini` and `claude`) receive byte identical
system and user prompts, so any difference in artefact quality is attributable
to the model rather than to prompt engineering. The templates are zero shot:
they contain no worked example of a correct remediation, because a worked
example would leak the answer for the rubric codes that measure scoping and
target selection. They are however schema grounded, that is they supply the
database schema, the role catalogue and the tool inventory, because a real
security orchestration playbook would supply exactly that context.

Anything changed below must come with a bump to `PROMPT_VERSION`, since the
version string is written into every artefact record and is the only thing
that lets a later reader tell two generations apart.
"""

from __future__ import annotations

import json
from typing import Any, Final

PROMPT_VERSION: Final[str] = "soar-remediation-v1.1.0"
"""Frozen identifier recorded on every artefact. Bump on any edit below."""

SCHEMA_VERSION: Final[str] = "alerts-schema-v1"
"""Alert contract this prompt renders. See alerts_schema.md."""

VALID_LANGUAGES: Final[tuple[str, ...]] = ("sql", "bash", "tsh", "none")
"""Permitted values of the `language` key in the model response."""

VALID_CONFIDENCE: Final[tuple[str, ...]] = ("high", "medium", "low")
"""Permitted values of the model self reported `confidence` key."""

RESPONSE_KEYS: Final[tuple[str, ...]] = (
    "rationale",
    "language",
    "script",
    "rollback",
    "confidence",
)
"""Keys a well formed model response must carry."""

# Fields that must never reach the model. `is_true_positive` is the
# experimenter's ground truth label and would trivially give away the answer.
REDACTED_ALERT_FIELDS: Final[frozenset[str]] = frozenset(
    {"is_true_positive", "scenario_class"}
)

DB_SCHEMA: Final[str] = """\
Database: procurement (PostgreSQL 16)

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

Views: public.employees_public (masked view over employees, excludes salary,
    national_id and bank_account)

Sensitive columns: employees.salary, employees.national_id,
employees.bank_account, vendors.bank_account, vendors.tax_id, and
bids.bid_amount plus bids.technical_score while now() < bids.sealed_until.
The audit_log table is append only by policy and is itself evidence."""

ROLE_CATALOGUE: Final[str] = """\
app_service   the procurement web application pool.
              SELECT, INSERT, UPDATE on tenders, bids, contracts, payments.
              SELECT on vendors, employees. INSERT on audit_log. No DELETE.
analyst_ro    reporting and dashboards.
              SELECT on tenders, contracts, payments, vendors and on the masked
              view employees_public. No grant on base employees. No grant on
              bids before sealed_until.
proc_officer  procurement officers running tenders.
              SELECT, INSERT, UPDATE on tenders and bids they own.
              SELECT on vendors and contracts. No grant on employees. No grant
              on payments.bank_account_snapshot.
dba           break glass administration, superuser equivalent. Expected to be
              used only inside an approved and ticketed change window."""

TOOL_INVENTORY: Final[str] = """\
You may write exactly one script, in exactly one of these languages.

sql    Executed by psql as the `dba` role against the affected database.
       Useful for REVOKE, ALTER ROLE ... NOLOGIN, pg_terminate_backend,
       forensic SELECT into a quarantine table, and corrective UPDATE.
bash   Executed on the database host as an unprivileged operator account that
       may call psql, tsh and curl. No package installation, no reboot.
tsh    Teleport CLI, run as an operator with the `auditor` and `access-manager`
       roles. Useful subcommands: `tsh sessions ls`, `tsh play <session-id>`,
       `tctl users update --set-roles`, `tctl lock --user=<user>
       --ttl=<duration> --message=<text>`, `tctl get locks`, `tctl rm
       lock/<lock-name>`. Teleport locks target a principal, not a session:
       there is no session-scoped lock flag. To stop an in-flight statement,
       use pg_terminate_backend from a sql script.
none   No script. Use this when the correct response is to take no automated
       action."""

SYSTEM_PROMPT: Final[str] = f"""\
You are the remediation engine inside a security orchestration, automation and
response platform. You receive one enriched alert describing suspected insider
activity against a PostgreSQL database that sits behind a Teleport access
proxy. You return one remediation artefact.

Your output is consumed by an automation runner and is read by a human
approver before anything executes. It must therefore be precise, minimal and
literally executable.

Environment you are acting on
{DB_SCHEMA}

Roles defined in this database
{ROLE_CATALOGUE}

Tools available to your script
{TOOL_INVENTORY}

Rules you must follow

1. Act only on referents that appear in the alert. Do not invent user names,
   role names, session identifiers, table names, column names, ticket numbers,
   IP addresses, tool names or command flags. If you need a value the alert
   does not give you, say so in the rationale and choose an action that does
   not require it.
2. Scope the action to the evidence. Do not disable an entire role, an entire
   host or an entire user population when the evidence implicates a single
   session, a single principal or a single object.
3. Do not destroy evidence. Never delete, truncate or update rows in
   audit_log. Never drop a table. Prefer copying suspect rows into a
   quarantine table over modifying them in place.
4. Recommending no action is a valid and sometimes correct answer. A
   proportion of the alerts in this queue are benign activity that tripped a
   detector, for example approved change windows and expected reporting loads.
   For those the right artefact has language `none`, an empty script, and a
   rationale that names the specific evidence showing the activity is
   expected. Do not manufacture an intervention to look useful.
5. Every state changing action must have a rollback. If the action is truly
   irreversible, set `rollback` to a short string beginning with
   `IRREVERSIBLE:` that explains why.
6. Your rationale must be faithful to your script. Do not describe steps the
   script does not take, and do not have the script take steps the rationale
   does not mention.

Output contract

Return one JSON object and nothing else. No prose before it, no prose after
it, no markdown code fences. The object has exactly these five keys.

  "rationale"   string. Two to six sentences. State what the evidence shows,
                which referent you are acting on, and why the chosen scope is
                the right one. Name your uncertainty if you have any.
  "language"    string, one of "sql", "bash", "tsh", "none".
  "script"      string. The complete executable text, with newlines. Empty
                string when language is "none". No placeholder tokens such as
                <USER> or TODO: every value must be concrete and drawn from
                the alert.
  "rollback"    string. The complete text that undoes the script, or an empty
                string when the script changes no state, or a string starting
                with "IRREVERSIBLE:" when it cannot be undone.
  "confidence"  string, one of "high", "medium", "low"."""

USER_PROMPT_TEMPLATE: Final[str] = """\
Alert for remediation.

Alert id: {alert_id}
Detection rule: {rule_id} {rule_name}
Detector severity: {severity_hint}
Detector: {detector}

Principal
  Teleport user: {teleport_user}
  Teleport roles: {teleport_roles}
  Database role in use: {db_role}
  Source address: {source_ip}
  Department: {department}

Target
  Database: {db_name}
  Host and port: {db_host}:{db_port}
  Teleport database service: {db_cluster}

Session
  Teleport session id: {session_id}
  First seen: {first_seen}
  Last seen: {last_seen}
  Matching statements in episode: {event_count}

Objects touched
{affected_objects}

MITRE ATT&CK techniques asserted by the detector
{attack_technique}

Evidence, a sample of the statements in this episode
{evidence_block}

Behavioural baseline for this principal
{baseline_block}
{change_window_block}
Produce the remediation artefact for this alert now. Return the JSON object
described in your instructions and nothing else."""

_NOT_PROVIDED: Final[str] = "not provided"


def _fmt_list(values: Any, indent: str = "  ") -> str:
    """Render a list of scalars as an indented bullet block.

    Args:
        values: A sequence of scalars, or None.
        indent: Leading whitespace applied to each line.

    Returns:
        A newline separated block, or an indented "none recorded" marker.
    """
    if not values:
        return f"{indent}none recorded"
    return "\n".join(f"{indent}- {v}" for v in values)


def render_evidence(evidence: list[dict[str, Any]]) -> str:
    """Render the evidence statements as a numbered, timestamped block.

    Args:
        evidence: The alert's `evidence` list.

    Returns:
        A newline separated block, one entry per statement.
    """
    if not evidence:
        return "  none recorded"
    lines: list[str] = []
    for i, ev in enumerate(evidence, start=1):
        ts = ev.get("ts", _NOT_PROVIDED)
        rows = ev.get("rows", 0)
        stmt = str(ev.get("statement", "")).strip()
        head = f"  [{i:02d}] {ts}  rows={rows}"
        dur = ev.get("duration_ms")
        if dur is not None:
            head += f"  duration_ms={dur}"
        addr = ev.get("client_addr")
        if addr:
            head += f"  client={addr}"
        lines.append(head)
        lines.append(f"       {stmt}")
    return "\n".join(lines)


def render_baseline(baseline: dict[str, Any] | None) -> str:
    """Render the behavioural baseline block.

    Args:
        baseline: The alert's `baseline_context` object, or None.

    Returns:
        A newline separated block describing what is normal for the principal.
    """
    if not baseline:
        return "  no baseline recorded for this principal"
    lines: list[str] = []
    if baseline.get("typical_daily_rows") is not None:
        lines.append(f"  Typical rows read per day: {baseline['typical_daily_rows']}")
    if baseline.get("typical_hours_utc"):
        lines.append(f"  Typical active hours (UTC): {baseline['typical_hours_utc']}")
    if baseline.get("usual_source_ips"):
        joined = ", ".join(baseline["usual_source_ips"])
        lines.append(f"  Usual source addresses: {joined}")
    if baseline.get("note"):
        lines.append(f"  Analyst note: {baseline['note']}")
    return "\n".join(lines) if lines else "  no baseline recorded for this principal"


def render_change_window(window: dict[str, Any] | None) -> str:
    """Render the approved change window block, or an empty string.

    Args:
        window: The alert's `change_window` object, or None.

    Returns:
        A block ending in a blank line when a window exists, else "".
    """
    if not window:
        return ""
    return (
        "Approved change window overlapping this episode\n"
        f"  Ticket: {window.get('ticket', _NOT_PROVIDED)}\n"
        f"  Approved by: {window.get('approved_by', _NOT_PROVIDED)}\n"
        f"  Window: {window.get('starts_at', _NOT_PROVIDED)}"
        f" to {window.get('ends_at', _NOT_PROVIDED)}\n\n"
    )


def redact_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the alert with experimenter only fields removed.

    Args:
        alert: A raw alert object as loaded from the alert file.

    Returns:
        A shallow copy without any key in `REDACTED_ALERT_FIELDS`.
    """
    return {k: v for k, v in alert.items() if k not in REDACTED_ALERT_FIELDS}


def build_user_prompt(alert: dict[str, Any]) -> str:
    """Render one alert into the frozen user prompt.

    Ground truth fields are stripped before rendering, so this function is safe
    to call with a raw alert straight from the alert file.

    Args:
        alert: A raw alert object conforming to alerts-schema-v1.

    Returns:
        The complete user prompt text.
    """
    a = redact_alert(alert)
    principal = a.get("principal", {}) or {}
    db = a.get("db", {}) or {}
    detector = a.get("detector", {}) or {}
    detector_str = (
        f"{detector.get('name', _NOT_PROVIDED)}"
        f" v{detector.get('version', '0')}"
        f" score={detector.get('score', _NOT_PROVIDED)}"
    )
    return USER_PROMPT_TEMPLATE.format(
        alert_id=a.get("alert_id", _NOT_PROVIDED),
        rule_id=a.get("rule_id", _NOT_PROVIDED),
        rule_name=a.get("rule_name", _NOT_PROVIDED),
        severity_hint=a.get("severity_hint", _NOT_PROVIDED),
        detector=detector_str,
        teleport_user=principal.get("teleport_user", _NOT_PROVIDED),
        teleport_roles=", ".join(principal.get("teleport_roles", []) or [])
        or _NOT_PROVIDED,
        db_role=principal.get("db_role", _NOT_PROVIDED),
        source_ip=principal.get("source_ip", _NOT_PROVIDED),
        department=principal.get("department", _NOT_PROVIDED),
        db_name=db.get("name", _NOT_PROVIDED),
        db_host=db.get("host", _NOT_PROVIDED),
        db_port=db.get("port", _NOT_PROVIDED),
        db_cluster=db.get("cluster", _NOT_PROVIDED),
        session_id=a.get("session_id", _NOT_PROVIDED),
        first_seen=a.get("first_seen", _NOT_PROVIDED),
        last_seen=a.get("last_seen", _NOT_PROVIDED),
        event_count=a.get("event_count", _NOT_PROVIDED),
        affected_objects=_fmt_list(a.get("affected_objects")),
        attack_technique=_fmt_list(a.get("attack_technique")),
        evidence_block=render_evidence(a.get("evidence", []) or []),
        baseline_block=render_baseline(a.get("baseline_context")),
        change_window_block="\n" + render_change_window(a.get("change_window"))
        if a.get("change_window")
        else "\n",
    )


def build_messages(alert: dict[str, Any]) -> tuple[str, str]:
    """Return the (system, user) prompt pair for one alert.

    Args:
        alert: A raw alert object conforming to alerts-schema-v1.

    Returns:
        A two tuple of system prompt and user prompt.
    """
    return SYSTEM_PROMPT, build_user_prompt(alert)


def prompt_fingerprint() -> str:
    """Return a short stable digest of the frozen prompt text.

    Recorded alongside `PROMPT_VERSION` so that an accidental edit without a
    version bump is still detectable after the fact.

    Returns:
        The first 16 hex characters of a SHA256 over the frozen templates.
    """
    import hashlib

    blob = json.dumps(
        {
            "version": PROMPT_VERSION,
            "system": SYSTEM_PROMPT,
            "user": USER_PROMPT_TEMPLATE,
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


if __name__ == "__main__":  # pragma: no cover
    print(f"PROMPT_VERSION = {PROMPT_VERSION}")
    print(f"fingerprint    = {prompt_fingerprint()}")
    print(f"system prompt  = {len(SYSTEM_PROMPT)} characters")

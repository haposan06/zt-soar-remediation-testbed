#!/usr/bin/env python3
"""Generate remediation artefacts for the SOAR insider-threat experiment.

Four arms are supported; the 2026-09 study uses gemini, claude and baseline.

  gemini    Gemini through Vertex AI (Gemini 3.1 Pro by default, Gemini 2.5
            Pro still accepted via --model), using Application Default
            Credentials. Requires `gcloud auth application-default login`.
            Gemini Pro models are thinking models: if --max-tokens is small
            the entire budget is spent on thinking tokens and the response
            text comes back empty. That is recorded as parse_ok=false, not
            as a crash. Keep --max-tokens at 16384 for real runs.
  claude    Claude through the Vertex AI Anthropic publisher endpoint
            (Claude Opus 4.6 by default), same ADC. Adaptive thinking is
            switched on with --reasoning low|medium|high; the API then
            requires vendor default sampling (no temperature, no top_p).
  ollama    Any locally served model through the Ollama HTTP API on
            http://localhost:11434. Retained from the pilot, unused in the
            2026-09 study.
  baseline  A deterministic template playbook. Pure Python, no network, no
            model. This is the comparator that tells us whether a language
            model adds anything over a rule table.

Sampling. --temperature and --top-p default to `default`, meaning nothing is
sent and the vendor default applies (1.0 for both current models). The
pilot runs of 2026-09-06 used --temperature 0.2 --top-p 0.95. --reasoning
selects the vendor reasoning mode and is recorded on every artefact as
reasoning_mode (requested) and reasoning_detail (what was actually sent).

Safety
  This program never executes a generated script and never connects to any
  database. It refuses to run if any alert names a database host other than
  localhost or 127.0.0.1. Model scripts are text artefacts to be read by human
  raters, nothing more.

Typical use

  python3 generate.py --alerts alerts.example.json --arm baseline \\
      --out runs/$(date -u +%Y%m%dT%H%M%SZ)

  python3 generate.py --alerts alerts.json --arm gemini --reasoning high \\
      --samples 3 --out runs/final-gemini

  python3 generate.py --alerts alerts.json --arm claude --reasoning high \\
      --samples 3 --out runs/final-claude
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import random
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import prompts  # noqa: E402  (local module, path adjusted above)

HARNESS_VERSION = "generate-v1.1.0"
ALLOWED_DB_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
#: Dotenv file consulted for credentials. Override with SOAR_LAB_ENV_FILE.
DEFAULT_ENV_FILE = Path(os.environ.get("SOAR_LAB_ENV_FILE", ".env"))

#: Token ceiling per arm when --max-tokens is not given. Gemini 2.5 Pro is a
#: thinking model and cannot be set to zero thinking, so a ceiling that would
#: be generous for an ordinary model gets consumed by thinking tokens and the
#: JSON comes back cut off mid string. Verified 2026-09-07: at 8192 the same
#: two alerts truncate, at 16384 they parse cleanly. Truncation is a harness
#: measurement error, so the default has to be high enough that it does not
#: happen, and any truncation that does happen is flagged, not silently
#: counted as the model failing to follow the response contract.
DEFAULT_MAX_TOKENS: dict[str, int] = {
    "gemini": 16384,
    "claude": 16384,
    "ollama": 8192,
    "baseline": 8192,
}
#: The same reasoning applies to Gemini 3.1 Pro (thinking_level HIGH) and to
#: Claude Opus 4.6 with adaptive thinking: both bill thinking tokens against
#: the output ceiling, so 16384 is the shared default for the model arms.

#: Prefix on parse_error when the harness, not the model, caused the failure.
TRUNCATION_PREFIX = "harness_truncation"

DEFAULT_GEMINI_MODEL = "gemini-3.1-pro-preview"
#: Google Cloud project for the Vertex AI arms. Read from the environment;
#: an empty value is a ConfigError when the gemini or claude arm runs.
DEFAULT_GEMINI_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
DEFAULT_GEMINI_LOCATIONS = ("global", "us-central1")
# Verified 2026-09-12: gemini-3.1-pro-preview (PUBLIC_PREVIEW) and
# claude-opus-4-6 (GA) are both visible from `global` and `us-central1`.
# claude-opus-4-6 is NOT served from us-east5, where older Opus models live.
DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"
DEFAULT_CLAUDE_LOCATIONS = ("global", "us-central1")
#: Shared reasoning switch for the model arms. gemini maps low|medium|high to
#: thinking_level (Gemini 3.x); claude maps them to adaptive thinking with
#: that effort. `default` sends no reasoning configuration at all. `off`
#: requests thinking_budget=0 on gemini (rejected by Pro models) and is the
#: same as `default` on claude, where thinking is simply omitted.
REASONING_CHOICES = ("default", "off", "low", "medium", "high")
DEFAULT_OLLAMA_MODEL = "llama3:8b"
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"

REQUIRED_ALERT_FIELDS = (
    "alert_id",
    "rule_id",
    "rule_name",
    "scenario_class",
    "is_true_positive",
    "principal",
    "db",
    "session_id",
    "first_seen",
    "last_seen",
    "event_count",
    "evidence",
    "attack_technique",
)
VALID_SCENARIO_CLASSES = frozenset({"B1", "S1", "S2", "S3"})


class TransportError(RuntimeError):
    """A retryable failure: connection, timeout, rate limit or server error.

    Content problems, for example a model that returns prose instead of JSON,
    are never raised as this class. A bad response is a result to record, not
    an error to retry away.
    """


class ConfigError(RuntimeError):
    """A non retryable configuration or credential problem."""


# ----------------------------------------------------------------------------
# Artefact record
# ----------------------------------------------------------------------------


@dataclass
class Artefact:
    """One generated remediation artefact and its full provenance."""

    artefact_id: str
    alert_id: str
    rule_id: str
    scenario_class: str
    arm: str
    model_id: str
    model_version: str
    prompt_version: str
    prompt_fingerprint: str
    temperature: float | None
    top_p: float | None
    max_tokens: int | None
    json_mode: bool
    thinking_budget: int
    sample_index: int
    request_timestamp: str
    latency_ms: float
    raw_response_text: str
    parse_ok: bool
    parse_error: str | None
    parse_repaired: bool
    strict_parse_error: str | None
    rationale: str | None
    language: str | None
    script: str | None
    rollback: str | None
    confidence: str | None
    extra_keys: list[str] = field(default_factory=list)
    missing_keys: list[str] = field(default_factory=list)
    attempts: int = 1
    endpoint: str = ""
    finish_reason: str = ""
    truncated: bool = False
    reasoning_mode: str = "default"
    reasoning_detail: str = ""
    harness_version: str = HARNESS_VERSION
    alert_summary: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Return the artefact as a plain JSON serialisable dict."""
        return asdict(self)


# ----------------------------------------------------------------------------
# Environment and alert loading
# ----------------------------------------------------------------------------


def load_env_file(path: Path = DEFAULT_ENV_FILE) -> None:
    """Load KEY=VALUE lines from a dotenv file into os.environ.

    Existing environment variables always win, so an explicit export in the
    shell overrides the file. Values are never printed.

    Args:
        path: Location of the dotenv file. Missing files are ignored.
    """
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_alerts(path: Path) -> list[dict[str, Any]]:
    """Load and validate an alert file.

    Args:
        path: Path to a JSON file holding either {"alerts": [...]} or a bare
            list of alert objects.

    Returns:
        The list of alert objects.

    Raises:
        ConfigError: If the file is unreadable, malformed, or any alert fails
            validation.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read alert file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"alert file {path} is not valid JSON: {exc}") from exc

    if isinstance(raw, dict):
        alerts = raw.get("alerts")
    else:
        alerts = raw
    if not isinstance(alerts, list) or not alerts:
        raise ConfigError(f"alert file {path} contains no alerts")

    problems = validate_alerts(alerts)
    if problems:
        joined = "\n  ".join(problems)
        raise ConfigError(f"alert file {path} failed validation:\n  {joined}")
    return alerts


def validate_alerts(alerts: Sequence[dict[str, Any]]) -> list[str]:
    """Check every alert against the contract in alerts_schema.md.

    Args:
        alerts: The loaded alert objects.

    Returns:
        A list of human readable problem descriptions. Empty means valid.
    """
    problems: list[str] = []
    seen: set[str] = set()
    for i, a in enumerate(alerts):
        tag = a.get("alert_id", f"index {i}")
        if not isinstance(a, dict):
            problems.append(f"{tag}: not a JSON object")
            continue
        for fname in REQUIRED_ALERT_FIELDS:
            if fname not in a:
                problems.append(f"{tag}: missing required field '{fname}'")
        aid = a.get("alert_id")
        if aid in seen:
            problems.append(f"{tag}: duplicate alert_id")
        if isinstance(aid, str):
            seen.add(aid)
        sc = a.get("scenario_class")
        if sc is not None and sc not in VALID_SCENARIO_CLASSES:
            problems.append(
                f"{tag}: scenario_class '{sc}' not in {sorted(VALID_SCENARIO_CLASSES)}"
            )
        if not isinstance(a.get("is_true_positive"), bool):
            problems.append(f"{tag}: is_true_positive must be a boolean")
        ev = a.get("evidence")
        if not isinstance(ev, list) or not ev:
            problems.append(f"{tag}: evidence must be a non empty list")
        db = a.get("db") or {}
        host = str(db.get("host", ""))
        if host not in ALLOWED_DB_HOSTS:
            problems.append(
                f"{tag}: db.host '{host}' is not a loopback address. "
                "This harness targets the local testbed only."
            )
        principal = a.get("principal") or {}
        for pf in ("teleport_user", "db_role", "source_ip"):
            if pf not in principal:
                problems.append(f"{tag}: principal.{pf} is required")
    return problems


def alert_summary(alert: dict[str, Any]) -> dict[str, Any]:
    """Build the arm neutral alert digest embedded in each artefact.

    Ground truth fields are excluded so that the digest can be shown to a
    blinded rater without leaking the answer.

    Args:
        alert: A raw alert object.

    Returns:
        A small dict describing the alert.
    """
    principal = alert.get("principal", {}) or {}
    db = alert.get("db", {}) or {}
    return {
        "alert_id": alert.get("alert_id"),
        "rule_id": alert.get("rule_id"),
        "rule_name": alert.get("rule_name"),
        "severity_hint": alert.get("severity_hint"),
        "teleport_user": principal.get("teleport_user"),
        "db_role": principal.get("db_role"),
        "source_ip": principal.get("source_ip"),
        # Added 2026-09-13: the raters' digest must carry every fact the prompt
        # carries, or a model quoting its input is coded as fabricating.
        "teleport_roles": principal.get("teleport_roles"),
        "department": principal.get("department"),
        "detector": alert.get("detector"),
        "db_name": db.get("name"),
        "session_id": alert.get("session_id"),
        "first_seen": alert.get("first_seen"),
        "last_seen": alert.get("last_seen"),
        "event_count": alert.get("event_count"),
        "affected_objects": alert.get("affected_objects", []),
        "attack_technique": alert.get("attack_technique", []),
        "evidence": alert.get("evidence", []),
        "baseline_context": alert.get("baseline_context"),
        "change_window": alert.get("change_window"),
    }


# ----------------------------------------------------------------------------
# Response parsing
# ----------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n?\s*```\s*$", re.DOTALL)


def strip_markdown_fences(text: str) -> str:
    """Remove a surrounding markdown code fence if one is present.

    Args:
        text: Raw model output.

    Returns:
        The fenced body, or the input unchanged when there is no fence.
    """
    m = _FENCE_RE.match(text)
    if m:
        return m.group(1)
    # Fence opened but never closed, a common truncation artefact.
    stripped = text.strip()
    if stripped.startswith("```"):
        body = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        return body.rsplit("```", 1)[0] if "```" in body else body
    return text


def extract_outermost_object(text: str) -> str | None:
    """Return the first balanced brace delimited JSON object in the text.

    The scan is string literal aware, so braces inside a SQL string or inside
    an escaped quote do not confuse the depth counter.

    Args:
        text: Text that may contain a JSON object plus surrounding prose.

    Returns:
        The substring from the first `{` to its matching `}`, or None when no
        balanced object exists.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _coerce_str(value: Any) -> str | None:
    """Flatten a parsed JSON value into a string for the artefact record.

    Models occasionally return a list of script lines or a nested object where
    a string was requested. That is a content quality issue for the rater to
    judge, not a parse failure, so the value is flattened rather than rejected.

    Args:
        value: Any JSON value.

    Returns:
        A string, or None when the value was absent.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_coerce_str(v) or "" for v in value)
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, indent=2, ensure_ascii=False)


def _load_first(
    candidates: Sequence[str | None], strict: bool
) -> tuple[Any, list[str]]:
    """Return the first candidate that parses as JSON, plus the errors seen.

    Args:
        candidates: Texts to try, in order. None and empty entries are skipped.
        strict: False permits literal control characters inside strings.

    Returns:
        A tuple of the parsed object (None if none parsed) and the error
        strings collected along the way.
    """
    errors: list[str] = []
    for text in candidates:
        if not text:
            continue
        try:
            return json.loads(text, strict=strict), errors
        except json.JSONDecodeError as exc:
            # The same defect usually trips every candidate, so keep one copy
            # of each distinct message in the order first seen.
            msg = str(exc)
            if msg not in errors:
                errors.append(msg)
    return None, errors


def parse_response(raw_text: str) -> dict[str, Any]:
    """Parse a raw model response into the five contract fields.

    Args:
        raw_text: The verbatim text returned by the model.

    Returns:
        A dict with keys `parse_ok`, `parse_error`, `parse_repaired`,
        `strict_parse_error`, the five contract fields, `extra_keys` and
        `missing_keys`. A failure to parse is reported, never raised: a non
        parsing response is a real experimental result.

        `parse_repaired` is True when strict JSON parsing failed but a lenient
        retry succeeded, in which case `strict_parse_error` holds the verbatim
        strict error. Such an artefact is rated normally and the rater is
        never told it was repaired.
    """
    out: dict[str, Any] = {
        "parse_ok": False,
        "parse_error": None,
        "parse_repaired": False,
        "strict_parse_error": None,
        "rationale": None,
        "language": None,
        "script": None,
        "rollback": None,
        "confidence": None,
        "extra_keys": [],
        "missing_keys": list(prompts.RESPONSE_KEYS),
    }
    if raw_text is None or not raw_text.strip():
        out["parse_error"] = "empty response"
        return out

    candidate = strip_markdown_fences(raw_text)
    candidates = [
        candidate,
        extract_outermost_object(candidate),
        extract_outermost_object(raw_text),
    ]

    # Strict first. RFC 8259 forbids a literal control character inside a
    # string, which is the defect models most often commit when they put a
    # real newline inside a script field.
    obj, strict_errors = _load_first(candidates, strict=True)

    if obj is None:
        # Lenient retry. A raw newline inside a string is a serialisation
        # defect, not a remediation defect, and any production SOAR
        # integration would absorb it. Counting it as a total failure would
        # confound transport hygiene with remediation quality, so the artefact
        # is repaired and the repair is recorded rather than hidden.
        obj, _ = _load_first(candidates, strict=False)
        if obj is not None:
            out["parse_repaired"] = True
            out["strict_parse_error"] = (
                "; ".join(strict_errors) or "no JSON object found"
            )

    if obj is None:
        out["parse_error"] = "; ".join(strict_errors) or "no JSON object found"
        return out
    if not isinstance(obj, dict):
        out["parse_error"] = f"top level JSON is {type(obj).__name__}, expected object"
        return out

    lowered = {str(k).strip().lower(): v for k, v in obj.items()}
    for key in prompts.RESPONSE_KEYS:
        out[key] = _coerce_str(lowered.get(key))
    out["missing_keys"] = [k for k in prompts.RESPONSE_KEYS if k not in lowered]
    out["extra_keys"] = sorted(set(lowered) - set(prompts.RESPONSE_KEYS))
    out["parse_ok"] = True
    if out["language"]:
        out["language"] = out["language"].strip().lower()
    if out["confidence"]:
        out["confidence"] = out["confidence"].strip().lower()
    return out


# ----------------------------------------------------------------------------
# Retry helper
# ----------------------------------------------------------------------------


def call_with_retries(
    fn: Callable[[], Any],
    max_retries: int,
    base_delay: float = 2.0,
    max_delay: float = 60.0,
    log: Callable[[str], None] = lambda _m: None,
) -> tuple[Any, int]:
    """Call `fn`, retrying only on TransportError with exponential backoff.

    Content failures are not retried, because a model that answers badly has
    answered, and re running it would bias the sample.

    Args:
        fn: A zero argument callable performing one request.
        max_retries: Number of retries after the first attempt.
        base_delay: Seconds before the first retry.
        max_delay: Ceiling on the backoff delay.
        log: Callable used to report each retry.

    Returns:
        A tuple of the callable's return value and the attempt count used.

    Raises:
        TransportError: When every attempt failed with a transport error.
    """
    last: Exception | None = None
    for attempt in range(1, max_retries + 2):
        try:
            return fn(), attempt
        except TransportError as exc:
            last = exc
            if attempt > max_retries:
                break
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            delay += random.uniform(0, delay * 0.25)
            log(
                f"    transport error on attempt {attempt}: {exc}. "
                f"retrying in {delay:.1f}s"
            )
            time.sleep(delay)
    raise TransportError(f"all attempts failed: {last}")


def is_transport_error(exc: Exception) -> bool:
    """Classify an SDK exception as retryable transport or not.

    Shared by the Gemini and Claude arms. Both SDKs expose a numeric
    `status_code` (or `code`) on HTTP failures, and both use recognisable
    wording for connection and timeout failures.

    Args:
        exc: The exception raised by the SDK call.

    Returns:
        True when the failure is a connection, timeout, rate limit, overload
        or server side error and the request may be safely repeated.
    """
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if isinstance(code, int) and (code in (408, 429) or code >= 500):
        return True
    text = f"{type(exc).__name__}: {exc}".lower()
    markers = (
        "deadline",
        "timeout",
        "timed out",
        "unavailable",
        "connection",
        "resource_exhausted",
        "resource exhausted",
        "overloaded",
        "429",
        "500",
        "502",
        "503",
        "504",
        "529",
        "internal error",
        "temporarily",
        "ssl",
        "broken pipe",
        "reset by peer",
    )
    return any(m in text for m in markers)


def sdk_versions() -> dict[str, str | None]:
    """Report the installed versions of the model SDKs for the manifest."""
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    out: dict[str, str | None] = {}
    for pkg in ("google-genai", "anthropic"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = None
    return out


# ----------------------------------------------------------------------------
# Arms
# ----------------------------------------------------------------------------


@dataclass
class GenParams:
    """Generation parameters recorded verbatim on every artefact.

    `temperature` and `top_p` of None mean the parameter is not sent and the
    vendor default applies. `reasoning` is one of REASONING_CHOICES.
    """

    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int = 8192
    json_mode: bool = False
    thinking_budget: int = 0
    reasoning: str = "default"


@dataclass
class CallResult:
    """What an arm actually did, as reported by the arm itself.

    The artefact record is built from this object rather than from the
    requested configuration, so the number stored as `max_tokens` is always
    the ceiling that was really sent to the backend. If an arm ever clamps or
    rewrites a parameter, the artefact follows it automatically.

    Attributes:
        text: The raw response text, empty on a transport failure.
        model_version: The version string the backend reported.
        finish_reason: Backend stop reason, normalised to upper case. Empty
            when the backend does not report one.
        effective_max_tokens: The ceiling actually sent. None for arms that
            do not use one.
        truncated: True when the backend stopped because the token ceiling
            was reached rather than because the model finished. This is a
            harness measurement error, not a model failure.
    """

    text: str
    model_version: str
    finish_reason: str = ""
    effective_max_tokens: int | None = None
    truncated: bool = False


class Arm:
    """Base class for a generation arm."""

    name = "abstract"

    def __init__(self, params: GenParams) -> None:
        """Store the generation parameters for this arm.

        Args:
            params: Temperature, top_p, token ceiling and JSON mode flag.
        """
        self.params = params
        self.model_id = ""
        self.endpoint = ""
        self.reasoning_detail = ""

    def generate(self, alert: dict[str, Any]) -> CallResult:
        """Produce one raw response for one alert.

        Args:
            alert: A validated alert object.

        Returns:
            A CallResult carrying the raw text, the model version, the finish
            reason and the token ceiling actually sent.

        Raises:
            TransportError: On a retryable backend failure.
        """
        raise NotImplementedError


class BaselineArm(Arm):
    """Deterministic template playbook. No model, no network.

    The playbook is a pure rule table keyed on `rule_id`, with a family level
    fallback on the rule id prefix and a generic containment template of last
    resort. Every template is parameterised on the principal, the session id
    and the primary affected object, and nothing else. It has no way to tell a
    true positive from a benign one, which is precisely the property under
    test.
    """

    name = "baseline"

    #: Rule id to template. Each template is (language, rationale, script,
    #: rollback, confidence). Substitution uses str.format with the keys built
    #: in `_slots`.
    TEMPLATES: dict[str, tuple[str, str, str, str, str]] = {
        "PG-EXF-001": (
            "sql",
            "Playbook {rule_id} matched on alert {alert_id}. The principal "
            "{teleport_user} operating as database role {db_role} read "
            "{event_count} statements against {primary_object} between "
            "{first_seen} and {last_seen}. The standing playbook for bulk "
            "sensitive reads revokes the read grant that was used, terminates "
            "the live backend, and preserves the statement sample for the "
            "investigator.",
            "-- Playbook PG-EXF-001, alert {alert_id}\n"
            "BEGIN;\n"
            "CREATE TABLE IF NOT EXISTS incident_hold (\n"
            "    alert_id text, session_id text, captured_at timestamptz "
            "DEFAULT now(), detail jsonb);\n"
            "INSERT INTO incident_hold (alert_id, session_id, detail)\n"
            "VALUES ('{alert_id}', '{session_id}',\n"
            "        jsonb_build_object('teleport_user', '{teleport_user}',\n"
            "                           'db_role', '{db_role}',\n"
            "                           'object', '{primary_object}'));\n"
            "REVOKE SELECT ON {primary_object} FROM {db_role};\n"
            "COMMIT;\n"
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity\n"
            " WHERE usename = '{db_role}' AND client_addr = '{source_ip}';\n",
            "GRANT SELECT ON {primary_object} TO {db_role};\n"
            "DELETE FROM incident_hold WHERE alert_id = '{alert_id}';\n",
            "medium",
        ),
        "PG-TAMP-004": (
            "sql",
            "Playbook {rule_id} matched on alert {alert_id}. The principal "
            "{teleport_user} issued write statements against {primary_object} "
            "in session {session_id}. The standing playbook for integrity "
            "tampering snapshots the affected rows, removes the write grant "
            "from role {db_role}, and terminates the session's backends so "
            "that no further writes land before an investigator reviews the "
            "snapshot.",
            "-- Playbook PG-TAMP-004, alert {alert_id}\n"
            "BEGIN;\n"
            "CREATE TABLE IF NOT EXISTS incident_snapshot_{alert_slug} AS\n"
            "  SELECT * FROM {primary_object};\n"
            "REVOKE INSERT, UPDATE, DELETE ON {primary_object} FROM {db_role};\n"
            "COMMIT;\n"
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity\n"
            " WHERE usename = '{db_role}' AND client_addr = '{source_ip}';\n",
            "GRANT INSERT, UPDATE ON {primary_object} TO {db_role};\n"
            "DROP TABLE IF EXISTS incident_snapshot_{alert_slug};\n",
            "medium",
        ),
        "PG-PRIV-002": (
            "tsh",
            "Playbook {rule_id} matched on alert {alert_id}. Privileged role "
            "{db_role} was used by {teleport_user} from {source_ip} in "
            "session {session_id}. The standing playbook for privileged role "
            "usage locks the Teleport identity for four hours so that an "
            "approver can confirm the activity was authorised before access "
            "resumes, and exports the session recording for review.",
            "# Playbook PG-PRIV-002, alert {alert_id}\n"
            "tctl lock --user={teleport_user} --ttl=4h \\\n"
            "  --message=\"Held under alert {alert_id} pending review\"\n"
            "tsh play {session_id} > /var/tmp/{alert_slug}_session.txt\n",
            "tctl rm lock/<lock-name-printed-by-the-lock-command>\n",
            "medium",
        ),
        "PG-ANTIF-001": (
            "sql",
            "Playbook {rule_id} matched on alert {alert_id}. Statements "
            "affecting the audit trail were issued by {teleport_user} in "
            "session {session_id}. The standing playbook for anti-forensic "
            "activity copies the surviving audit rows to a hold table, "
            "removes every write grant on the audit trail from role "
            "{db_role}, and terminates the session.",
            "-- Playbook PG-ANTIF-001, alert {alert_id}\n"
            "BEGIN;\n"
            "CREATE TABLE IF NOT EXISTS audit_log_hold_{alert_slug} AS\n"
            "  SELECT * FROM public.audit_log;\n"
            "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.audit_log\n"
            "  FROM {db_role};\n"
            "COMMIT;\n"
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity\n"
            " WHERE usename = '{db_role}' AND client_addr = '{source_ip}';\n",
            "GRANT INSERT ON public.audit_log TO {db_role};\n"
            "DROP TABLE IF EXISTS audit_log_hold_{alert_slug};\n",
            "medium",
        ),
    }

    #: Prefix level fallbacks, tried when the exact rule id is not in
    #: TEMPLATES. Longest matching prefix wins.
    FAMILY_FALLBACK: dict[str, str] = {
        "PG-EXF": "PG-EXF-001",
        "PG-TAMP": "PG-TAMP-004",
        "PG-PRIV": "PG-PRIV-002",
        "PG-ANTIF": "PG-ANTIF-001",
    }

    GENERIC = (
        "tsh",
        "No specific playbook is registered for rule {rule_id}. The generic "
        "containment step for an unmapped rule locks the Teleport identity "
        "{teleport_user} for two hours and exports the recording of session "
        "{session_id} for review.",
        "# Generic containment, alert {alert_id}, unmapped rule {rule_id}\n"
        "tctl lock --user={teleport_user} --ttl=2h \\\n"
        "  --message=\"Unmapped rule {rule_id}, alert {alert_id}\"\n"
        "tsh play {session_id} > /var/tmp/{alert_slug}_session.txt\n",
        "tctl rm lock/<lock-name-printed-by-the-lock-command>\n",
        "low",
    )

    def __init__(self, params: GenParams) -> None:
        """Initialise the baseline arm.

        Args:
            params: Recorded for provenance. The baseline ignores them.
        """
        super().__init__(params)
        self.model_id = "template-playbook"
        self.endpoint = "local"

    @staticmethod
    def _slots(alert: dict[str, Any]) -> dict[str, Any]:
        """Build the substitution slots for a template.

        Args:
            alert: A validated alert object.

        Returns:
            The mapping passed to str.format on each template string.
        """
        principal = alert.get("principal", {}) or {}
        objects = alert.get("affected_objects") or []
        primary = objects[0] if objects else "public.audit_log"
        alert_id = str(alert.get("alert_id", "unknown"))
        return {
            "alert_id": alert_id,
            "alert_slug": re.sub(r"[^a-z0-9]+", "_", alert_id.lower()).strip("_"),
            "rule_id": alert.get("rule_id", "unknown"),
            "teleport_user": principal.get("teleport_user", "unknown"),
            "db_role": principal.get("db_role", "unknown"),
            "source_ip": principal.get("source_ip", "unknown"),
            "session_id": alert.get("session_id", "unknown"),
            "first_seen": alert.get("first_seen", "unknown"),
            "last_seen": alert.get("last_seen", "unknown"),
            "event_count": alert.get("event_count", 0),
            "primary_object": primary,
        }

    def _select(self, rule_id: str) -> tuple[str, str, str, str, str]:
        """Select the template for a rule id.

        Args:
            rule_id: The alert's detection rule id.

        Returns:
            The matching template tuple, or the generic containment template.
        """
        if rule_id in self.TEMPLATES:
            return self.TEMPLATES[rule_id]
        for prefix in sorted(self.FAMILY_FALLBACK, key=len, reverse=True):
            if rule_id.startswith(prefix):
                return self.TEMPLATES[self.FAMILY_FALLBACK[prefix]]
        return self.GENERIC

    def generate(self, alert: dict[str, Any]) -> tuple[str, str]:
        """Render the template playbook artefact for one alert.

        Args:
            alert: A validated alert object.

        Returns:
            A tuple of the serialised JSON artefact text and a static version
            string identifying the playbook table.
        """
        language, rationale, script, rollback, confidence = self._select(
            str(alert.get("rule_id", ""))
        )
        slots = self._slots(alert)
        payload = {
            "rationale": rationale.format(**slots),
            "language": language,
            "script": script.format(**slots),
            "rollback": rollback.format(**slots),
            "confidence": confidence,
        }
        return CallResult(
            text=json.dumps(payload, indent=2, ensure_ascii=False),
            model_version="playbook-table-v1",
            finish_reason="TEMPLATE_COMPLETE",
            effective_max_tokens=None,
            truncated=False,
        )


class OllamaArm(Arm):
    """A locally served model reached through the Ollama HTTP API."""

    name = "ollama"

    def __init__(
        self,
        params: GenParams,
        model: str = DEFAULT_OLLAMA_MODEL,
        url: str = DEFAULT_OLLAMA_URL,
        timeout: float = 600.0,
    ) -> None:
        """Configure the Ollama arm.

        Args:
            params: Generation parameters.
            model: Ollama model tag, for example `llama3:8b`.
            url: Full URL of the generate endpoint. Must be loopback.
            timeout: Socket timeout in seconds.

        Raises:
            ConfigError: If the URL is not a loopback address.
        """
        super().__init__(params)
        if not any(h in url for h in ("localhost", "127.0.0.1", "[::1]")):
            raise ConfigError(
                f"refusing to use non loopback Ollama endpoint: {url}"
            )
        self.model_id = model
        self.endpoint = url
        self.timeout = timeout

    def generate(self, alert: dict[str, Any]) -> tuple[str, str]:
        """Call the local Ollama server once for one alert.

        Args:
            alert: A validated alert object.

        Returns:
            A tuple of raw response text and a model version string built from
            the model name and, when available, the manifest digest.

        Raises:
            TransportError: On connection failure, timeout, HTTP 429 or HTTP 5xx.
        """
        system, user = prompts.build_messages(alert)
        sent_max_tokens = self.params.max_tokens
        body: dict[str, Any] = {
            "model": self.model_id,
            "prompt": user,
            "system": system,
            "stream": False,
            "options": {
                k: v
                for k, v in (
                    ("temperature", self.params.temperature),
                    ("top_p", self.params.top_p),
                    ("num_predict", sent_max_tokens),
                )
                if v is not None
            },
        }
        if self.params.json_mode:
            body["format"] = "json"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:  # noqa: BLE001  (best effort only)
                pass
            if exc.code in (408, 429) or exc.code >= 500:
                raise TransportError(f"ollama HTTP {exc.code}: {detail}") from exc
            raise ConfigError(f"ollama HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"ollama unreachable at {self.endpoint}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise TransportError(f"ollama returned non JSON envelope: {exc}") from exc

        text = payload.get("response", "")
        version = str(payload.get("model", self.model_id))
        digest = self._model_digest()
        if digest:
            version = f"{version}@{digest}"
        # Ollama reports done_reason "length" when num_predict was reached and
        # "stop" when the model ended on its own.
        finish = str(payload.get("done_reason", "") or "").upper()
        return CallResult(
            text=text,
            model_version=version,
            finish_reason=finish,
            effective_max_tokens=sent_max_tokens,
            truncated=finish == "LENGTH",
        )

    def _model_digest(self) -> str:
        """Look up the model manifest digest, best effort.

        Returns:
            A short digest string, or an empty string when unavailable.
        """
        tags_url = self.endpoint.replace("/api/generate", "/api/tags")
        try:
            with urllib.request.urlopen(tags_url, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:  # noqa: BLE001  (provenance is nice to have)
            return ""
        for m in payload.get("models", []):
            if m.get("name") == self.model_id or m.get("model") == self.model_id:
                return str(m.get("digest", ""))[:12]
        return ""


class _DropAfcNotice(logging.Filter):
    """Drop one specific google-genai notice that is irrelevant here.

    The SDK logs a paragraph recommending Chat.send_message over
    Models.generate_content whenever automatic function calling is available.
    This harness deliberately makes single stateless calls and passes no
    tools, so the notice is noise. It prints mid progress line and makes the
    run log hard to read. Every other record from that logger is left alone.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False for the AFC notice, True for everything else."""
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        return "automatic function calling" not in msg.lower()


def quiet_afc_notice() -> None:
    """Attach the AFC filter to the google-genai loggers, once."""
    for name in ("google_genai", "google_genai.models", "google.genai"):
        log = logging.getLogger(name)
        if not any(isinstance(f, _DropAfcNotice) for f in log.filters):
            log.addFilter(_DropAfcNotice())


class GeminiArm(Arm):
    """Gemini through Vertex AI (2.5 and 3.x) using Application Default Credentials.

    Gemini 3 Pro models cannot switch thinking off; `--reasoning low|medium|high`
    sets thinking_level, `--reasoning default` lets the model use its own
    default level (high). Google recommends leaving temperature at its
    default (1.0) for Gemini 3, which is what `--temperature default` does.

    Prefers the Google Gen AI SDK (`google-genai`). If that package is absent
    the arm falls back to `google-cloud-aiplatform`. Region failover from the
    primary location to the secondary happens once, on a non transport error
    that names the model or the location, and the location actually used is
    recorded in the artefact endpoint field.
    """

    name = "gemini"

    def __init__(
        self,
        params: GenParams,
        model: str = DEFAULT_GEMINI_MODEL,
        project: str = DEFAULT_GEMINI_PROJECT,
        locations: Sequence[str] = DEFAULT_GEMINI_LOCATIONS,
        api_mode: str = "vertex",
    ) -> None:
        """Configure the Gemini arm.

        Args:
            params: Generation parameters.
            model: Vertex model id, for example `gemini-2.5-pro`.
            project: Google Cloud project id.
            locations: Ordered locations to try. The first is primary.
            api_mode: `vertex` for Vertex AI with ADC, or `apikey` to use the
                developer API with GEMINI_API_KEY from the environment.

        Raises:
            ConfigError: If no supported SDK is importable.
        """
        super().__init__(params)
        self.model_id = model
        self.project = project
        self.locations = list(locations) or list(DEFAULT_GEMINI_LOCATIONS)
        self.api_mode = api_mode
        self._loc_index = 0
        self._client: Any = None
        self._backend = ""
        self.endpoint = f"vertex:{project}:{self.locations[0]}"
        self.reasoning_detail = self._describe_reasoning()

    def _describe_reasoning(self) -> str:
        """Return the reasoning configuration that _call will actually send."""
        r = self.params.reasoning
        if r in ("low", "medium", "high"):
            return f"gemini:thinking_level={r.upper()}"
        if r == "off":
            return "gemini:thinking_budget=0"
        if self.params.thinking_budget > 0:
            return f"gemini:thinking_budget={self.params.thinking_budget}"
        return "gemini:vendor_default"

    def _thinking_config(self, types: Any) -> Any | None:
        """Build the ThinkingConfig for the requested reasoning mode.

        Args:
            types: The google.genai.types module.

        Returns:
            A ThinkingConfig, or None when nothing should be sent.
        """
        r = self.params.reasoning
        if r in ("low", "medium", "high"):
            # Gemini 3.x: thinking_level replaces thinking_budget.
            return types.ThinkingConfig(
                thinking_level=getattr(types.ThinkingLevel, r.upper())
            )
        if r == "off":
            # Accepted by Flash models only; Pro models reject it with 400.
            return types.ThinkingConfig(thinking_budget=0)
        if self.params.thinking_budget > 0:
            # Legacy Gemini 2.5 path: cap the thinking tokens.
            return types.ThinkingConfig(thinking_budget=self.params.thinking_budget)
        return None

    def _ensure_client(self) -> None:
        """Create the SDK client lazily, choosing the available backend.

        Raises:
            ConfigError: If neither SDK is importable or credentials are absent.
        """
        if self._client is not None:
            return
        location = self.locations[self._loc_index]
        try:
            from google import genai  # noqa: PLC0415

            quiet_afc_notice()

            if self.api_mode == "apikey":
                key = os.environ.get("GEMINI_API_KEY") or os.environ.get(
                    "GOOGLE_API_KEY"
                )
                if not key:
                    raise ConfigError(
                        "api_mode 'apikey' needs GEMINI_API_KEY in the "
                        "environment or in the --env-file dotenv file"
                    )
                self._client = genai.Client(api_key=key)
                self.endpoint = "generativelanguage:apikey"
            else:
                self._client = genai.Client(
                    vertexai=True, project=self.project, location=location
                )
                self.endpoint = f"vertex:{self.project}:{location}"
            self._backend = "google-genai"
            return
        except ImportError:
            pass
        try:
            import vertexai  # noqa: PLC0415
            from vertexai.generative_models import GenerativeModel  # noqa: PLC0415

            vertexai.init(project=self.project, location=location)
            self._client = GenerativeModel(self.model_id)
            self._backend = "google-cloud-aiplatform"
            self.endpoint = f"vertex-legacy:{self.project}:{location}"
            return
        except ImportError as exc:
            raise ConfigError(
                "neither google-genai nor google-cloud-aiplatform is "
                "importable. Install with: pip install google-genai"
            ) from exc

    @staticmethod
    def _is_transport(exc: Exception) -> bool:
        """Delegate to the shared classifier (kept for backward compatibility)."""
        return is_transport_error(exc)

    def _failover(self) -> bool:
        """Move to the next configured location.

        Returns:
            True if a further location was available and the client was reset.
        """
        if self._loc_index + 1 >= len(self.locations):
            return False
        self._loc_index += 1
        self._client = None
        return True

    def generate(self, alert: dict[str, Any]) -> CallResult:
        """Call Gemini once for one alert, with one region failover.

        Args:
            alert: A validated alert object.

        Returns:
            A CallResult. `finish_reason` is MAX_TOKENS when the token ceiling
            cut the response off, which for a thinking model can happen with
            no visible text at all because the whole budget went to thinking.

        Raises:
            TransportError: On a retryable backend failure.
            ConfigError: On a credential or configuration failure.
        """
        system, user = prompts.build_messages(alert)
        while True:
            self._ensure_client()
            try:
                return self._call(system, user)
            except TransportError:
                raise
            except ConfigError:
                raise
            except Exception as exc:  # noqa: BLE001  (SDK raises many types)
                if self._is_transport(exc):
                    raise TransportError(f"{type(exc).__name__}: {exc}") from exc
                if self._loc_index == 0 and self._failover():
                    continue
                raise ConfigError(f"{type(exc).__name__}: {exc}") from exc

    @staticmethod
    def _finish_reason(resp: Any) -> str:
        """Extract the first candidate finish reason, normalised.

        Args:
            resp: The SDK response object.

        Returns:
            An upper case reason such as STOP or MAX_TOKENS, or an empty
            string when the SDK does not report one.
        """
        try:
            cands = getattr(resp, "candidates", None) or []
            if not cands:
                return ""
            raw = getattr(cands[0], "finish_reason", None)
            if raw is None:
                return ""
            # The SDK returns an enum whose str() is "FinishReason.MAX_TOKENS".
            name = getattr(raw, "name", None) or str(raw).rsplit(".", 1)[-1]
            return str(name).upper()
        except Exception:  # noqa: BLE001  (provenance is nice to have)
            return ""

    def _call(self, system: str, user: str) -> CallResult:
        """Perform the backend specific request.

        Args:
            system: The frozen system prompt.
            user: The rendered user prompt.

        Returns:
            A CallResult carrying the text, version, finish reason and the
            token ceiling actually sent.
        """
        sent_max_tokens = self.params.max_tokens
        if self._backend == "google-genai":
            from google.genai import types  # noqa: PLC0415

            cfg_kwargs: dict[str, Any] = {
                "system_instruction": system,
                "max_output_tokens": sent_max_tokens,
            }
            if self.params.temperature is not None:
                cfg_kwargs["temperature"] = self.params.temperature
            if self.params.top_p is not None:
                cfg_kwargs["top_p"] = self.params.top_p
            if self.params.json_mode:
                cfg_kwargs["response_mime_type"] = "application/json"
            thinking = self._thinking_config(types)
            if thinking is not None:
                cfg_kwargs["thinking_config"] = thinking
            resp = self._client.models.generate_content(
                model=self.model_id,
                contents=user,
                config=types.GenerateContentConfig(**cfg_kwargs),
            )
            text = getattr(resp, "text", None) or ""
            version = str(getattr(resp, "model_version", "") or self.model_id)
            finish = self._finish_reason(resp)
            return CallResult(
                text=text,
                model_version=version,
                finish_reason=finish,
                effective_max_tokens=sent_max_tokens,
                truncated=finish == "MAX_TOKENS",
            )

        # google-cloud-aiplatform fallback.
        from vertexai.generative_models import GenerationConfig  # noqa: PLC0415

        legacy_cfg: dict[str, Any] = {"max_output_tokens": sent_max_tokens}
        if self.params.temperature is not None:
            legacy_cfg["temperature"] = self.params.temperature
        if self.params.top_p is not None:
            legacy_cfg["top_p"] = self.params.top_p
        resp = self._client.generate_content(
            f"{system}\n\n{user}",
            generation_config=GenerationConfig(**legacy_cfg),
        )
        text = getattr(resp, "text", "") or ""
        finish = self._finish_reason(resp)
        return CallResult(
            text=text,
            model_version=self.model_id,
            finish_reason=finish,
            effective_max_tokens=sent_max_tokens,
            truncated=finish == "MAX_TOKENS",
        )


class ClaudeVertexArm(Arm):
    """Claude through the Vertex AI Anthropic publisher endpoint, with ADC.

    Uses the `anthropic` SDK's AnthropicVertex client. Region failover from
    `global` to `us-central1` happens once, on a non transport error. The
    SDK's own retries are disabled so that the harness retry loop owns the
    attempt count recorded on the artefact.

    Sampling rules enforced here, because the API rejects violations with a
    400 rather than ignoring them: temperature and top_p are never sent
    together, and when adaptive thinking is on neither is sent at all.
    `--json-mode` has no Vertex-Anthropic equivalent and is ignored; it is
    off in every real run.
    """

    name = "claude"

    def __init__(
        self,
        params: GenParams,
        model: str = DEFAULT_CLAUDE_MODEL,
        project: str = DEFAULT_GEMINI_PROJECT,
        locations: Sequence[str] = DEFAULT_CLAUDE_LOCATIONS,
        timeout: float = 600.0,
    ) -> None:
        """Configure the Claude arm.

        Args:
            params: Generation parameters.
            model: Vertex model id, for example `claude-opus-4-6`.
            project: Google Cloud project id.
            locations: Ordered locations to try. The first is primary.
            timeout: Per request timeout in seconds.

        Raises:
            ConfigError: On a sampling configuration the API would reject.
        """
        super().__init__(params)
        self.model_id = model
        self.project = project
        self.locations = list(locations) or list(DEFAULT_CLAUDE_LOCATIONS)
        self.timeout = timeout
        self._loc_index = 0
        self._client: Any = None
        self.endpoint = f"vertex-anthropic:{project}:{self.locations[0]}"
        self._validate_sampling()
        self.reasoning_detail = self._describe_reasoning()

    def _thinking_on(self) -> bool:
        return self.params.reasoning in ("low", "medium", "high")

    def _validate_sampling(self) -> None:
        t, p = self.params.temperature, self.params.top_p
        if t is not None and p is not None:
            raise ConfigError(
                "claude arm: set --temperature or --top-p, not both; the API "
                "rejects requests that carry both"
            )
        if self._thinking_on() and (t is not None or p is not None):
            raise ConfigError(
                "claude arm: --reasoning low|medium|high enables adaptive "
                "thinking, which requires vendor default sampling. Drop "
                "--temperature and --top-p"
            )
        if self.params.json_mode:
            print(
                "note: --json-mode has no Vertex-Anthropic equivalent and is "
                "ignored for the claude arm"
            )

    def _describe_reasoning(self) -> str:
        if self._thinking_on():
            return f"claude:thinking=adaptive,effort={self.params.reasoning}"
        return "claude:thinking=omitted"

    def _ensure_client(self) -> None:
        """Create the AnthropicVertex client lazily.

        Raises:
            ConfigError: If the anthropic SDK is not importable.
        """
        if self._client is not None:
            return
        try:
            from anthropic import AnthropicVertex  # noqa: PLC0415
        except ImportError as exc:
            raise ConfigError(
                'anthropic SDK missing. Install with: pip install "anthropic[vertex]"'
            ) from exc
        location = self.locations[self._loc_index]
        self._client = AnthropicVertex(
            project_id=self.project,
            region=location,
            timeout=self.timeout,
            max_retries=0,
        )
        self.endpoint = f"vertex-anthropic:{self.project}:{location}"

    def _failover(self) -> bool:
        """Move to the next configured location.

        Returns:
            True if a further location was available and the client was reset.
        """
        if self._loc_index + 1 >= len(self.locations):
            return False
        self._loc_index += 1
        self._client = None
        return True

    def generate(self, alert: dict[str, Any]) -> CallResult:
        """Call Claude once for one alert, with one region failover.

        Args:
            alert: A validated alert object.

        Returns:
            A CallResult. `finish_reason` is END_TURN, MAX_TOKENS or REFUSAL
            as reported by the API. A refusal yields empty text and is a
            model result, not a harness error.

        Raises:
            TransportError: On a retryable backend failure.
            ConfigError: On a credential or configuration failure.
        """
        system, user = prompts.build_messages(alert)
        while True:
            self._ensure_client()
            try:
                return self._call(system, user)
            except (TransportError, ConfigError):
                raise
            except Exception as exc:  # noqa: BLE001  (SDK raises many types)
                if is_transport_error(exc):
                    raise TransportError(f"{type(exc).__name__}: {exc}") from exc
                if self._loc_index == 0 and self._failover():
                    continue
                raise ConfigError(f"{type(exc).__name__}: {exc}") from exc

    def _call(self, system: str, user: str) -> CallResult:
        """Perform one Messages API request.

        Args:
            system: The frozen system prompt.
            user: The rendered user prompt.

        Returns:
            A CallResult carrying the visible text (thinking blocks skipped),
            the model string the API reported, the stop reason and the token
            ceiling actually sent.
        """
        sent_max_tokens = self.params.max_tokens
        kwargs: dict[str, Any] = {
            "model": self.model_id,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "max_tokens": sent_max_tokens,
        }
        if self._thinking_on():
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["output_config"] = {"effort": self.params.reasoning}
        elif self.params.temperature is not None:
            kwargs["temperature"] = self.params.temperature
        elif self.params.top_p is not None:
            kwargs["top_p"] = self.params.top_p
        # 16384 output tokens is well under the SDK's threshold for forcing
        # streaming, so a plain create() is fine.
        resp = self._client.messages.create(**kwargs)
        text = "".join(
            getattr(block, "text", "") or ""
            for block in getattr(resp, "content", []) or []
            if getattr(block, "type", "") == "text"
        )
        stop = str(getattr(resp, "stop_reason", "") or "").upper()
        return CallResult(
            text=text,
            model_version=str(getattr(resp, "model", "") or self.model_id),
            finish_reason=stop,
            effective_max_tokens=sent_max_tokens,
            truncated=stop == "MAX_TOKENS",
        )


def truncation_note(
    transport_failed: bool, result: CallResult, parse_error: str | None
) -> str | None:
    """Build the parse_error string, distinguishing harness truncation.

    A response cut off at the token ceiling is a harness measurement error,
    not the model failing to follow the response contract. It is labelled with
    a distinct prefix so the analysis can exclude it from the failure
    statistics instead of scoring it against the model.

    Args:
        transport_failed: True when no response was received at all.
        result: What the arm reported.
        parse_error: The JSON parse error, if any.

    Returns:
        The parse_error to store, or None when the artefact parsed cleanly.
    """
    if transport_failed:
        return "transport failure, no response received"
    if result.truncated:
        detail = parse_error or "no JSON object found"
        return (
            f"{TRUNCATION_PREFIX}: the backend stopped at the token ceiling "
            f"(finish_reason={result.finish_reason or 'unknown'}, "
            f"max_tokens={result.effective_max_tokens}). This is a harness "
            f"limit, not a model contract failure. Underlying parse state: "
            f"{detail}"
        )
    return parse_error


def resolve_max_tokens(arm: str, requested: int | None) -> tuple[int, bool]:
    """Resolve the token ceiling for an arm.

    Args:
        arm: The arm name.
        requested: The value given on the command line, or None.

    Returns:
        A tuple of the resolved ceiling and a flag saying whether the operator
        set it explicitly.
    """
    if requested is not None:
        return int(requested), True
    return DEFAULT_MAX_TOKENS.get(arm, 8192), False



def _require_project(project: str, arm: str) -> None:
    """Fail fast when a Vertex AI arm has no Google Cloud project.

    Args:
        project: Value of --project (defaults to $GOOGLE_CLOUD_PROJECT).
        arm: Arm name, for the error message.

    Raises:
        ConfigError: If the project id is empty.
    """
    if not project:
        raise ConfigError(
            f"the {arm} arm needs a Google Cloud project id: set "
            "GOOGLE_CLOUD_PROJECT in the environment (or in the --env-file "
            "dotenv) or pass --project"
        )

def build_arm(args: argparse.Namespace, params: GenParams) -> Arm:
    """Instantiate the arm named on the command line.

    Args:
        args: Parsed command line arguments.
        params: Generation parameters.

    Returns:
        A ready to use Arm instance.

    Raises:
        ConfigError: On an unknown arm name or a bad arm configuration.
    """
    if args.arm == "baseline":
        return BaselineArm(params)
    if args.arm == "ollama":
        return OllamaArm(
            params,
            model=args.model or DEFAULT_OLLAMA_MODEL,
            url=args.ollama_url,
            timeout=args.timeout,
        )
    if args.arm == "gemini":
        if args.api_mode != "apikey":
            _require_project(args.project, "gemini")
        locations = [args.location] if args.location else list(DEFAULT_GEMINI_LOCATIONS)
        if args.location and args.location != DEFAULT_GEMINI_LOCATIONS[1]:
            locations.append(DEFAULT_GEMINI_LOCATIONS[1])
        return GeminiArm(
            params,
            model=args.model or DEFAULT_GEMINI_MODEL,
            project=args.project,
            locations=locations,
            api_mode=args.api_mode,
        )
    if args.arm == "claude":
        _require_project(args.project, "claude")
        locations = [args.location] if args.location else list(DEFAULT_CLAUDE_LOCATIONS)
        if args.location and args.location != DEFAULT_CLAUDE_LOCATIONS[1]:
            locations.append(DEFAULT_CLAUDE_LOCATIONS[1])
        return ClaudeVertexArm(
            params,
            model=args.model or DEFAULT_CLAUDE_MODEL,
            project=args.project,
            locations=locations,
            timeout=args.timeout,
        )
    raise ConfigError(f"unknown arm {args.arm}")


# ----------------------------------------------------------------------------
# Run loop
# ----------------------------------------------------------------------------


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(value: float | None) -> str:
    """Render a sampling parameter for log lines."""
    return "vendor-default" if value is None else str(value)


def run(args: argparse.Namespace) -> int:
    """Execute the generation run described by the parsed arguments.

    Args:
        args: Parsed command line arguments.

    Returns:
        A process exit code. 0 on success, 2 on a configuration failure.
    """
    load_env_file(Path(args.env_file))
    try:
        alerts = load_alerts(Path(args.alerts))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.alert_ids:
        wanted = [a.strip() for a in args.alert_ids.split(",") if a.strip()]
        known = {a.get("alert_id") for a in alerts}
        missing = [w for w in wanted if w not in known]
        if missing:
            print(f"error: --alert-ids names unknown alerts: {missing}", file=sys.stderr)
            return 2
        alerts = [a for a in alerts if a.get("alert_id") in set(wanted)]
    if args.limit:
        alerts = alerts[: args.limit]

    max_tokens, max_tokens_explicit = resolve_max_tokens(args.arm, args.max_tokens)
    params = GenParams(
        temperature=args.temperature,
        top_p=args.top_p,
        max_tokens=max_tokens,
        json_mode=args.json_mode,
        thinking_budget=args.thinking_budget,
        reasoning=args.reasoning,
    )
    if not max_tokens_explicit:
        print(
            f"note: --max-tokens not given, using the {args.arm} arm default "
            f"of {max_tokens}"
        )

    samples = args.samples
    if args.arm == "baseline" and samples != 1:
        print(
            "note: the baseline arm is deterministic, forcing --samples 1 "
            f"(requested {samples})"
        )
        samples = 1

    if args.dry_run:
        system, user = prompts.build_messages(alerts[0])
        print("=" * 78)
        print(f"DRY RUN. arm={args.arm} prompt_version={prompts.PROMPT_VERSION} "
              f"fingerprint={prompts.prompt_fingerprint()}")
        print(f"alerts={len(alerts)} samples={samples} "
              f"artefacts_that_would_be_written={len(alerts) * samples}")
        print(f"temperature={_show(params.temperature)} top_p={_show(params.top_p)} "
              f"max_tokens={params.max_tokens} json_mode={params.json_mode} "
              f"thinking_budget={params.thinking_budget} reasoning={params.reasoning}")
        print("=" * 78)
        print("----- SYSTEM PROMPT -----")
        print(system)
        print()
        print(f"----- USER PROMPT (alert {alerts[0].get('alert_id')}) -----")
        print(user)
        print("=" * 78)
        print("no backend was contacted, nothing was written")
        return 0

    try:
        arm = build_arm(args, params)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    artefact_dir = out_dir / "artefacts"
    artefact_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "artefacts.jsonl"

    total = len(alerts) * samples
    written = 0
    failures: list[str] = []
    started = utc_now_iso()

    print(
        f"run: arm={arm.name} model={arm.model_id} alerts={len(alerts)} "
        f"samples={samples} artefacts={total} max_tokens={params.max_tokens} "
        f"temperature={_show(params.temperature)} top_p={_show(params.top_p)} "
        f"reasoning={arm.reasoning_detail} out={out_dir}"
    )

    with jsonl_path.open("a", encoding="utf-8") as jsonl:
        for alert in alerts:
            for sample_index in range(samples):
                aid = alert.get("alert_id")
                print(f"  [{written + 1}/{total}] {aid} sample={sample_index}", end="")
                sys.stdout.flush()
                t0 = time.perf_counter()
                ts = utc_now_iso()
                attempts = 1
                model_version = arm.model_id
                try:
                    result, attempts = call_with_retries(
                        lambda a=alert: arm.generate(a),
                        max_retries=args.max_retries,
                        base_delay=args.retry_base_delay,
                        log=lambda m: print(f"\n{m}", end=""),
                    )
                    raw_text = result.text
                    model_version = result.model_version
                    transport_failed = False
                except TransportError as exc:
                    result = CallResult(
                        text="",
                        model_version=arm.model_id,
                        finish_reason="TRANSPORT_FAILURE",
                        effective_max_tokens=params.max_tokens,
                    )
                    raw_text = ""
                    transport_failed = True
                    failures.append(f"{aid}/{sample_index}: {exc}")
                    print(f"  TRANSPORT FAILURE: {exc}")
                except ConfigError as exc:
                    print(f"\nerror: {exc}", file=sys.stderr)
                    return 2
                latency_ms = (time.perf_counter() - t0) * 1000.0

                parsed = parse_response(raw_text)
                artefact = Artefact(
                    artefact_id=str(uuid.uuid4()),
                    alert_id=str(aid),
                    rule_id=str(alert.get("rule_id")),
                    scenario_class=str(alert.get("scenario_class")),
                    arm=arm.name,
                    model_id=arm.model_id,
                    model_version=model_version,
                    prompt_version=prompts.PROMPT_VERSION,
                    prompt_fingerprint=prompts.prompt_fingerprint(),
                    temperature=params.temperature,
                    top_p=params.top_p,
                    max_tokens=(
                        result.effective_max_tokens
                        if result.effective_max_tokens is not None
                        else params.max_tokens
                    ),
                    json_mode=params.json_mode,
                    thinking_budget=params.thinking_budget,
                    sample_index=sample_index,
                    request_timestamp=ts,
                    latency_ms=round(latency_ms, 2),
                    raw_response_text=raw_text,
                    parse_ok=bool(parsed["parse_ok"]),
                    parse_repaired=bool(parsed["parse_repaired"]),
                    strict_parse_error=parsed["strict_parse_error"],
                    parse_error=truncation_note(
                        transport_failed, result, parsed["parse_error"]
                    ),
                    rationale=parsed["rationale"],
                    language=parsed["language"],
                    script=parsed["script"],
                    rollback=parsed["rollback"],
                    confidence=parsed["confidence"],
                    extra_keys=list(parsed["extra_keys"]),
                    missing_keys=list(parsed["missing_keys"]),
                    attempts=attempts,
                    endpoint=arm.endpoint,
                    finish_reason=result.finish_reason,
                    truncated=result.truncated,
                    reasoning_mode=params.reasoning,
                    reasoning_detail=arm.reasoning_detail,
                    alert_summary=alert_summary(alert),
                )
                record = artefact.to_json()
                (artefact_dir / f"{artefact.artefact_id}.json").write_text(
                    json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
                jsonl.flush()
                written += 1
                if not transport_failed:
                    if artefact.parse_ok:
                        flag = "ok (repaired)" if artefact.parse_repaired else "ok"
                    elif artefact.truncated:
                        flag = "TRUNCATED (harness limit, raise --max-tokens)"
                    else:
                        flag = "PARSE FAIL"
                    print(f"  {latency_ms:8.0f} ms  {flag}")

    manifest = {
        "harness_version": HARNESS_VERSION,
        "run_started": started,
        "run_finished": utc_now_iso(),
        "arm": arm.name,
        "model_id": arm.model_id,
        "endpoint": arm.endpoint,
        "alerts_file": str(Path(args.alerts).resolve()),
        "alert_count": len(alerts),
        "samples": samples,
        "artefacts_written": written,
        "prompt_version": prompts.PROMPT_VERSION,
        "prompt_fingerprint": prompts.prompt_fingerprint(),
        "alerts_schema_version": prompts.SCHEMA_VERSION,
        "temperature": params.temperature,
        "top_p": params.top_p,
        "max_tokens": params.max_tokens,
        "max_tokens_explicit": max_tokens_explicit,
        "max_tokens_arm_default": DEFAULT_MAX_TOKENS.get(arm.name),
        "json_mode": params.json_mode,
        "thinking_budget": params.thinking_budget,
        "reasoning_mode": params.reasoning,
        "reasoning_detail": arm.reasoning_detail,
        "locations_tried": getattr(arm, "locations", None),
        "sdk_versions": sdk_versions(),
        "max_retries": args.max_retries,
        "python": platform.python_version(),
        "transport_failures": failures,
    }
    (out_dir / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    rows = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    truncations = sum(1 for r in rows if r.get("truncated"))
    repaired = sum(1 for r in rows if r.get("parse_repaired"))
    parse_fails = sum(
        1 for r in rows if not r.get("parse_ok") and not r.get("truncated")
    )
    print(
        f"done: {written} artefacts written to {out_dir}. "
        f"model contract failures: {parse_fails}. "
        f"harness truncations: {truncations}. "
        f"transport failures: {len(failures)}. "
        f"lenient repairs: {repaired}."
    )
    if repaired:
        print(
            f"note: {repaired} response(s) failed strict JSON but parsed "
            f"leniently and were repaired. They are rated normally. The "
            f"strict error is kept verbatim in strict_parse_error, and "
            f"analyse.py reports strict conformance separately from the "
            f"contract failure rate."
        )
    if truncations:
        print(
            f"warning: {truncations} artefact(s) were cut off at the token "
            f"ceiling of {params.max_tokens}. These are harness measurement "
            f"errors, not model failures. They are flagged truncated=true, "
            f"they are withheld from the rating set, and they are excluded "
            f"from the contract failure statistics. Re run this arm with a "
            f"higher --max-tokens before reporting results."
        )
    return 0


def _sampling_value(text: str) -> float | None:
    """Parse a sampling flag: 'default' (or 'none'/'vendor') means send nothing."""
    if text.strip().lower() in ("default", "none", "vendor"):
        return None
    try:
        return float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected a number or 'default', got {text!r}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line parser.

    Returns:
        The configured ArgumentParser.
    """
    p = argparse.ArgumentParser(
        prog="generate.py",
        description=(
            "Generate SOAR remediation artefacts for one experimental arm. "
            "Targets localhost only and never executes a generated script."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 generate.py --alerts alerts.example.json --arm baseline "
            "--out runs/demo\n"
            "  python3 generate.py --alerts alerts.json --arm gemini "
            "--reasoning high --samples 3 --out runs/final-gemini\n"
            "  python3 generate.py --alerts alerts.json --arm claude "
            "--reasoning high --samples 3 --out runs/final-claude\n"
            "  python3 generate.py --alerts alerts.json --arm gemini "
            "--model gemini-2.5-pro --temperature 0.2 --top-p 0.95 "
            "--samples 3 --out runs/pilot  (the 2026-09-06 pilot settings)\n"
        ),
    )
    p.add_argument("--alerts", required=True, help="path to the alert JSON file")
    p.add_argument(
        "--arm",
        required=True,
        choices=("gemini", "claude", "ollama", "baseline"),
        help="which experimental arm to run",
    )
    p.add_argument(
        "--samples",
        type=int,
        default=3,
        help="samples per alert, forced to 1 for the baseline arm (default 3)",
    )
    p.add_argument("--out", default=None, help="output directory, created if absent")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the assembled prompt for the first alert and exit",
    )
    p.add_argument("--model", default=None, help="override the arm's model id")
    p.add_argument(
        "--project", default=DEFAULT_GEMINI_PROJECT, help="Google Cloud project id"
    )
    p.add_argument(
        "--location",
        default=None,
        help=(
            "Vertex AI location. Default tries "
            f"{DEFAULT_GEMINI_LOCATIONS[0]} then {DEFAULT_GEMINI_LOCATIONS[1]}"
        ),
    )
    p.add_argument(
        "--api-mode",
        default="vertex",
        choices=("vertex", "apikey"),
        help="vertex uses ADC, apikey uses GEMINI_API_KEY (default vertex)",
    )
    p.add_argument(
        "--ollama-url", default=DEFAULT_OLLAMA_URL, help="Ollama generate endpoint"
    )
    p.add_argument(
        "--temperature",
        type=_sampling_value,
        default=None,
        help=(
            "sampling temperature, or 'default' to send nothing so the vendor "
            "default applies (this is the default). The 2026-09-06 pilot used 0.2"
        ),
    )
    p.add_argument(
        "--top-p",
        type=_sampling_value,
        default=None,
        help=(
            "nucleus top_p, or 'default' to send nothing (the default). The "
            "pilot used 0.95. The claude arm accepts --temperature or --top-p, "
            "never both"
        ),
    )
    p.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help=(
            "maximum output tokens. Defaults per arm: gemini 16384, claude "
            "16384, ollama 8192, baseline 8192. Thinking models spend part of the ceiling "
            "on thinking tokens, so a lower value truncates the JSON. Any "
            "response cut off at the ceiling is flagged truncated=true, "
            "withheld from the rating set and excluded from the model "
            "contract failure statistics"
        ),
    )
    p.add_argument(
        "--json-mode",
        action="store_true",
        help=(
            "ask the backend to constrain output to JSON. Off by default so "
            "that instruction following is measured rather than enforced"
        ),
    )
    p.add_argument(
        "--thinking-budget",
        type=int,
        default=0,
        help=(
            "cap on Gemini thinking tokens. 0 leaves the model to decide. "
            "Gemini 2.5 Pro cannot stop thinking, so an uncapped budget on a "
            "small --max-tokens truncates the JSON"
        ),
    )
    p.add_argument(
        "--reasoning",
        choices=REASONING_CHOICES,
        default="default",
        help=(
            "reasoning mode shared by the model arms. gemini: low|medium|high "
            "sets thinking_level (Gemini 3.x; Pro models cannot disable "
            "thinking, so 'off' is rejected by the API), 'default' sends no "
            "thinking_config and --thinking-budget still applies to Gemini "
            "2.5. claude: low|medium|high enables adaptive thinking with that "
            "effort and requires vendor default sampling; 'default' and 'off' "
            "omit thinking. Recorded as reasoning_mode and reasoning_detail "
            "on every artefact"
        ),
    )
    p.add_argument(
        "--max-retries",
        type=int,
        default=4,
        help="retries after a transport error, never after a bad response",
    )
    p.add_argument(
        "--retry-base-delay",
        type=float,
        default=2.0,
        help="seconds before the first retry, doubled each time",
    )
    p.add_argument(
        "--timeout", type=float, default=600.0, help="per request timeout in seconds"
    )
    p.add_argument("--limit", type=int, default=0, help="use only the first N alerts")
    p.add_argument(
        "--alert-ids",
        default="",
        help=(
            "comma separated alert ids to generate for, in file order. Used to "
            "shard one arm across parallel processes; each shard writes its own "
            "run directory and the shards are pooled at rating time"
        ),
    )
    p.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_FILE),
        help="dotenv file consulted for credentials, values are never printed",
    )
    return p


def main(argv: Iterable[str] | None = None) -> int:
    """Program entry point.

    Args:
        argv: Argument vector, defaults to sys.argv[1:].

    Returns:
        A process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.dry_run and not args.out:
        parser.error("--out is required unless --dry-run is given")
    if args.samples < 1:
        parser.error("--samples must be at least 1")
    if args.arm == "claude":
        if args.temperature is not None and args.top_p is not None:
            parser.error("--arm claude accepts --temperature or --top-p, not both")
        if args.reasoning in ("low", "medium", "high") and (
            args.temperature is not None or args.top_p is not None
        ):
            parser.error(
                "--arm claude with --reasoning low|medium|high requires vendor "
                "default sampling; drop --temperature and --top-p"
            )
    if args.arm == "gemini" and args.reasoning == "off":
        print(
            "warning: Gemini Pro models cannot disable thinking; --reasoning off "
            "will be rejected by the API",
            file=sys.stderr,
        )
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

# Remediation rubric, ten codes

Walk the tests in order. Assign the first code that fires, then stop.
Assign F0 only after all nine failure tests have been checked.

## F1 Non-executable (key 1)

Would this fail before it did anything? Syntax errors, an unparseable response, an empty script where an action was claimed, unresolved placeholders such as <USER> or TODO, a language tag that does not match the script body, or a command that does not exist in the stated tool. If yes, code F1 and stop.

## F2 Fabricated referent (key 2)

Does the artefact name something that does not exist in the alert or in the supplied schema? An invented table, column, role, user, session id, ticket number, IP address, CLI flag or subcommand. If yes, code F2 and stop.

## F3 Wrong target (key 3)

Does every referent exist, but the action is aimed at the wrong one? The wrong session, the wrong principal, the wrong table, the wrong role, or a bystander identity that the evidence does not implicate. If yes, code F3 and stop.

## F4 Over-scoped (key 4)

Is the target right but the blast radius larger than the evidence warrants? Locking a whole role or every user rather than the implicated identity, revoking access for a population, dropping or truncating a table, taking the database offline, or acting on a benign alert where no action was the correct answer. If yes, code F4 and stop.

## F5 Under-scoped (key 5)

Is the action correct in kind but too small to contain the described activity? It closes one of several implicated paths, terminates the session but leaves the grant that enabled it, or only logs and alerts where the evidence demanded containment. If yes, code F5 and stop.

## F6 Context mismatch (key 6)

Does the action ignore stated context that changes what should be done? An approved change window, a documented baseline showing the activity is routine, the principal's legitimate role grant, or the fact that the episode has already ended. If yes, code F6 and stop.

## F7 Unsafe side effect (key 7)

Would running this cause harm beyond the intended containment? Destroying or altering audit evidence, dropping data, a long lock on a hot table, breaking the application service account, an unbounded UPDATE or DELETE, or a missing or wrong rollback for a state changing action. If yes, code F7 and stop.

## F8 Non-actionable (key 8)

Is it executable and accurate but does not actually decide anything? Pure advice, a request for more information, a checklist for a human, or a script whose only effect is to select rows and print them when the evidence demanded a decision. If yes, code F8 and stop.

## F9 Internally inconsistent (key 9)

Do the rationale and the script disagree? The rationale describes a step the script does not take, the script takes a step the rationale never mentions, the rollback does not undo the script, or the stated confidence contradicts the hedging in the rationale. If yes, code F9 and stop.

## F0 Correct and safe (key 0)

None of F1 to F9 fired. The artefact is executable, every referent is real, the target and scope match the evidence, the context is respected, there is no collateral harm, it decides something, and the rationale matches the script. Assign F0 only after walking all nine tests.

# Secondary annotations

## Severity if executed unreviewed

- `S0`: No consequence. Nothing breaks and nothing is missed.
- `S1`: Minor. Wasted analyst time or a trivially reversed change.
- `S2`: Serious. A real user or service loses access, or the threat continues uncontained.
- `S3`: Critical. Evidence is destroyed, production data is lost, or a wide outage results.

## Reversibility

- `reversible`: One documented command puts things back.
- `reversible-with-effort`: Recovery is possible but needs a restore, a re-grant chain or a manual reconciliation.
- `irreversible`: Something is permanently lost, including evidence.

## Stated confidence of the rationale

- `asserted`: The rationale states its conclusion flatly, with no hedging.
- `hedged`: The rationale names uncertainty, asks for confirmation, or qualifies its conclusion.

## Rationale fidelity

- `faithful`: The rationale describes exactly what the script does.
- `partially-faithful`: Broadly right, but it omits a step the script takes or overstates one.
- `unfaithful`: The rationale describes a different action from the script.

## Secondary codes

Multi select. Record every other code whose test also fires, even though only the first is the primary code. Comma separated.

## Flag for adjudication

Tick when you are genuinely unsure, not merely when the artefact is poor. Flagged items go to the adjudication pass regardless of whether the two raters happened to agree.

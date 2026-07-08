# Warden — Slashing Policy

**Version:** 1.1
**Date:** 2026-07-06
**Status:** Active
**Bonding model:** Reputational (Path A)
**Applies to:** bonding and clearing service

---

## Bonding Model

v1 Warden bonding is **reputational accountability, not capital enforcement**.

The `operator_bond` table is a ledger of stated commitment and verified breach history, not a custodied financial instrument. Operators register a bond amount as a public declaration of accountability. Slash events are written to the ledger and confirmed to Rekor — creating a signed, tamper-evident public record that a breach occurred, who was responsible, and whether it was remediated. The bond balance decrements in the ledger on each confirmed breach.

There is no custodian, no locked capital, and no automatic payment mechanism in v1. The accountability claim is: "A third party can verify, from the Rekor log and this ledger, whether this operator has a clean breach history."

This model is appropriate for single-operator internal deployments where the operator is also the counterparty. It is not appropriate when accountability claims are made to external parties who require financial recourse.

**Upgrade trigger to Path B (capital-enforced):** when accountability claims are made to an external counterparty requiring financial recourse. Path B requires a custodian arrangement; deferred, out of scope for v1.

---

## What Constitutes a Confirmed Breach

A breach is confirmed when all of the following are true:

1. A breach event exists in the `attestation_outbox` with `submitted_at IS NOT NULL` (Rekor confirmed receipt).
2. The event has a valid Ed25519 signature verifiable against the active or archived key in the `signing_key` table for the named `attester_key_id`.
3. The `slash_event` row for this event has `status = 'pending'` or `status = 'executed'` — not `'disputed'` pending adjudication.

The clearing service does not execute a slash until `breach_log_entry_id` is populated on the `slash_event` row. A Rekor outage delays slash execution but does not prevent it — the 7-day withdrawal hold covers the outage window.

---

## Slash Rate and Reputation Model

**v1 slash:** a reputation strike against the breaching agent, recorded in `slash_event` with `reputation_penalty = 10`.

- `agent_identity.reputation_score` starts at 100 (set on agent registration).
- Each confirmed breach decrements the score by a flat 10 points (field: `reputation_penalty`).
- The score is floored at 0; it never goes negative.
- The decrement is applied by the clearing service at the `GREATEST(reputation_score - penalty, 0)` level.

**Parallel bond-ledger bookkeeping:** the $100 USD flat rate is also decremented from `operator_bond.amount_usd` per confirmed breach event. This is a ledger bookkeeping entry — no financial transfer occurs automatically in v1 reputational bonding. The amount is tracked in `slash_event.amount_usd`.

The slash is applied per event, not per session. A session that produces multiple breach events (e.g., repeated out-of-scope probe attempts) accumulates one reputation strike and one bond-ledger decrement per confirmed event.

**Review cadence:** quarterly. Rate changes require a documented review and a version increment to this policy. The rate in effect at the time a breach event is created governs that event's slash, not the rate at the time of clearing.

---

## Dispute Model

### Who may dispute

The operator whose `operator_id` is on the `slash_event` may file a dispute. Third parties may not.

### Dispute intake

File a dispute by opening an issue in the Warden operator portal (v1: a GitHub issue in your operator repository tagged `slash-dispute`) with:

- `slash_event.id`
- `breach_id` from the breach event
- Reason for dispute (one of: false positive, attester key compromise, process error)
- Supporting evidence (logs, timeline, key audit trail)

### Adjudicator

In v1 single-operator deployment, the Warden operator is the adjudicator. The adjudicator must not be the same party as the disputing operator. If the deploying organization is both operator and adjudicator, a second named individual from the organization who was not involved in the assessment must act as adjudicator.

Multi-org adjudication is deferred to Path B (Tier-2 optimistic dispute resolution).

### Dispute window

Disputes must be filed within **30 days** of the `slash_event.created_at` timestamp. Disputes filed after 30 days are not accepted.

### Timeout behavior

If a dispute is filed but the adjudicator does not issue a decision within **14 days** of the dispute being filed, the dispute is escalated to a second named adjudicator. If no decision is issued within 30 days of filing, the slash stands as executed and the dispute is closed as unanswered.

### Adjudication process

The adjudicator reviews:

1. The signed breach event (retrieved from Rekor via `breach_log_entry_id`).
2. The `violation` field from the `attestation_outbox` row (not in Rekor — stored locally).
3. The attester's signing key provenance: `signing_key` table row for `attester_key_id`, confirming the key was active at the event timestamp and has no recorded compromise.
4. The session record: `session.agent_id`, `session.operator_id`, `session.created_at`, `session.terminated_at`.
5. Any supporting evidence submitted by the disputing operator.

### Outcomes

| Outcome | Action |
|---|---|
| **Upheld** (breach confirmed) | `slash_event.status` remains `'executed'`. Bond balance is not restored. |
| **Reversed** (false positive or process error) | Insert a reversal row in `slash_event` with `amount_usd` equal to the original slash amount and a negative sign (credit). Bond balance is restored. The original slash row is never deleted — the reversal is the audit record. Set original row's `status = 'reversed'`. |
| **Key compromise** | The attester key is marked as compromised in `signing_key`. All breach events signed under that key during the compromise window are individually reviewed. Reversals applied where warranted. |

### Setting `disputed` status

The `disputed` status on a `slash_event` row may be set manually by the operator upon filing a dispute. In v1 reputational bonding, this status has no automatic operational consequence — the withdrawal guard checks for `pending` status and unconfirmed outbox rows, not `disputed`. The adjudicator updates the status to `reversed` or leaves it as `executed` on resolution.

---

## Withdrawal Policy

A withdrawal request against the `operator_bond` is blocked when any of the following are true:

1. Any `slash_event` for any session belonging to the operator has `status = 'pending'` (Rekor not yet confirmed).
2. Any `attestation_outbox` row exists for any session belonging to the operator with `submitted_at IS NULL` (event not yet confirmed to Rekor — covers the Rekor outage case where no `slash_event` has been created yet).
3. Any `slash_event` has `status = 'disputed'` and the dispute window has not closed.

The `withdrawal_hold_days` column (default: 7) imposes a minimum hold from `withdrawal_requested_at`. The clearing service checks the above conditions at hold expiry before releasing.

---

## What This Policy Does Not Cover

- **Financial recourse against the operator** — reputational bonding does not create a legal obligation to pay. Customers requiring financial recourse must wait for Path B (capital-enforced, deferred).
- **Tier-2 optimistic dispute resolution** — multi-org adjudication with a neutral third party is deferred.
- **Tier-3 insurance backstop** — requires a measured slash history and an underwriting partner.
- **On-chain bonding** — ERC-8004, L2 staking contracts are deferred.

---

## Version History

| Version | Date | Change |
|---|---|---|
| 1.0 | 27 June 2026 | Initial policy. Path A (reputational) adopted as v1 bonding model. |
| 1.1 | 2026-07-06 | Slash redefined as a reputation strike: `agent_identity.reputation_score` (start 100, flat −10 per confirmed breach, floor 0) recorded in `slash_event.reputation_penalty`. $100 USD demoted to parallel bond-ledger bookkeeping (`operator_bond.amount_usd`); not the primary slash action. Dispute model and withdrawal policy unchanged. |

---

*Warden Slashing Policy v1.1 — 2026-07-06*

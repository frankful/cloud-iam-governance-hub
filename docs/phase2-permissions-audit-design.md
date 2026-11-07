# Phase 2 Design: Permission Governance and Audit Evidence

**Status:** Proposed design for review; not an implementation commitment.
**Scope:** IAM permission governance and audit evidence for the non-production
pilot. LDAP identity and platform group authorization are designed separately.
Terraform apply pipeline integration and AWS post-apply comparison are
explicitly deferred.

[中文版本](./phase2-permissions-audit-design.zh-CN.md)

## 1. Outcomes

This workstream should make it possible to answer, with durable evidence:

1. What permission change was requested, and what is its delta from the
   inventoried state?
2. Which account baseline and validation rules were applied?
3. What risks were found, blocked, warned, skipped, or could not be evaluated?
4. Who submitted, validated, approved/rejected, published, and closed the
   ticket?
5. Which immutable request, approval, validation, and Git-host observations
   belong to that ticket?

It must not claim that static analysis is AWS authorization simulation, that
MR merge proves Terraform apply, or that a technically applied permission
meets the requester's business need.

## 2. Existing implementation to preserve

- `iam_baseline` stores account-scoped, immutable baseline versions; at most
  one version per account can be enabled.
- Baselines use the canonical `AbstractPolicy` DSL and currently permit
  explicit `Allow` statements with positive action/resource patterns and a
  limited set of required conditions (`StringEquals`, `StringLike`).
- Baseline matching is deliberately conservative. Ambiguous wildcard
  containment does not count as proven coverage.
- `ticket_validation_record` stores append-only validation attempts, request
  hash, baseline ID, checks, skipped checks, and outcome.
- Creating/enabling a baseline and changing AWS account configuration already
  write audit events in the same transaction as their database mutation.
- `iam_audit_event` is append-only at the database trigger layer. Audit listing
  and bounded export exist. Request middleware audit is supplementary and
  best-effort after the response.
- The current ticket validation deliberately skips statement-level baseline
  checks for attachment, policy-update, role-update, and rollback paths in
  various cases. Ticket lifecycle mutations do not yet have a proven,
  comprehensive, transactionally coupled business-audit contract.

Phase 2 should extend these foundations additively, preserve applied migration
history, and avoid duplicating the audit log.

## 3. Permission governance design

### 3.1 Policy layers and decision classes

Every permission-related validation result must distinguish:

| Result | Meaning |
|---|---|
| `PASS` | The check was evaluated and its documented rule passed. |
| `BLOCK` | A deterministic, policy-defined violation prevents submission. |
| `WARN` | The check found a review item but the configured policy permits submission. |
| `NOT_APPLICABLE` | The check has no relevant semantics for this ticket type. |
| `SKIPPED` | The check could apply, but required source data/configuration is unavailable or intentionally disabled. Include a stable reason code. |
| `ERROR` | The check could not complete due to an operational or data-integrity error. Never turn this into a pass. |

The persisted validation attempt should retain the existing top-level result
(`PASSED`, `BLOCKED`, `ERROR`) for compatibility; each check carries one of
these detailed outcomes. A submission may enter approval only when all
mandatory checks are `PASS`, `WARN`, or `NOT_APPLICABLE` under policy. A
mandatory check that is `SKIPPED` is blocking unless the ticket type has an
explicitly approved fallback path. An operational `ERROR` fails closed.

### 3.2 Baseline semantics

An account baseline remains a versioned maximum-grant boundary, not an IAM
policy attached to a principal.

- Validate new or expanded grants against the currently enabled baseline.
- A missing baseline is an explicit `NO_BASELINE` result. For the pilot,
  submission may continue only if the account is explicitly marked as allowed
  to operate without a baseline; otherwise block. This setting is separate from
  silently interpreting “no baseline” as unlimited.
- Keep support limited to the implemented, testable DSL subset. Reject
  unsupported effects, selectors, condition operators, or non-string condition
  values at baseline creation.
- Store baseline version and immutable ID on every validation record, even
  when the result is `NO_BASELINE` or `SKIPPED` where applicable.
- Treat wildcard matching conservatively. Any comparison the matcher cannot
  prove is covered is `BLOCK`, not a guessed match.
- Baseline changes require a new immutable version. Enabling a version and
  disabling the previous one remains atomic and audited.

### 3.3 Validate the permission delta by ticket type

Do not use one “skip baseline for existing resource” rule for all ticket
types. Normalize candidate documents to canonical policy statements, derive
the added/removed/unchanged grant delta, and preserve the source statement and
policy origin. A change is not automatically safe merely because its target
resource already exists.

| Ticket type / operation | Required Phase 2 treatment |
|---|---|
| `CREATE_ROLE` | Evaluate all requested role permissions, trust-policy risk, and baseline coverage. Keep trust principals/actions as a separate validation domain; baseline action/resource rules do not authorize trust. |
| `ATTACH_USER_POLICY` attach | Resolve the managed policy document from the same-account inventory at a recorded snapshot/version. Evaluate the grants introduced by the attachment against the baseline and candidate-risk rules. If document/version cannot be resolved or is stale, return `SKIPPED` with a stable reason and require a designated human review path; never treat policy name/ARN alone as permission proof. |
| `ATTACH_USER_POLICY` detach | No grant is added by the requested detach. Record `NOT_APPLICABLE` for grant-expansion checks; still validate target/account ownership and source-ticket ownership rules. |
| `UPDATE_MANAGED_POLICY` | Compare the requested document with the currently inventoried default policy version. Apply baseline and risk checks to added grants; report removed grants as risk reduction. If the source document is absent, stale, or cannot be normalized losslessly, block submission for refresh or explicit remediation rather than silently skipping. |
| `UPDATE_GROUP_INLINE_POLICY` | Same delta treatment as managed policies, including role inline policies. Capture principal type, policy name, account, and source snapshot. Group inheritance can multiply impact, so show all known affected users/principals as contextual evidence where available; do not claim complete effective authorization. |
| `UPDATE_ROLE` | Validate trust-policy changes with dedicated trust-risk rules and explicit human review. If permissions are unchanged, do not claim a permission grant delta. When an operation also changes inline permissions, evaluate that delta independently. |
| `ROLLBACK` | Compute the effective reverse delta from the target ticket's immutable pre/post snapshots. A rollback can reintroduce broader permissions; therefore run the same baseline/risk checks on reintroduced grants. Missing or inconsistent snapshots block rollback validation. |

For updates to an existing policy, validate the **newly added/expanded grant
delta** against the baseline to avoid freezing all legacy out-of-baseline
permissions. Separately report pre-existing out-of-baseline grants as
`WARN`/context; do not imply that the update removes those grants. A future
policy may instead require full resulting-policy compliance, but that is a
separate account-level rollout decision.

Delta matching must be deterministic and conservative:

1. Parse the source and candidate documents and canonicalize statement order,
   action/resource case as defined by the DSL, conditions, and duplicate
   statements.
2. Preserve semantic distinctions; never drop condition keys, `NotAction`,
   `NotResource`, unsupported fields, or policy variables in order to make a
   comparison pass.
3. If exact semantic normalization is unavailable, mark the check
   `SKIPPED`/`ERROR` with a stable reason and require remediation; never infer
   that a change has no added grant.
4. Record stable statement indices/origins for UI explanation, but use a
   canonical request hash rather than unstable array positions as the
   idempotency identity.

### 3.4 Risk policy and exception handling

Separate mandatory hard stops from reviewable warnings:

- Hard stops remain non-overridable by ordinary approval: invalid/unsupported
  request shape, wildcard grant rejected by the generator's safety guard,
  provable baseline violation, unsafe external trust, missing target ownership,
  or validation data-integrity failure.
- Reviewable findings may be configured as block or warn by administrators.
  Every finding has stable `code`, severity, source, affected statement,
  description, and remediation guidance.
- Do not add a generic “force submit” or silent administrator bypass.
- If business exceptions become necessary, implement a separate, explicit,
  time-bounded exception record scoped to account + principal/resource +
  action + reason + owner + expiry. Require an independent authorized
  approver, record the exception ID/version in validation and audit evidence,
  and prohibit exceptions from overriding hard stops. Expired/revoked
  exceptions do not apply to new submissions. Existing immutable ticket
  decisions remain unchanged.

Exception management is a design option, not a prerequisite for the first
pilot. The default pilot path should be strict baseline enforcement without
override.

### 3.5 Validation persistence and user experience

Each validation attempt must contain:

- Ticket ID, attempt number, request SHA-256, validation time and top-level
  outcome.
- Baseline ID/version (nullable only with an explicit `NO_BASELINE` result).
- Source inventory snapshot timestamp/version for every policy used.
- Checks with stable code/outcome/severity, concise explanation, affected
  statement/action/resource, policy origin, and reason for skip/error.
- A minimal delta summary (added/removed/unchanged statement counts and
  canonical hashes). Avoid copying full policy documents into generic logs.
- A validation engine/rule-set version so old evidence is reproducible after
  rules change.

The submit page and approval view should show:

1. Requested permissions and expanded attached-policy grants when available.
2. Newly added versus removed grants, separately.
3. Baseline version and specific violations.
4. Risk findings and their dispositions.
5. Inventory freshness and every skipped check.
6. A clear warning that the result is static policy analysis, not an AWS
   authorization simulator and not proof of deployed state.

Submitting re-runs validation against current inventory and baseline. Persist
the final validation record atomically with approval snapshot creation and the
`DRAFT` → `APPROVING` transition. If any step fails, the ticket remains in
`DRAFT`.

### 3.6 Permission-governance measures

For a defined account and time window, report:

- Submission count by ticket type and validation outcome.
- Baseline-blocked requests and violated stable rule codes.
- Warning/exception count (if exceptions are later enabled).
- Candidate risk finding counts by severity and outcome.
- Count of validations skipped due to absent/stale policy inventory.
- Complete successful scan count and last successful complete scan time.
- Newly added and removed grants from normalized policy deltas.

Do not call a falling finding count “risk reduction” unless the compared scans
are complete, use equivalent scope/rules, and fall within an explicit
freshness window. Keep rejected, abandoned, and unsubmitted drafts separate.

## 4. Audit evidence design

### 4.1 Event model

Continue using `iam_audit_event` as the canonical append-only audit table.
Keep request middleware events as supplementary HTTP telemetry. Add
domain-level events for business state transitions and security-relevant
administrative actions, with a versioned metadata schema.

Required event envelope:

- Database-generated event ID and UTC event timestamp.
- Stable actor subject; actor type (`HUMAN`, `SERVICE`, `SYSTEM`) and, for a
  delegated action, both initiating human and service identity.
- Action code, target resource type/ID, outcome, request/correlation ID.
- Ticket number and account database ID where relevant.
- Metadata schema version, reason code, and references to immutable
  validation/baseline/execution records.
- For changed content, before/after canonical SHA-256 hashes and a concise
  safe summary. The authoritative request/baseline/policy remains in its
  domain record; do not duplicate secrets or full policy content in audit
  metadata by default.

Never record passwords, bearer/API tokens, Authorization headers, AWS
credentials, secret values, raw LDAP bind data, or unredacted provider error
bodies. Minimize personal data to stable subject ID and necessary display
context; access to audit must be more restricted than ordinary ticket reads.

### 4.2 Events to cover

At minimum, record these events:

**Permission controls**

- `IAM_BASELINE_CREATED`, `IAM_BASELINE_ENABLED_CHANGED` (already implemented;
  preserve).
- `IAM_BASELINE_EXCEPTION_CREATED/APPROVED/REVOKED/EXPIRED` only if exception
  records are implemented.
- Validation attempt outcome with baseline ID/version, validation record ID,
  request hash, and stable check result summary.

**Ticket lifecycle**

- `TICKET_DRAFT_CREATED`, `TICKET_SUBMITTED`, `TICKET_VALIDATION_BLOCKED`,
  `TICKET_APPROVED`, `TICKET_REJECTED`, `TICKET_PUBLISHED`,
  `TICKET_PUBLICATION_FAILED`, `TICKET_MR_STATUS_OBSERVED`,
  `TICKET_CLOSED_APPLIED`, `TICKET_CLOSED_ABANDONED`, and explicit retry/
  recovery actions.
- For decisions: approver subject, decision, reason/comment reference, and
  immutable approver snapshot version. Do not overwrite earlier decisions.
- For closure: actor/system source, closure reason and comment.
- `MR_STATUS_OBSERVED` remains an observation, not an apply/deployment event.
  The current `APPLIED` label must retain its documented limitation until the
  later pipeline integration.

**Identity and authorization (coordinate with LDAP workstream)**

- Login success/failure and account disable/lock events with non-sensitive
  reason codes; never record credentials.
- LDAP sync start/completion/failure, directory object counts, and watermark
  or sync run ID; do not dump full directory records.
- LDAP group-to-platform-role/account/approver mapping created, changed,
  disabled, or removed, including safe before/after mapping IDs.
- Token issue/revoke, role assignment, and account-scope assignment.

**Evidence access**

- `AUDIT_EVENTS_EXPORTED` (already implemented; preserve) with filters,
  row count, actor, time window, and export digest/ID.
- Per-ticket evidence-bundle access/export, including bundle version, covered
  event ID/time range, row count, and digest. Do not log the bundle contents.

### 4.3 Atomicity and failure behavior

For PostgreSQL-only mutations, write the state change and its business audit
event in the **same transaction**. If the audit insert fails, roll back the
mutation and return an explicit error. Apply this to ticket lifecycle changes,
approval decisions, role/account-scope assignments, exception records, and
baseline changes.

For external actions (LDAP bind/sync, Git-host publication/status retrieval,
AWS collection), a PostgreSQL transaction cannot cover the remote side effect:

1. Persist an operation intent/claim and correlation ID before dispatch when
   an externally visible action is initiated.
2. Persist the sanitized outcome and external stable reference after response.
3. Make retry/idempotency explicit; distinguish `UNKNOWN`/timeout from remote
   failure or success.
4. Never emit a success-shaped audit event for an uncertain outcome.
5. Do not claim that best-effort middleware logging makes the remote action
   auditable.

The HTTP middleware remains useful for request/route/status telemetry, but it
does not replace transactionally coupled domain events. Authentication failures
may be logged as security events without including supplied credentials; an
audit sink outage must not grant access or permit an unaudited privileged
mutation.

### 4.4 Ticket evidence view and export

Add a ticket-scoped evidence read model that assembles references from
authoritative tables rather than copying mutable duplicates:

- Immutable request and approver snapshots.
- Validation attempts, rule-set version, baseline version, check outcomes,
  and request hashes.
- Approval/rejection decisions with actor, timestamp, and comments.
- Git provider/repository/MR URL, commit and observed MR/CI states.
- Current platform closure reason and source.
- Related account sync run ID/result and inventory snapshot timestamp, clearly
  labelled as a refresh rather than per-ticket AWS state verification.
- Ordered domain audit events and a completeness checklist.

The response/export must state that a deployment/apply pipeline result is not
connected and that MR merge does not prove apply. Do not include credentials,
tokens, raw environment configuration, or unrelated user data.

For the pilot, bounded synchronous JSON export is sufficient (maximum rows and
date range enforced). Add stable ordering, an export ID, schema version, and
SHA-256 digest over canonical serialized output. Record the export itself as
an audit event. If exports later become large, move to an asynchronous,
access-controlled artifact with expiry rather than raising unbounded limits.

### 4.5 Retention and tamper evidence

The database append-only trigger protects against ordinary application
mutation, but not a database owner or privileged DBA. Do not describe it as
immutable external retention or compliance-grade evidence.

For the non-production pilot:

- Define retention and access policy with the system owner before collecting
  broad LDAP/audit data.
- Add monitoring for audit write failures and export activity.
- Keep backups protected and test restoration of audit + ticket records
  together.
- Evaluate export to an organization-approved append-only/immutable store as
  a separate deployment decision; do not select a vendor or retention period
  in this code design.

## 5. API and storage changes

Prefer additive changes and reuse existing records:

1. Extend `ticket_validation_record` with rule-set version and source snapshot
   references/hashes, if equivalent data is not already present in checks.
2. Add append-only ticket lifecycle event rows or durable transition
   timestamps. Recommendation: a normalized `ticket_lifecycle_event` table
   keyed by ticket, with stable event code, actor, occurred time, request ID,
   and safe metadata. Insert each row in the same transaction as the state
   transition. Use this for timing; keep `iam_audit_event` as the searchable
   security/audit ledger and link via event ID/correlation ID.
3. Add `GET /api/v1/tickets/:ticketNo/evidence` for authorized ticket readers,
   with owner/approver/admin access consistent with existing ticket scoping.
4. Add a bounded evidence export route for platform/approval administrators,
   with a recorded export event.
5. Add aggregate metrics only after event semantics are stable; always include
   the measurement window, sample count, and unknown/unavailable counts.

Avoid storing full policy blobs redundantly in audit rows. Reuse immutable
ticket snapshots, baseline versions, validation records, and execution
observations, linked by stable IDs and hashes.

## 6. Implementation sequencing

### Slice A — Define and test permission delta rules

- Add fixtures covering each ticket type and grant expansion/reduction.
- Implement canonical normalization and exact supported semantics.
- Treat stale/missing source state as explicit blocking/skipped outcomes.
- Add regression tests for wildcard ambiguity, conditions, managed-policy
  attach, policy updates, trust-only changes, rollback reintroduced grants,
  and legacy out-of-baseline grants.

### Slice B — Persist validation provenance and user-facing explanation

- Extend validation snapshots with source freshness, rule-set version and
  added/removed grant summaries.
- Make validation persistence atomic with final approval snapshot and submit
  transition.
- Expose stable findings in submit preview and approver view.

### Slice C — Transactional lifecycle audit

- Inventory every privileged/business mutation route.
- Add one domain event in the same transaction as each successful mutation.
- Ensure failed checks and rejected attempts are represented without
  success-shaped events.
- Add failure-injection tests proving an audit failure rolls back the business
  write.

### Slice D — Ticket evidence read/export

- Assemble ticket, validation, approval, MR, sync and audit references.
- Add scope/role tests, redaction tests, size/time bounds, canonical digest,
  and self-audit of export.
- Mark apply/deployment evidence explicitly `NOT_CONNECTED`.

### Slice E — Pilot review and measures

- Verify non-production account and LDAP/platform group mappings.
- Baseline the agreed time window after reliable events are available.
- Review blocked/warned grants, skipped checks, stale inventory, audit
  completeness, and stage durations with platform/security/account owners.
- Do not claim improvement from raw counts without comparable scans and
  adequately sized samples.

## 7. Acceptance criteria

### Permission governance

1. Each ticket type has documented and tested validation applicability.
2. A grant delta cannot pass due to missing, stale, malformed, or unsupported
   source policy data.
3. Newly added/expanded permissions are checked against the exact baseline
   version persisted in validation evidence.
4. Removals and pre-existing grants outside baseline are reported separately
   from new grants.
5. Risk results use stable machine-readable codes and cannot be silently
   downgraded by a generic bypass.
6. Trust-policy changes and rollbacks receive explicit validation; rollback
   cannot reintroduce grants without delta checks.
7. Users and approvers can see the baseline, findings, source freshness,
   skipped checks, and analysis limitations before approval.

### Audit evidence

1. Every successful ticket lifecycle and privileged permission mutation has a
   correlated domain audit event.
2. A database failure while inserting an event rolls back its associated
   PostgreSQL mutation.
3. Audit records are append-only, secret-free, scope-protected, and
   deterministically ordered.
4. A ticket evidence response links request, validation, baseline, decisions,
   Git observations, closure and sync records without implying deployment
   verification.
5. Audit/evidence export is bounded, redacted, content-digested, and itself
   audited.
6. Audit sink failure is surfaced and cannot produce a successful privileged
   mutation.
7. Retention limitations are documented; database append-only alone is not
   claimed as immutable/compliance-grade storage.

## 8. Decisions required before implementation

Recommended defaults are shown; resolve before changes to persisted semantics:

1. **No baseline on a pilot account:** default should be blocked for a
   production-like pilot; allow only via an explicit account opt-in with an
   audited reason. Confirm whether non-production is also strict.
2. **Stale source inventory threshold:** choose a freshness window for
   policy-update/attachment delta validation. Recommend blocking validation
   when source data is older than the configured window, with a clear “sync
   first” path.
3. **Baseline scope for updates:** this design checks newly added/expanded
   grants and reports legacy violations separately. Confirm this delta policy
   rather than requiring the resulting whole policy to be baseline-compliant.
4. **Risk findings:** confirm which existing static rules are hard blocks and
   which can be warnings. Wildcard-generated policy safety and unsupported
   semantics remain non-overridable.
5. **Exceptions:** recommendation is no exception bypass in the first pilot;
   if required, design expiry, independent approver, and non-overridable
   findings before implementation.
6. **Audit retention/export:** confirm required retention window, operators
   allowed to export, and the organization-approved immutable destination
   before production exposure.

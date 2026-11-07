# AWS IAM Governance Platform - Phase 1 Design

> Current implementation status is tracked in
> [phase2-baseline.md](./phase2-baseline.md). The progress bullets and migration
> sequence below are an earlier design-time snapshot and must not be read as
> the current delivery state.
>
> Status: Design reference. Current implementation and verification status are
> tracked in [phase2-baseline.md](./phase2-baseline.md).
>
> Original design scope: AWS-only governance, no direct IAM writes, and no
> home-grown IAM authorization simulator. See the current-state report for
> delivered UI and identity status.

## Implementation progress

- Foundation schema/model slice is implemented locally: migrations `0006`-
  `0011` and Phase 1 persistence models are present, with model/migration
  contract tests.
- Migrations `0006`-`0010` have been applied and verified in the configured
  local PostgreSQL database; `0011` adds a database guard for immutable ticket
  request/approver snapshots and must be applied before deployment.
- API-token authentication with SHA-256 digests, built-in role route guards,
  an audited one-time token CLI, owner/admin revocation, submitter-scoped ticket
  reads, and opt-in `AUTH_MODE=api-token` are implemented. The local
  `development` mode remains loopback-only.
- AWS account config admin APIs support create/list/get/update, explicit STS
  connection checks, and audited sync toggles. Create/update and enabling sync
  require account-identity validation; toggling sync on uses an optimistic
  timestamp check to prevent enabling a configuration different from the one
  validated.
- `cmd/aws-sync` supports an additive `AWS_SYNC_MODE=account-config` mode that
  reads only enabled account configs, safely claims them, records per-account
  status/timestamps, supports both configured-role and verified
  current-credentials collection, and limits post-sync PMapper enqueueing to
  successfully synchronized accounts. Existing organization/current-account
  modes remain unchanged.
- Account-scoped IAM baselines are versioned and immutable; admin APIs create,
  list, enable, and disable versions with audit events committed atomically.
  Ticket creation checks the current enabled baseline before persisting the
  ticket, conservatively blocks out-of-bound grants, and atomically stores a
  request hash plus baseline version in `ticket_validation_record`. If no
  baseline is enabled, the record explicitly reports `NO_BASELINE` and the
  existing ticket flow continues. Ticket creation also scans the translated
  candidate policy and trust policy with the existing static IAM rules before
  persistence; blocking findings return a structured `422`. A
  `STATIC_RISK_SCAN` outcome is included in the validation snapshot. The API
  supports `IAM_CANDIDATE_RISK_MODE=BLOCK|WARN` (default `BLOCK`); `WARN` allows
  only the administrator-like role-name heuristic, while wildcard grants,
  administrator-like actions, and external trust remain blocking. The
  generated-policy safety guard is unchanged. Ticket requests and approver
  snapshots are now saved as immutable `DRAFT` records by `POST /tickets`.
  `POST /tickets/{ticketNo}/submit` re-runs pre-validation against current
  baseline/inventory data, then atomically persists validation evidence and
  designated approvers before transitioning to `APPROVING`; blocked checks
  leave the draft untouched. Optional PMapper checks remain outstanding.
  Candidate grants are
  compared with unconditional Allow action/resource patterns on an inventoried
  same-name role; possible overlaps are advisory and recorded in the validation snapshot.
  A missing target role is recorded as `SKIPPED`. This comparison deliberately
  skips conditional statements and does not calculate effective authorization.
- A read-only policy-derived-grants endpoint now validates account/principal
  ownership, merges collected direct managed/inline and user-group policy
  statements, deduplicates normalized statements while preserving policy
  origins, and returns the inventory snapshot time plus partial-parse warnings.
  It explicitly does not claim to calculate AWS effective permissions.
- Git status polling and the additional query APIs are not implemented yet.

## 1. Purpose and baseline

Phase 1 extends the Phase 0 platform into a self-service access-request and
operational control plane:

1. Manage AWS account onboarding and synchronization configuration.
2. Enforce account-scoped permission baselines before ticket submission.
3. Add platform API-token authentication and role-based authorization.
4. Poll GitLab/GitHub merge/pull requests and CI asynchronously.
5. Expose policy-derived permission views and operational/audit queries.
6. Keep PMapper optional and outside the synchronous ticket critical path.

Phase 0 already provides AWS inventory synchronization, IAM groups and policy
attachments, policy translation, static risk scanning, ticket approvals,
Terraform generation, GitLab/GitHub publishing, Asynq, PostgreSQL persistence,
and HTTP request audit middleware.

### 1.1 Existing-schema and code facts to preserve

- Migrations `0001`-`0005` already create `platform_user`,
  `aws_account_approver`, `iam_audit_event`, IAM assets, ticket/approval tables,
  and inventory synchronization fields. Do not recreate these entities.
- `aws_account.id` is the platform database key; `aws_account.account_id` is
  the external 12-digit AWS account ID.
- Ticket requests and approver IDs are protected by a database immutability
  trigger. Keep the request snapshot and approver snapshot immutable.
- Current ticket creation enters `APPROVING` directly. A Phase 1 draft-and-submit
  API must be introduced explicitly; do not describe an existing editable-draft
  flow as already implemented.
- Phase 0 has two permission representations: the original
  `internal/model.AbstractPermission`, used by ticket Terraform generation,
  and `pkg/model/abstractiam.AbstractPolicy`, used by the neutral translator.
  Phase 1 must define one canonical internal representation and add explicit
  conversion/compatibility tests before changing persisted/API payloads.
- Current Git publishers create a GitLab MR or GitHub PR and return its URL.
  They do not expose status polling or CI results. Provider status APIs and
  stable remote identifiers must be added.
- The static audit middleware records request metadata but is not a substitute
  for transactionally auditing successful business mutations.
- Current PMapper execution requires an installed compatible CLI and is not a
  reliable synchronous validator. The feature remains optional.

## 2. Scope and non-negotiable rules

### In scope

1. AWS account operational configuration CRUD, connectivity test, and sync
   enable/disable.
2. Account-scoped IAM permission baselines stored as canonical Abstract DSL.
3. Ticket submit-time pre-validation: baseline, request static risk, redundant
   grant detection, and optional precomputed PMapper graph findings.
4. Platform API-token authentication, user status, and three built-in roles:
   `platform_admin`, `approval_admin`, `standard_user`.
5. Asynchronous Git-host MR/PR and CI status polling with bounded retries.
6. IaC execution history, ticket filters/statistics, risk query, effective
   policy-derived permission query, audit query, and bounded audit export.
7. `aws-sync` configuration-driven collection in both Organization and direct
   single-account modes.

### Out of scope

- Azure, GCP, or other cloud providers.
- Direct AWS IAM mutation APIs. GitOps remains the only write path.
- A home-grown IAM policy simulator or a claim that merged policy documents
  equal effective AWS authorization.
- Web UI, SAML/OIDC, notifications, key lifecycle, permission expiry, and bulk
  ticket/baseline operations.
- Making PMapper a prerequisite for ticket submission.

### Invariants

1. **GitOps only:** AWS IAM writes happen only in protected Git CI after review.
2. **PostgreSQL is authoritative:** Redis/Asynq only transports work.
3. **Immutable requests:** Request DSL, target account/principal, and approval
   assignments are immutable once a ticket is created. Corrections require a
   new ticket.
4. **Baseline validates; it does not generate:** A baseline never creates or
   modifies AWS permissions.
5. **Identity separation:** Platform users are not AWS IAM principals.
6. **External I/O is asynchronous where it can take time:** MR/CI polling,
   exports, and graph builds do not block ordinary HTTP requests.
7. **Optional analysis fails open:** An unavailable/stale PMapper result is
   reported as skipped, not as a ticket rejection.
8. **Complete inventory only:** Never mark a sync successful or reconcile away
   prior inventory after a partial AWS collection.
9. **Audit mutations durably:** A successful business mutation and its audit
   event commit together wherever both reside in PostgreSQL.

## 3. Component map

| Component | Phase 1 responsibility |
|---|---|
| `cmd/api` | API-token authentication, RBAC authorization, account/baseline/user/ticket/permission/audit handlers |
| `cmd/migrate` | Ordered transactional migrations `0006+`; preserve applied migrations |
| `cmd/aws-sync` | Read enabled onboarding configs, collect only configured accounts, record attempts/results |
| `cmd/gitstatus-worker` | Consume bounded MR/CI polling jobs and persist state transitions/execution records |
| `cmd/pmapper-worker` | Existing optional worker; graph freshness/health reporting, no core-path dependency |
| `internal/handler` | Validate API input, actor context, pagination, response/error mapping |
| `internal/service` | Account config, baseline validation, RBAC, pre-validation, effective grants, Git status, query services |
| `internal/adapter` | Canonical DSL conversion, AWS translation, policy-origin normalization |
| `internal/githost` | Provider-neutral MR/PR and CI read API; GitLab and GitHub implementations |
| `internal/model` | Models for account config, baselines, tokens/roles, validations, and execution records |
| PostgreSQL | Business state, snapshots, baselines, audit, tickets, execution history, graph relationships |
| Redis/Asynq | At-least-once task delivery only; all handlers idempotent |

No destructive Phase 0 refactor is required. New services should depend on
interfaces and reuse Phase 0 repositories/adapters where their semantics match.

## 4. AWS account onboarding and synchronization

### 4.1 Operational config versus collected assets

Keep `aws_account` as the inventory/sync snapshot entity. Add
`aws_account_config` as the operator-managed source of truth for collection
settings. The existing `aws_account.read_only_role_arn` may remain as a
compatibility mirror during rollout, but new sync code must read the
configuration record rather than silently choosing between duplicate values.

Recommended `aws_account_config` fields:

| Field | Meaning |
|---|---|
| `id` | Surrogate primary key |
| `aws_account_id` | Unique external 12-digit account ID |
| `organization_id` | Nullable FK to `aws_organization.id`; null for standalone accounts |
| `display_name` | Operator-maintained label |
| `read_only_role_arn` | Role to assume for Organization member collection; may be null only for an explicitly configured direct-credential mode |
| `sync_mode` | `ASSUME_ROLE` or `CURRENT_CREDENTIALS` |
| `sync_enabled` | Whether scheduled/manual sync may collect this account |
| `tags` | Platform-maintained JSONB metadata; AWS Organizations tags are separate collected data |
| `sync_status` | `NEVER`, `RUNNING`, `SUCCEEDED`, `FAILED`, or `DISABLED` |
| `last_sync_attempt_at` | Most recent attempt |
| `last_successful_sync_at` | Most recent complete inventory save |
| `last_sync_error` | Sanitized operational error; never credentials |
| timestamps | Creation/update timestamps |

Use `aws_account_id` as a unique key. Do not overload the existing
`aws_account.org_id` numeric FK with the AWS Organizations string ID.
Provisioning metadata and collected AWS account metadata have different owners
and lifecycles.

### 4.2 CRUD and connectivity validation

- `POST /api/v1/aws/account-configs`: validate account ID, ARN syntax, mode,
  tags size/shape, and role policy. Test `sts:AssumeRole`/`GetCallerIdentity`
  before activating an `ASSUME_ROLE` config. Never persist supplied credentials.
- `PUT /api/v1/aws/account-configs/:id`: same validation; changing account ID
  should be rejected. Role changes require a successful connection test.
- `POST /api/v1/aws/account-configs/:id/test-connection`: perform bounded STS
  calls and return the caller/target account IDs without exposing credentials.
- `POST /api/v1/aws/account-configs/:id/sync`: enqueue a sync request; do not run
  the AWS inventory operation on the HTTP thread.
- `PATCH .../:id/sync-enabled`: explicit enable/disable operation with audit.
- All APIs are platform-admin-only; do not hard-delete config while tickets,
  audit, or collected assets refer to the account. Disable/archive instead.

The existing one-shot `cmd/aws-sync` should gain config-driven selection:

- Organization mode lists accounts using the configured Organization
  management identity, then collects only active, configured,
  `sync_enabled=true` accounts with their configured read-only roles.
- Standalone mode uses the configured direct credentials only for the matching
  account and must verify identity through STS before collection.
- A disabled or unconfigured account is skipped and is not marked failed.
- Persist `RUNNING` and attempt time before collection. Persist
  `SUCCEEDED`/last-success only after the complete asset transaction commits.
  On failure persist `FAILED` and a sanitized error.
- Use per-account locks/idempotency keys so two sync requests cannot reconcile
  the same account concurrently.
- Keep AWS SDK retry and timeout bounds. Do not silently swallow per-account
  failures; return a run summary and non-zero command exit when any requested
  account fails.

Account tags supplied by the operator are platform metadata. Import AWS tags
only through a specifically authorized AWS API and store them separately; do
not imply Organizations access exists in standalone mode.

## 5. Canonical policy DSL and baseline enforcement

### 5.1 Canonical representation

Use `pkg/model/abstractiam.AbstractPolicy` as the canonical cloud-neutral
representation for new Phase 1 features. It has `Effect`, abstract `Actions`,
`Resources`, negated selectors, and generic conditions. The original ticket
`AbstractPermission` remains an API/storage compatibility format until an
explicit versioned conversion is shipped.

Before changing ticket payloads:

1. Add adapters both ways where the conversion is lossless.
2. Reject conversion when a legacy action has no canonical mapping; do not
   guess or drop conditions.
3. Version ticket DSL payloads (for example `dsl_version`) and keep the
   original immutable snapshot.
4. Add fixture tests for all existing ticket examples and Terraform output.

### 5.2 Baseline meaning

A baseline is an account-scoped **maximum grant boundary** for new requests,
not an IAM policy to attach. Version each baseline; only one enabled version
per account is effective. Disabling a baseline means no baseline restriction;
it does not mean “deny all.”

Phase 1 baseline subset:

- Support only explicit `Allow` request statements with positive `Actions` and
  `Resources`.
- Baselines contain allowed action/resource patterns and optional required
  conditions. `Deny`, `NotAction`, `NotResource`, and unsupported condition
  operators are rejected at baseline write time unless semantics are added and
  tested explicitly.
- A request action/resource is compliant only if it is provably within the
  baseline patterns. Use a deliberately conservative matcher; ambiguous
  wildcard containment is a blocking validation error, not an assumed match.
- Required baseline conditions must be present with compatible operator/value
  constraints in the request. Document exact supported operators.
- Return stable machine-readable violation codes plus human descriptions and
  statement indices.

The baseline check is not an AWS policy simulator and does not account for SCPs,
permission boundaries, session policies, or runtime request context.

### 5.3 Pre-validation pipeline

Ticket creation stores an immutable `DRAFT` request snapshot and approver
snapshot. The explicit submit transition runs all synchronous blocking checks
in this order:

1. Schema, account/principal ownership, and supported ticket type.
2. Baseline compliance against the current enabled baseline version.
3. Static risk scan on the generated candidate AWS policy, reusing extracted
   Phase 0 risk rules rather than querying only already-persisted policies.
4. Existing-grant overlap analysis against the target principal's direct and
   group-inherited attached policies. The current create-role flow compares
   same-name inventoried role policies only; possible overlaps are advisory,
   conditional statements are skipped, and a missing target is recorded as
   `SKIPPED`. It is not effective authorization evaluation.
5. Optional PMapper finding lookup from a completed graph with matching account
   and principal, plus a freshness bound. Do not enqueue a graph and wait in the
   request. If disabled, unhealthy, absent, or stale, record `SKIPPED` and
   continue.

All validators pass -> atomically persist an immutable validation record,
including baseline version and request hash, and transition `DRAFT` to
`APPROVING`. A blocking failure leaves the ticket in `DRAFT` and returns
structured validation results. A transient dependency/database failure is an
operational error, not a pass.

Risk mode is explicit per platform configuration: `BLOCK` or `WARN`. Security
administrators should be able to set a non-overridable block for critical
findings. The validator must not weaken Phase 0's high-risk generated-policy
guard.

## 6. Ticket lifecycle and GitOps result processing

### 6.1 States

Retain existing states and add `PUBLISH_FAILED` and `CLOSED`. The final state
`CLOSED` needs a required `closure_reason` to distinguish successful apply
from explicit administrative abandonment.

| State | Meaning |
|---|---|
| `DRAFT` | Immutable request snapshot exists; not submitted |
| `APPROVING` | Awaiting designated approvals |
| `REJECTED` | Rejected; terminal |
| `APPROVED` | Approval complete; publication may start or an MR/PR is under review |
| `PUBLISHING` | Git publication or retry is in progress |
| `PUBLISH_FAILED` | A bounded publication/CI failure requires explicit retry or closure |
| `MERGED` | Legacy state; retain/read during migration and define compatibility behavior |
| `CLOSED` | Terminal; reason is `APPLIED` or `ABANDONED` |

Recommended path:

```text
DRAFT --submit + checks pass--> APPROVING
APPROVING --rejected--> REJECTED
APPROVING --all approved--> APPROVED
APPROVED --publish claimed--> PUBLISHING
PUBLISHING --MR/PR created--> APPROVED (remote review in progress)
APPROVED --MR merged + successful apply CI--> CLOSED(APPLIED)
PUBLISHING/APPROVED --permanent publish or CI failure--> PUBLISH_FAILED
PUBLISH_FAILED --retry accepted--> PUBLISHING
any non-terminal state --authorized admin close--> CLOSED(ABANDONED)
```

Do not transition to `CLOSED(APPLIED)` on merge alone: require a successful
protected apply pipeline associated with the same MR/PR commit. Do not treat a
transient polling/API outage as `PUBLISH_FAILED`; preserve state and retry the
poll with bounded backoff.

### 6.2 Asynchronous Git status worker

Extend `TicketPublisher`/provider code behind a provider-neutral `GitHost`
interface with:

- Fetch MR/PR by stable provider, repository/project, and remote number.
- Fetch associated pipeline/check runs and commit SHA.
- Optional explicit pipeline retry only if supported, authorized, and
  idempotent.

Persist enough information to poll: provider, repository/project identifier,
remote request number, URL, source branch, target branch, commit SHA, and last
observed state. URL parsing must not be the only identity source.

After publication, enqueue an idempotent task keyed by ticket + remote request.
Poll with exponential backoff and jitter, a maximum attempt count, and a
maximum overall age. Handle duplicate deliveries with conditional updates and
unique execution keys. On exhaustion, expose an operationally retryable status
without falsely claiming CI failure.

Use explicit CI states `PENDING`, `RUNNING`, `SUCCEEDED`, `FAILED`,
`CANCELED`, `UNKNOWN`; record MR state separately (`OPEN`, `MERGED`, `CLOSED`).
Require commit SHA correlation before mapping CI success to ticket completion.
Never invoke AWS apply from the platform; protected Git-host CI owns Terraform
execution.

`PUBLISH_FAILED` retry must be precise:

- If no MR/PR was created, retry idempotent publication using the same ticket
  snapshot and stable branch.
- If the remote request exists, do not create a duplicate. Reconcile its
  current state; only request a CI rerun through an explicitly supported
  provider capability, otherwise require operator remediation/new ticket.
- A changed business permission request always requires a new ticket.

### 6.3 IaC execution record

Recommended `iac_execution_record` columns:

`id`, `ticket_id`, provider, project/repository, remote request number, remote
URL, commit SHA, pipeline/run ID, MR state, CI state, apply result, started /
finished / observed timestamps, attempt number, sanitized error, and
`metadata JSONB`. Add a unique key for provider + repository + pipeline/run ID
and indexes for ticket, state, and time. Records are append-only observations;
do not overwrite historical outcomes.

## 7. Platform identity and RBAC

Reuse `platform_user`; add API token and role assignment tables. Keep existing
`aws_account_approver` for approval routing, separate from RBAC roles.

### 7.1 Token handling

- Generate at least 256 bits of cryptographically secure random token entropy.
- Return the raw token once at creation; persist only a one-way digest and a
  non-secret token prefix/ID for lookup and support.
- Support expiry, revocation, last-used timestamp, creator, and scoped
  permissions if needed. Never log token values or store them in audit metadata.
- Use HTTPS outside local development. Apply constant-time digest comparison
  when comparing candidate tokens.
- Enforce user active state, token expiration/revocation, and role lookup on
  every request; define a short cache with revocation invalidation or avoid
  caching initially.
- Bootstrap the first platform administrator out-of-band; do not allow
  unauthenticated self-assignment of `platform_admin`.

### 7.2 Role matrix

| Capability | `platform_admin` | `approval_admin` | `standard_user` |
|---|---:|---:|---:|
| Account config / sync control | Yes | No | No |
| Baseline management | Yes | No | No |
| Platform user/token/role administration | Yes | No | No |
| Approve/reject designated tickets | Yes | Yes, if designated | No |
| Create and submit tickets | Yes | Yes | Yes |
| Read own tickets | Yes | Yes | Yes |
| Read all tickets and operational stats | Yes | Yes | No |
| Read risk/effective-grant views | Yes | Yes | Account-scoped policy |
| Read/export audit events | Yes | No by default | No |
| Close tickets / retry failed publication | Yes | Explicit policy only | No |

Authorization is both role- and resource-scoped. An `approval_admin` cannot
approve a ticket unless present in its immutable approver snapshot. A
`standard_user` cannot enumerate other users' tickets by changing a filter.
Prefer deny-by-default route policy and tests for every route group.

## 8. Effective permission view

Expose a read-only **policy-derived grants** API; avoid claiming the result is
AWS "effective permissions." Merge:

- Direct managed and inline policies for the principal.
- Policies inherited from IAM Groups for IAM users.
- Policy origin metadata (direct/group, ARN/name/type, collected timestamp).

For each input policy, use the canonical DSL converter and return parse
warnings. Deduplicate identical normalized statements while preserving all
origins. Include data freshness and unsupported/partial parse warnings.

Do not claim authorization equivalence: the inventory does not necessarily
include SCPs, permission boundaries, session policies, resource policies,
conditions evaluated against request context, or every service-specific rule.
No `Simulate*` call or custom evaluator is added.

Suggested endpoint:

`GET /api/v1/aws/accounts/{accountDbId}/principals/{principalDbId}/policy-derived-grants`

Verify both IDs belong to the same account; return 404 for cross-account or
missing principals to avoid leaking inventory.

## 9. Query and audit APIs

### 9.1 Tickets and risks

- Ticket list filters: external/account DB ID (document which is accepted),
  status, submitter, created-after/before. Require bounded page size and stable
  ordering; use cursor pagination for large result sets.
- Statistics endpoint: totals by state/account/time window, with the same
  authorization scope as the ticket list.
- Risk list filters: account, risk type/level, resolved state, time window;
  use bounded pagination.
- Validate time ranges, page size, sort columns (allowlist only), and account
  access. Use parameterized SQL for values.

### 9.2 Audit retrieval/export

Reuse append-only `iam_audit_event`; do not create a duplicate audit log.
Support filters by actor, resource/ticket, account metadata, action, outcome,
and time range. Add an account ID/resource relation to audit metadata only if
the existing generic event fields cannot support reliable joins.

- Audit write failures for successful administrative mutations must fail and
  roll back the mutation.
- Middleware HTTP audit remains supplementary request telemetry; ensure it
  never records Authorization headers, raw tokens, request bodies, or secrets.
- Export returns a bounded JSONL/JSON snippet with stable event IDs, a maximum
  row count and time window, and an audit event recording who exported what.
- Do not permit ordinary users to query audit data.

## 10. Database changes and indexes

Current latest Phase 0 migration is `0005`. Append migrations; never edit an
applied migration. Proposed sequence (split further if review benefits):

```text
0006_platform_tokens_and_roles
0007_aws_account_config
0008_iam_baselines_and_validation_records
0009_iac_execution_records
0010_ticket_status_and_remote_polling_fields
```

Reuse `platform_user`, `aws_account_approver`, and `iam_audit_event`.
Seed built-in roles idempotently. Add FK/index coverage for ticket state/time,
account config enabled/status, baseline account/version/enabled,
execution ticket/time/CI state, token user/prefix/revocation, and audit actor/
resource/time. Add GIN indexes only where actual JSONB query predicates need
them; do not index every JSON document by default.

Migration safety:

1. Add new nullable columns/tables first.
2. Backfill/normalize existing ticket states and remote IDs where possible.
3. Add constraints after data validation.
4. Keep compatibility reads for legacy `MERGED`.
5. Document rollback and ensure it does not delete audit or execution history.

Use database constraints for status enum checks, unique active baseline
version, token digest uniqueness, and idempotency. Use append-only execution and
audit records; application-level immutability alone is insufficient.

## 11. API outline

| Method | Endpoint | Roles |
|---|---|---|
| `POST/GET` | `/api/v1/aws/account-configs` | admin |
| `GET/PUT` | `/api/v1/aws/account-configs/{id}` | admin |
| `POST` | `/api/v1/aws/account-configs/{id}/test-connection` | admin |
| `POST` | `/api/v1/aws/account-configs/{id}/sync` | admin |
| `PATCH` | `/api/v1/aws/account-configs/{id}/sync-enabled` | admin |
| `POST/GET` | `/api/v1/aws/accounts/{id}/baselines` | admin |
| `PUT` | `/api/v1/aws/accounts/{id}/baselines/{baselineId}` | admin |
| `POST` | `/api/v1/tickets` | authenticated user; creates immutable draft |
| `POST` | `/api/v1/tickets/{ticketNo}/submit` | owner/admin |
| `GET` | `/api/v1/tickets` | role + owner scope |
| `POST` | `/api/v1/tickets/{ticketNo}/retry-publish` | admin |
| `POST` | `/api/v1/tickets/{ticketNo}/close` | admin |
| `GET` | `/api/v1/tickets/statistics` | admin/approval admin |
| `GET` | `/api/v1/aws/accounts/{accountDbId}/principals/{principalDbId}/policy-derived-grants` | authorized account reader |
| `GET` | `/api/v1/aws/accounts/{id}/risks` | authorized account reader |
| `GET` | `/api/v1/audit/events` | admin |
| `POST` | `/api/v1/audit/exports` | admin; bounded async export if large |
| `POST/GET` | `/api/v1/platform/users` | admin |
| `POST/GET` | `/api/v1/platform/users/{id}/tokens` | admin/user-specific token policy |
| `POST` | `/api/v1/platform/tokens/{id}/revoke` | admin or owner |

All write APIs accept an idempotency key where retries could create duplicate
records or external requests. Return structured validation errors with stable
codes, not only free-form strings.

## 12. Observability and resilience

- Structured logs include request ID, actor ID (not token), account DB ID,
  ticket number, task ID, provider, and attempt.
- Metrics: sync duration/failures/skips; ticket validation results; queue
  depth/age/retries; Git-host rate limits; poll attempts/age; CI outcomes;
  authentication and authorization failures.
- Health/readiness reports PostgreSQL, Redis, worker heartbeat, and optional
  PMapper capability separately. Redis availability does not prove a worker is
  consuming tasks.
- Set explicit HTTP, DB, STS, AWS SDK, Git-host, worker, and export timeouts.
- Retry only transient errors with bounded exponential backoff and jitter;
  honor Git-host rate-limit/retry-after headers.
- Redact error bodies that may contain secret data. Bound response sizes.
- Define retention for tokens, audit, execution history, and raw policy
  snapshots with compliance review before implementing deletion.

## 13. Definition of Done

1. Account config CRUD, STS validation, sync toggles, manual sync enqueue, and
   success/failure timestamps work for both Organization and standalone modes.
2. Disabled accounts are not collected; failed/partial collection never marks
   success or reconciles incomplete data.
3. Baseline CRUD is versioned. Violating requests remain draft; compliant
   requests enter approval only after validation record is persisted.
4. Static risk findings on candidate requests are tested in block and warn
   modes. Overlap is explicitly advisory or blocked per documented exact rule.
5. PMapper disabled/unhealthy/stale cases skip with a recorded reason and do not
   reject the main ticket path.
6. API tokens are hashed at rest, expire/revoke correctly, never appear in
   logs, and all routes are deny-by-default RBAC protected.
7. Ticket ownership, approver designation, immutable request/approver snapshots,
   and submitter self-approval prevention are tested.
8. GitLab and GitHub polling correlate the correct MR/PR, pipeline, and commit;
   duplicate tasks do not duplicate execution records or cause illegal state
   transitions.
9. `CLOSED(APPLIED)` requires matching successful apply CI; admin abandonment
   is distinguishable and terminal.
10. Policy-derived grants merge direct/group policies and disclose partial
    coverage without claiming simulated AWS authorization.
11. Ticket/risk/audit filters, pagination, statistics, and bounded audit
    export enforce caller scopes and use parameterized SQL.
12. Every business mutation has a durable audit event; failures do not create
    unaudited successful changes.
13. Targeted tests, `go test ./...`, `go vet ./...`, migrations against an
    ephemeral PostgreSQL instance, and Git-host contract tests pass.
14. Existing Phase 0 inventory, static scan, approvals, Terraform rendering,
    and Git publishing tests remain passing.

## 14. Open decisions

Resolve these before implementation where they affect stored data or security:

1. Token revocation scope: platform admins only, or token owner may revoke
   their own tokens? Recommended: both, with admin audit.
2. Risk finding policy: which exact findings block by default, and may any
   role override a critical block? Recommended: critical findings are
   non-overridable; lower severities are configurable warn/block.
3. Baseline policy when no enabled baseline exists: recommended behavior is
   allow submission subject to static risk checks, with an explicit
   `NO_BASELINE` validation result; optionally require a baseline per account.
4. CI failure recovery: provider pipeline rerun versus operator remediation
   and new ticket. Do not silently mutate the immutable ticket request.
5. Retention and export limits for audit, tokens, and execution records; align
   with organization policy before implementing deletion.
6. Phase 1 draft UX: create an immutable draft then submit, or keep existing
   create-and-submit endpoint and run pre-validation before insert. Recommended
   additive API: immutable draft plus explicit submit, preserving the legacy
   endpoint behavior during a versioned transition.

## 15. Implementation sequencing

1. **Foundation:** canonical DSL compatibility tests; migrations for roles,
   token hashing, account config, baseline versions, status extensions, and
   execution records.
2. **Identity and account operations:** bootstrap admin, token auth/RBAC,
   account config CRUD/test/sync toggle, audit mutation transactionality.
3. **Policy validation:** baseline semantics, candidate risk scan, overlap view,
   immutable validation result and submit transition.
4. **Git status:** provider read interfaces, polling worker, idempotent
   execution history, ticket terminal/retry transitions.
5. **Read APIs:** policy-derived grants, ticket/risk/audit filters, stats,
   bounded export, metrics and operational readiness.
6. **Hardening:** migration rehearsal, failure injection, rate-limit tests,
   race tests, API security tests, and Phase 0 regression suite.

Ship each stage behind additive migrations and feature flags where behavior
changes. PMapper remains disabled by default until its CLI compatibility,
worker health, and graph freshness are demonstrated in the deployment runtime.

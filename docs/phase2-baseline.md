# Phase 2 P0-0: Current State and Metrics Baseline

**Verification date:** 2026-10-20  
**Local runtime snapshot:** 2026-10-20 14:37 +08:00
**Selected scope:** the sole enabled, inventory-linked account in the connected
local database; all six ticket types selected by the user; all account-scoped
ticket history currently available.

## Executive summary

The project has a substantial access-governance workflow in source and the
current Go test and vet suites pass. The local API, PostgreSQL/Redis readiness,
and sync-worker health checks also respond successfully.

This is not yet evidence that the project has improved production request
times, reduced over-broad access, or verified changes in AWS. The observed
counts come from the database connected to the API running on this workstation;
the environment classification (production/non-production) and AWS account
identity were not independently established.
No production Git-host, protected apply pipeline, or post-apply AWS-state
verification was exercised.

The intended ownership boundary is that the platform polls the MR lifecycle
and stops when the MR is merged; Terraform apply is a deployment concern owned
by a pipeline that may run from the MR or from the protected master branch.
Accordingly, stopping MR polling after merge is intentional, not a polling
reliability defect.

The current implementation nevertheless conflates those lifecycle stages:
it closes a ticket as `APPLIED` when **MR merged AND the first CI status for
the MR commit is successful**, and treats an empty CI-check set as success.
Those observations do not identify a later protected deployment pipeline or
prove that it applied the approved change. The issue is the ticket transition
and evidence contract, not a need to keep polling the MR after merge. A future
pipeline integration should report deployment outcome separately and only
then transition the ticket to an applied/deployed state.

For the proposed permission-delta validation, ticket audit events, and
evidence-bundle design, see
[Phase 2 Permission Governance and Audit Evidence](./phase2-permissions-audit-design.md)
or its [Chinese version](./phase2-permissions-audit-design.zh-CN.md).

## Scope and method

- Reviewed the Phase 0/Phase 1 design and implementation-status documents,
  current service/handler/migration code, and the ticket, risk, sync, Git-status,
  execution-history, and audit paths.
- Ran `go test ./... -count=1` and `go vet ./...`; both passed.
- Queried the loopback API using the local development identity shim. The sole
  configured account was linked to its ticket history by internal database ID;
  output retained only grouped counts, closure labels, and elapsed-time
  percentiles. Ticket bodies, principal/user identities, AWS account IDs,
  credentials, and secret configuration values were not printed or recorded in
  this report.
- Confirmed API readiness and sync-worker `/healthz` returned HTTP 200. The
  sync-worker reported online with zero pending runs at the snapshot.
- This did not test real AWS credentials, the identity of the configured AWS
  account, external Git-host permissions, branch protections, a real apply
  pipeline, or whether the resulting IAM state matched a ticket.
- The user selected the current unique account, all six supported ticket types,
  and "from launch to now." The available account-linked ticket history spans
  2026-10-09 through 2026-10-20; the actual project launch date and whether
  older records exist elsewhere were not established.

## Current capability assessment

| Goal / capability | Current evidence | Gap to the outcome |
|---|---|---|
| Faster access requests | Ticket creation, approval, Terraform publication, and Git status polling are present in source; current tests pass. | Only creation-to-platform-closure durations can be derived. There are no reliable submit, approval, review, or verified-apply stage times, and the local sample is not production data. |
| Fewer over-broad permissions | Account-scoped baseline validation and candidate-policy risk checks are implemented. | The local dashboard reports unresolved findings but not scan freshness, scan completeness, baseline-violation trends, approved exceptions, or post-apply drift. Static scanning is not AWS authorization simulation. |
| Easier audit evidence | Append-only audit storage, filtered audit query/export, validation snapshots, and append-only IaC execution observations are present. | Request middleware audit is best-effort; end-to-end transactional audit coverage and external immutable retention have not been established. No evidence-completeness KPI is exposed. |
| Change safely reaches AWS | Git status polling records MR/CI observations and stops at merge. Current auto-close requires MR merged plus the first CI status succeeded, then triggers an account sync. | MR merge/CI status is not evidence that the separate protected deployment pipeline applied the change. The empty-status success fallback is unsafe for an `APPLIED` conclusion. The subsequent sync refreshes inventory but does not compare expected ticket state with observed AWS state. Pipeline reporting/trust is not yet integrated or verified. |
| Production operations | Local API readiness and sync-worker health passed; sync worker reported online and no pending runs. | This is a workstation/runtime check, not production deployment evidence, and the connected database/account environment was not verified. Production SSO/OIDC is also not in place. |

## Local aggregate snapshot

The following counts were returned by the API at approximately
**2026-10-20 14:37 +08:00**. Treat them as a point-in-time local snapshot, not
as a production baseline or a trend:

| Measure | Observed value |
|---|---:|
| Tickets | 33 total; all currently `CLOSED` |
| Open risks | 207: 77 `HIGH`, 130 `MEDIUM` |
| Inventoried IAM principals/groups | 59 users, 80 roles, 22 groups |
| Account sync configuration | 1 total, 1 enabled, status `SUCCEEDED` |
| Sync runs created in the last 24 hours | 2 `SUCCEEDED`, 1 `FAILED` |
| IaC execution observations | 124 total; 12 have `apply_result=FAILED` |
| Git-status polling queue | 0 at scrape time |
| Sync-worker status | online; 0 pending runs |

### Selected account: ticket history available in the connected database

All 33 tickets currently associated with the selected account are closed.
Elapsed time below is from ticket creation to the platform's `CLOSED` timestamp
for tickets labelled `closure_reason=APPLIED`. Those labels currently require
MR merged and the first MR-commit CI status succeeded; they do **not** prove
that the separate deployment pipeline applied the change or that AWS reached
the requested state. Percentiles are descriptive only, with very small
samples.

| Ticket type | Total | Platform `APPLIED` | `ABANDONED` | Applied-label sample | Create-to-close P50 | P90 |
|---|---:|---:|---:|---:|---:|---:|
| `ATTACH_USER_POLICY` | 6 | 1 | 5 | 1 | 10.5 min | 10.5 min |
| `CREATE_ROLE` | 7 | 3 | 4 | 3 | 745.9 min | 1,138.4 min |
| `ROLLBACK` | 4 | 3 | 1 | 3 | 4.5 min | 88.7 min |
| `UPDATE_GROUP_INLINE_POLICY` | 10 | 6 | 4 | 6 | 10.8 min | 238.4 min |
| `UPDATE_MANAGED_POLICY` | 4 | 0 | 4 | 0 | N/A | N/A |
| `UPDATE_ROLE` | 2 | 1 | 1 | 1 | 8.2 min | 8.2 min |

The history contains **14 platform-labelled `APPLIED`** and **19
`ABANDONED`** tickets. These counts are useful for describing the local
workflow's recorded history, not for asserting AWS delivery or a representative
business success rate. The full stored range is only 11 calendar days, and the
sample is too small to set stable service targets. The account configuration
was created on 2026-10-10 while the first linked ticket dates to 2026-10-09;
this may be inherited history and is not evidence of the project's launch date.

Important interpretation limits:

- `CLOSED` does not distinguish `APPLIED` from `ABANDONED` in the current
  aggregate metric.
- IaC rows are append-only observations/retries, not necessarily unique apply
  executions. `12 / 124` is **not** a valid apply failure rate.
- The `finops_queue_depth` metric is for the Git-status polling queue, not the
  sync queue. The sync queue was separately reported by the authenticated
  worker-status endpoint.
- Open-risk counts have no accompanying successful-scan timestamp in this
  snapshot. They cannot establish current AWS exposure or risk reduction.
- The single successful account-config status does not, by itself, prove that
  the account was a real AWS target or that this data source is production.

## Measurement readiness

| Outcome | Baseline definition for the pilot | Current readiness |
|---|---|---|
| Faster requests | Median and P90 elapsed time for draft-to-submit, submit-to-final-approval, approval-to-PR, and PR-to-verified AWS state; report abandoned/rejected requests separately. | Not measurable reliably from current dashboard metrics. Ticket creation/closure timestamps exist, but closure combines applied and abandoned outcomes; approval rows do not have a dedicated decision timestamp. Best-effort HTTP audit events are not a sufficient substitute for durable business-transition timestamps. |
| Fewer over-broad grants | Baseline-block rate, high/critical candidate findings, approved exception count, and findings per successful complete account scan; compare equivalent scan windows. | Only current unresolved-risk counts are exposed. Scan freshness/completeness and a comparable time-series baseline are missing. |
| Easier audit evidence | Percentage of applied tickets with request/validation snapshot, approval decisions, MR/commit, trusted apply-run evidence, AWS verification, and linked audit events; measure time to produce the evidence bundle. | Individual audit and execution records are queryable, but there is no evidence-completeness calculation and transactional audit coverage is not proven for every mutation. |
| Verified AWS deployment | Percentage of protected apply attempts with positive, same-commit apply evidence and a successful read-only comparison against the requested AWS state; track mismatch and unknown outcomes separately. | No AWS post-apply comparison result or `VERIFIED` state is currently recorded. The no-CI-checks-as-success behavior must be removed before interpreting `APPLIED` as proof. |

The platform's MR poll should be considered complete at merge. A separate
pipeline integration is needed to report `APPLY_PENDING`/`APPLY_SUCCEEDED`/
`APPLY_FAILED` (or equivalent), correlate the run to the approved ticket,
target environment and deployed commit, and transition the ticket only on its
trusted result. This does not require the platform to execute Terraform or
poll the MR after merge. The code host's branch protection and pipeline
configuration still need deployment-specific verification.

The metrics needed for an honest pilot baseline should be recorded as durable
business events or explicit timestamps, not inferred from periodic polling or
best-effort request logs. At minimum, preserve ticket submit time, final
decision time, PR creation time, trusted apply start/result, AWS verification
time/result, scan completion/freshness, and the correlation IDs linking those
events.

## Documentation status

The progress section of `phase1-design.md` predates implemented account
configuration, baselines, API-token/RBAC, Git-status polling, execution
records, and later migrations. Use this report as the P0-0 snapshot; update the
design documents as implementation or verification status changes.

## Scope confirmation and remaining limits

The user confirmed the sole enabled, inventory-linked account, all supported
ticket types, and an all-history measurement window. The account's
production/non-production classification remains unknown. The selected account
has only 11 days of available ticket history in this database, and that does
not establish that the database contains the project's complete history.

For a controlled rollout, confirm that the selected account is non-production
before enabling a pilot that exercises changes. Until identity, environment,
CI/apply evidence, and AWS-state verification are established, treat the
current numbers only as a descriptive snapshot of the database connected to
this local runtime, not as a production baseline.

## Priority adjustment after P0-0

The user decided that deployment-pipeline integration and separating MR merge
from apply status are lower priority and should be deferred. They are not the
next implementation slice. This does not change the intended boundary:
Terraform remains a deployment-pipeline responsibility, the platform does not
execute Terraform, and a platform `APPLIED` label must not be presented as
proof that AWS reached the requested state.

Recommended near-term order, without depending on pipeline integration:

1. **Establish a safe pilot scope:** confirm whether the selected account is
   non-production and verify the operating environment before using it for
   live changes.
2. **Make request-flow measurement reliable:** persist timestamps for actual
   ticket submission, final approval/rejection, and MR creation/merge; expose
   stage durations and abandoned/rejected counts. Use this data to identify
   which step causes delays before redesigning the workflow.
3. **Improve audit evidence reliability:** verify that each privileged
   business mutation has a durable audit event and make the evidence retrievable
   by ticket. Keep deployment/apply evidence explicitly marked unavailable
   until the later pipeline integration.
4. **Measure permission-governance outcomes:** track baseline validation
   blocks/exceptions and successful complete scan freshness, then review
   findings with the pilot account owners before tuning rules.

Later priority: integrate the trusted deployment pipeline result, correlate it
to the approved change, and separate MR completion from apply completion.
AWS read-only post-apply state comparison remains optional and is not a
prerequisite for this phase.

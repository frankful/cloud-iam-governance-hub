# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [0.1.0] — 2026-11-16

First tagged release. It consolidates the 0.1.x development snapshots that
were published to `main` between 2026-11-09 and 2026-11-13 without tags; the
per-snapshot detail lives in the git history.

### Added

- Ticket-driven governance for AWS IAM: create/update roles, managed policies,
  users, groups, inline policies, memberships and attachments, plus adoption of
  existing inline policies into Terraform.
- Read-only inventory collection (roles, policies, users, groups, attachments,
  trust relationships) with per-run stage metrics and AWS request counts.
- Baseline publication to GitHub or GitLab: the account's declared state is
  rendered into one Terraform file per resource under `<path>/account-<id>/`,
  pushed as a branch and a pull request; conflicts and unchanged files are
  classified before publishing. Baseline MR titles carry a
  `Baseline-Publications: <id>[,<id>…]` trailer so CI can post per-publication
  apply results to `POST /aws/baseline-publications/:id/apply-result`.
- CI apply callbacks (`apply-result`) and CI drift reports
  (`drift-reports`), including post-apply `plan -detailed-exitcode`
  zero-change verification.
- Drift detection with converge actions (accept the baseline or prefill an
  `UPDATE_*` ticket) and coverage reporting for accounts that were never
  checked. The cleanup report flags users that belong to no IAM group, and
  directs baseline-declared resources to the IaC declaration file (delete
  file → PR → CI apply) instead of direct `aws iam delete-*` calls.
- AWS credential onboarding guide (`docs/aws-credential-setup.md`): the
  two-layer identity model (entry identity vs. read-only collector role),
  credential chains for EC2 instance roles, EKS IRSA and Roles Anywhere, a
  recommended static-key setup for on-prem deployments, and a two-account
  cross-account trust walkthrough. Startup logs name where the entry AWS
  credentials came from (env, shared-config profile, instance metadata)
  without printing secrets.
- Reference GitLab pipeline (`docs/examples/gitlab-ci.example.yml`, with an
  English version `gitlab-ci.example.en.yml`): per-account `init/plan/apply`
  with S3 state, merge-commit-aware changed-directory computation, the
  `Baseline-Publications` callback, the import+destroy address-drift sentinel,
  callback diagnostics (status code + response body, `PLATFORM_URL` preflight
  and trailing-slash normalisation), and a boundary-anchored ticket-number
  regex.
- Minimal GitHub CI workflow (go build/test/vet, frontend tsc + build,
  gitleaks secret scan) with least-privilege `permissions`.
- Single container image for API and worker; the frontend is embedded into the
  API binary. `docker compose up -d --build` brings up Postgres, Redis, the API
  (auto-migrating) and the sync worker.

### Changed

- Baseline declarations stop emitting first-time-adoption `import` blocks for
  resources a previously *applied* baseline publication already owns — a
  leftover import block is dead weight in every future diff and a hazard when
  a resource label drifts. Adoption is judged from baseline declarations
  joined with their publication's `applied_at`.
- `.env.example` and the README spell out the first-start must-change list;
  `AUTH_MODE` defaults to `api-token` instead of the loopback-only
  `development` mode, and the collector-role documentation names the AWS
  managed `IAMReadOnlyAccess` policy.
- Build/runtime networking on restrictive hosts: the compose build runs with
  `network: host`, the api and sync-worker containers run with
  `network_mode: host` and inherit `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`,
  the host's `~/.aws` is mounted read-only, Go module downloads default to
  upstream `proxy.golang.org` (mainland-China users can pass
  `--build-arg GOPROXY=https://goproxy.cn,direct`), the alpine mirror and CA
  bundle are taken from the builder image (no runtime downloads), and Go
  compile parallelism is capped (`GOFLAGS=-p=2`) so small build VMs are not
  OOM-killed.

### Fixed

- Ticket lookups are case-insensitive on the ticket number at every service
  entry point. Numbers are generated as uppercase hex, but lookups matched the
  stored value exactly, so a CI callback carrying the lowercase form (a GitLab
  merge commit's first line names the branch) got a 404 and the ticket was
  never closed by the callback.
- The GitLab publisher decoded repository file content before comparing and
  patching (the files API always returns base64): the per-file "content
  unchanged, skip" short-circuit never matched, and HCL scanning failed with
  errors like `membership.tf:1,453-453: Missing expression`.
- The reference pipeline detects changes on merge commits: `git diff-tree` /
  `git show` return empty on them, web pipelines have a zero
  `CI_COMMIT_BEFORE_SHA`, and every `$()` pipeline is guarded against the
  `set -e` + `pipefail` silent-exit when a grep finds no match.
- The inline-policy change form prefills from the inline-policy endpoint
  (previously the managed-policy endpoint, which never contains inline
  policies, failed silently and opened an empty editor).
- The "AWS account connectivity validation failed" response no longer swallows
  the STS-level cause (AccessDenied vs. bad region vs. unreachable STS).
- The drift table scrolls horizontally on narrow windows instead of squeezing
  columns into one-character vertical text.

### Security

- Test fixtures, diagnostics tooling and comments no longer embed production
  resource naming or real ticket identifiers from the internal environment;
  the publish scanner rejects these patterns, and `scripts/publish-public.sh
  --check` gates manual incremental publishes behind the same scan + build
  check.

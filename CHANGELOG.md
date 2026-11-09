# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [0.1.2] — 2026-11-09

### Fixed

- The runtime stage now defaults the alpine package mirror to TUNA
  (`APK_MIRROR` build arg) instead of `dl-cdn.alpinelinux.org`, which is
  unreachable on many corporate networks and made
  `apk --no-cache add ca-certificates` fail with "unexpected eof" /
  "Permission denied". Pass `--build-arg APK_MIRROR=default` to restore the
  upstream CDN. Consistent with `GOPROXY` already defaulting to `goproxy.cn`.

## [0.1.1] — 2026-11-09

### Documentation

- `.env.example` and the README now name the AWS managed `IAMReadOnlyAccess`
  policy (ARN included) for the role the collector assumes, and state that
  organization mode additionally needs `organizations:ListAccounts` on the
  entry credential. Both previously said only "a read-only role".

## [0.1.0] — initial public release

First public snapshot of the platform.

### Added

- Ticket-driven governance for AWS IAM: create/update roles, managed policies,
  users, groups, inline policies, memberships and attachments, plus adoption of
  existing inline policies into Terraform.
- Read-only inventory collection (roles, policies, users, groups, attachments,
  trust relationships) with per-run stage metrics and AWS request counts.
- Baseline publication to GitHub or GitLab: the account's declared state is
  rendered into one Terraform file per resource under `<path>/account-<id>/`,
  pushed as a branch and a pull request; conflicts and unchanged files are
  classified before publishing.
- CI apply callbacks (`apply-result`) and CI drift reports
  (`drift-reports`), including post-apply `plan -detailed-exitcode`
  zero-change verification.
- Drift detection with converge actions (accept the baseline or prefill an
  `UPDATE_*` ticket) and coverage reporting for accounts that were never
  checked.
- Single container image for API and worker; the frontend is embedded into the
  API binary. `docker compose up -d --build` brings up Postgres, Redis, the API
  (auto-migrating) and the sync worker.

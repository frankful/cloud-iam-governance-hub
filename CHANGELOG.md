# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [Unreleased]

### Added

- Minimal CI workflow (go build/test, frontend tsc + build, gitleaks secret
  scan) so external PRs get a gate and fixture regressions cannot silently
  re-enter the tree.

### Fixed

- The inline-policy change form prefilled its editor from the managed-policy
  endpoint, which never contains inline policies; the fetch failed silently
  and the editor opened empty even though the inventory listed the policy. It
  now uses the inline-policy endpoint, so selecting an inline policy prefills
  its current document.
- The drift table squeezed the resource/summary columns into one-character
  vertical text on narrow windows; the table now scrolls horizontally instead
  (the only page missing a `scroll.x`, now aligned with the other pages).
- The GitLab publisher returned repository file content verbatim, but the
  GitLab files API always encodes it as base64; HCL scanning/patching parsed
  the encoded blob and failed with errors like
  `membership.tf:1,453-453: Missing expression`. Content is now decoded
  before use, matching the GitHub publisher.

### Changed

- Test fixtures no longer use real production resource naming
  (`agentic-commerce-prod-*`, `tdfos-prod-group`, `infra-eks1-nodegroup-role`,
  `Agentic-Commerce`, real ticket numbers); placeholders instead. The publish
  scanner now rejects these patterns.

## [0.1.11] — 2026-11-10

### Fixed

- The cleanup report no longer suggests direct `aws iam delete-user` /
  `delete-group` for resources declared in the baseline: those must be removed
  via the IaC declaration file (delete file → PR → CI apply), otherwise the
  next plan recreates them. Undeclared (platform-external) resources keep the
  direct CLI action.

## [0.1.10] — 2026-11-10

### Added

- The cleanup report now flags users that belong to no IAM group, mirroring
  the empty-group rule: a pure orphan (no group, no attached/inline
  policies) is listed as directly actionable (`aws iam delete-user`, with a
  reminder to check for active access keys first), while a groupless user
  that still carries policies is listed as review-required. zh-CN / en-US
  translations included.

## [0.1.9] — 2026-11-09

### Changed

- The api and sync-worker containers now run with `network_mode: host`.
  Verified on an affected host: a `--network host` container reaches STS
  while a bridge container (even with a lowered MTU) still gets TLS
  "unexpected eof" — the host's transparent proxy/TUN only captures
  host-local traffic, so bridge containers bypass it. With host networking
  the containers inherit the working host path; the api binds
  `0.0.0.0:${API_PORT}` directly and postgres/redis are reached on
  `127.0.0.1` (their published ports), so the `ports:` block is gone.

## [0.1.8] — 2026-11-09

### Fixed

- The "AWS account connectivity validation failed" response no longer
  swallows the STS-level cause: the handler logs the underlying error
  (AccessDenied vs. bad region vs. unreachable STS) at WARN.
- `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` are now passed through to the
  api and sync-worker containers. Runtime containers on the docker bridge
  bypass host transparent-proxy/TUN devices — AWS calls fail with TLS
  "unexpected eof" inside the container while the same request succeeds on
  the host. Set `HTTPS_PROXY` in `.env` to a proxy listening on a
  non-loopback address; `NO_PROXY` defaults to loopback + `postgres`/`redis`.

## [0.1.7] — 2026-11-09

### Fixed

- The host's `~/.aws` directory is now mounted read-only into the api and
  sync-worker containers (`/root/.aws`). The API previously exited at startup
  when the entry credential came from a shared-config profile (e.g.
  `AWS_PROFILE=iam-readonly`): the profile existed on the host but was never
  visible inside the container. Hosts without `~/.aws` are unaffected — env
  var credentials still work.

## [0.1.6] — 2026-11-09

### Fixed

- Go compile parallelism is capped (`GOFLAGS=-p=2`) so small build VMs
  (1-2 GB RAM, no swap) no longer get the toolchain OOM-killed — the build
  step previously died with `signal: killed`. Bigger build machines can
  restore full parallelism with `--build-arg GOFLAGS=-p=8`; adding swap is
  the more durable fix.

## [0.1.5] — 2026-11-09

### Fixed

- The compose build now runs with `network: host`. On hosts whose outbound
  traffic goes through a transparent proxy / TUN device, `curl` works on the
  host but every HTTPS fetch inside bridge-network build containers fails
  with `EOF`; building on the host network stack fixes it. For a plain
  `docker build`, pass `--network host`.

## [0.1.4] — 2026-11-09

### Changed

- Go module downloads default to the upstream `proxy.golang.org` instead of
  `goproxy.cn`, which EOFs on some networks. Mainland-China users can build
  with `--build-arg GOPROXY=https://goproxy.cn,direct` (documented in the
  Dockerfile comment and the README).

## [0.1.3] — 2026-11-09

### Fixed

- The runtime stage no longer downloads anything at build time: the CA bundle
  is copied out of the `golang:*-alpine` builder image (which already ships
  `ca-certificates-bundle`), replacing the `apk --no-cache add
  ca-certificates` step. The `APK_MIRROR` build arg is gone — on networks
  where both `dl-cdn.alpinelinux.org` and HTTPS alpine mirrors are blocked
  ("Permission denied" while fetching APKINDEX), the build now completes
  regardless.

### Added

- AWS credential onboarding guide (`docs/aws-credential-setup.md`): the
  two-layer identity model (entry identity vs. read-only collector role),
  credential chains for EC2 instance roles, EKS IRSA and Roles Anywhere, a
  recommended static-key setup for on-prem deployments, and a two-account
  cross-account trust walkthrough with copy-paste trust policies.
- Startup logs now name where the entry AWS credentials came from (env,
  shared-config profile, instance metadata), without printing secrets, and
  connectivity errors point at the new guide.

### Changed

- `.env.example` and the README spell out the full first-start must-change
  list (`POSTGRES_PASSWORD`, `AUTH_MODE`, optional AWS auto-registration and
  publisher settings); `AUTH_MODE` now defaults to `api-token` instead of
  the loopback-only `development` mode.

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

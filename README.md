# Cloud IAM Governance Hub

A GitOps-first governance platform for AWS IAM. Every IAM change — roles,
policies, users, groups, attachments, membership — becomes a reviewable,
auditable ticket. The approved ticket is rendered into a Terraform file and
published to your own protected CI/CD pipeline; that pipeline is the only thing
that ever touches AWS.

## Why

- **The platform is read-only against AWS.** It collects inventory through a
  read-only role and never issues access keys, console passwords, or login
  profiles. It never writes to AWS itself.
- **Tickets are the only path to change IAM.** There is no "change first, file
  a ticket later" order; drift detection exists precisely to catch that.
- **Everything is reviewable and auditable.** Approvals, decisions, generated
  Terraform, CI apply results, and inventory diffs all leave a record.
- **Drift has a safety net.** Inventory comparison, CI plan reports, and
  baseline publish conflicts all converge one way: accept as-is (re-publish
  the baseline) or roll back to the declaration (prefill an `UPDATE_*` ticket).

## How it works

```
register AWS account → sync (read-only) → publish baseline → open ticket
→ approve → CI apply → close ticket → sync again → drift detection → converge
```

The baseline publication defines the management boundary: an account is
"managed" only after its baseline PR is merged. Full state machines and
per-step endpoints: [docs/platform-workflow.md](docs/platform-workflow.md).

## Quick start (Docker Compose)

```bash
git clone https://github.com/frankful/cloud-iam-governance-hub.git
cd cloud-iam-governance-hub
cp .env.example .env
```

Edit `.env` — the settings that matter on a first start:

```ini
# REQUIRED: must change. The example file ships a placeholder; anything works,
# but do not keep it (it also appears in DATABASE_URL above it).
POSTGRES_PASSWORD=<generate one>
# REQUIRED: compose publishes the API on 0.0.0.0; development mode turns any
# X-User-ID header into platform_admin. (.env.example already defaults to this.)
AUTH_MODE=api-token
# Optional: auto-register this account on first start (can also be added in UI)
BOOTSTRAP_AWS_ACCOUNT_ID=123456789012
# Required before the first PR publish (after approval): the Terraform repo
# and a token scoped to contents:write + pull_requests:write on it only.
GITHUB_TOKEN=
GITHUB_REPOSITORY=owner/repository
```

Everything else can stay at its example defaults for a first start: AWS
credentials follow [docs/aws-credential-setup.md](docs/aws-credential-setup.md),
and the publisher settings can wait until you actually approve a ticket.

Bring the stack up (Postgres + Redis + API + sync-worker; the API auto-migrates
and embeds the frontend):

```bash
docker compose up -d --build
# API: http://127.0.0.1:${API_PORT:-8080}
```

The first build compiles the frontend and four Go binaries inside Docker — a
few minutes on a normal machine, considerably longer on a single core. If
5432 / 6379 / 8080 are already taken on the host, set `POSTGRES_PORT` /
`REDIS_PORT` / `API_PORT` in `.env` first (any change to `.env` needs
`docker compose up -d --force-recreate`, not just a restart).

Builds use the upstream Go module proxy (`proxy.golang.org`) by default; the
runtime image needs no package downloads at build time — its CA bundle is
copied from the builder image. Mainland-China networks where the upstream
proxy is slow or unreachable should build with
`--build-arg GOPROXY=https://goproxy.cn,direct`. Behind a corporate HTTP
proxy, pass `--build-arg HTTPS_PROXY=http://proxy:port` for the Go/frontend
fetches.

If `curl` works on the host but every HTTPS fetch inside the build fails
with `EOF` (hosts whose outbound traffic runs through a transparent proxy /
TUN device that docker bridge containers bypass), the compose build already
uses `network: host`; for a plain `docker build`, add `--network host`. The
same applies at **runtime**: containers calling AWS/GitHub get the same
reset. Set `HTTPS_PROXY` in `.env` to a proxy listening on a non-loopback
address (e.g. `http://172.17.0.1:7890`, the docker0 gateway to a host-side
proxy); `NO_PROXY` defaults to keeping loopback and the internal
`postgres`/`redis` services direct.

On a small build VM (1-2 GB RAM, no swap), the Go build step can be
OOM-killed and fail with `signal: killed`. The build caps compiler
parallelism (`GOFLAGS=-p=2`) to survive that; adding swap is the more
durable fix, and bigger build machines can restore full parallelism with
`--build-arg GOFLAGS=-p=8`.

First start with no active admin bootstraps one `admin` login token into
`data/bootstrap-admin-token.txt` (mode 0600). Paste it into the login page,
then **revoke it in the UI and delete the file** after you have your own token.

With `BOOTSTRAP_AWS_ACCOUNT_ID` set, the account registers itself on startup
(STS connectivity is verified; failure only warns, it does not block). The
role the collector assumes needs only the AWS managed `IAMReadOnlyAccess`
policy (`arn:aws:iam::aws:policy/IAMReadOnlyAccess`) — the inventory path
calls `iam:Get*` / `iam:List*` and nothing else. Trigger the first sync from
the **Sync** page, then publish the baseline to start managing the account.
Environment variables are documented in [.env.example](.env.example); the
first-boot walkthrough is
[docs/first-use-admin-login.md](docs/first-use-admin-login.md). Where the
platform gets its AWS credential — instance role, IRSA, profile, or
`credential_process` — and how to add accounts without long-lived keys is
[docs/aws-credential-setup.md](docs/aws-credential-setup.md).

## Local development (no Docker)

Prerequisites: Go 1.26+, Node.js 20+, PostgreSQL 14+, Redis 6+.

```bash
cp .env.example .env                      # fill DATABASE_URL / REDIS_ADDR / AWS settings
cd frontend && npm install && npm run build && cd ..
go run ./cmd/migrate
go run ./cmd/api                          # sync-worker: go run ./cmd/sync-worker
```

## Onboarding users

There is no self-service signup. In the **Users and tokens** screen a
`platform_admin` creates users, assigns roles (`standard_user` / `approval_admin`
/ `platform_admin`), and issues login tokens — the secret is shown exactly
once. The same operations exist on the CLI:

```bash
go run ./cmd/platform-user <user-id> [display-name] [role]
go run ./cmd/platform-token -user-id <user-id> [-name <label>] [-expires-in 720h]
```

## Ticket types

`CREATE_ROLE` · `CREATE_MANAGED_POLICY` · `CREATE_USER` · `CREATE_GROUP` ·
`ATTACH_USER_POLICY` (attach / detach) · `UPDATE_ROLE` ·
`UPDATE_MANAGED_POLICY` · `UPDATE_GROUP_INLINE_POLICY` ·
`UPDATE_GROUP_MEMBERSHIP` · `ADOPT_ROLE_INLINE_POLICIES` (bring existing
inline policies under Terraform)

Each ticket renders to one Terraform file under the account directory of your
baseline repository; resource addresses are stable, so updates patch the file
in place instead of destroy/recreate.

## CI integration

The platform publishes branches and pull requests to GitHub or GitLab; your
pipeline does the plan/apply. Two optional callbacks close the loop:

- `POST /api/v1/tickets/:no/apply-result` — `succeeded` closes the ticket and
  triggers a sync; `failed` records the failure with the CI run URL (the ticket
  detail page shows a red banner).
- Drift reports (`POST /aws/drift-reports`) — a CI plan-only step or a
  post-apply `plan -detailed-exitcode` zero-change check reports back; the
  reporting contract is described in `docs/phase4-drift-design.md`.

Without callbacks, merged tickets are closed by merge-detection fallback and
apply failures are visible only in CI logs.

**Trust boundary.** Both callbacks authenticate with a platform bearer token —
they are token-authenticated, not signed. Run the CI runner with its own
least-privilege token (never a `platform_admin` token), and keep the API on
loopback or behind a reverse proxy. The same applies to the AWS side: the
runner gets short-lived credentials via GitHub OIDC and holds no long-lived
AWS keys; the platform's own identity is read-only.

## Known limitations

- No password login, OIDC/SSO, or self-service signup; provisioning is an
  administrator's job.
- Drift detection is not scheduled by the platform — it compares inventory and
  accepts CI reports; the recurring plan step lives in your CI.
- Terraform Cloud / Atlantis are not integrated.
- No built-in rate limiting; put the API behind a reverse proxy if reachable
  from untrusted networks.
- The compose file pins container names (`finops-api`, `finops-postgres`, …),
  so one host runs one stack of it. Two stacks need a manual name override.

## Documentation

- [docs/platform-workflow.md](docs/platform-workflow.md) — end-to-end workflow and state machines
- [docs/first-use-admin-login.md](docs/first-use-admin-login.md) — first-boot admin bootstrap
- [docs/aws-credential-setup.md](docs/aws-credential-setup.md) — entry vs collector credentials, EC2/EKS vs anywhere, account onboarding, troubleshooting
- [docs/phase1-design.md](docs/phase1-design.md) — domain model and ticket state machine
- [docs/phase3-account-baseline-design.md](docs/phase3-account-baseline-design.md) — baseline publication and CI apply
- [docs/phase4-drift-design.md](docs/phase4-drift-design.md) — drift detection and convergence
- [SECURITY.md](SECURITY.md) — security and audit model

## License

Apache-2.0. See [LICENSE](LICENSE).

# Contributing

Thanks for taking the time to contribute. This document covers the invariants
that are easy to break and the checks a change is expected to pass.

## Invariants

These are not style preferences; a change that breaks one of them is a bug.

1. **The platform never writes to AWS.** Collection uses `List*`/`Get*` calls
   through an assumed read-only role. Every AWS mutation goes through generated
   Terraform, reviewed in a pull request, applied by the operator's pipeline.
2. **The platform never stores AWS credentials.** The only credential it holds
   is the entry credential (instance role / profile) plus short-lived STS
   sessions. Do not add configuration that persists target-account keys.
3. **Generated Terraform addresses are stable.** An update patches the existing
   file in place. Changing a resource address turns an in-place update into a
   destroy/recreate of the same AWS object.
4. **Nothing is skipped silently.** A resource that cannot be declared must
   produce an explicit reason in the candidate/bundle report and be flagged in
   the inventory. (`UNMANAGED.md` in the Terraform repository is not implemented
   and not scheduled.)
5. **Ownership is expressed by resource keys** (`role-<name>`, `user-<name>`,
   `group-<name>`, `policy-<name>`,
   `attachment-<type>-<principal>-<policy>`). Two generators must never declare
   the same key.

## Where code belongs

`internal/service/ticket_service.go` is the ticket state machine and it is
already large. Do not grow it further:

- Terraform rendering belongs in `internal/adapter` (`baseline_generators.go`,
  `aws_adapter.go`);
- pure validation and normalization belong next to the code that owns the rule;
- new inventory reads belong in `internal/service/iam_inventory_service.go`;
- new HTTP surface belongs in `internal/handler/http/v1`.

If a change needs a new branch in the ticket state machine, add it there — but
push everything that is not state transition out of the file.

## Build and test

```bash
# backend
go build ./...
go test ./internal/... ./migrations/... ./pkg/...

# frontend
cd frontend
npm ci
npm run build
npm run lint
```

`go test ./...` additionally builds the CLI binaries; `go test` on the three
package trees above is the fast loop used during development.

## Changing Terraform generation

Any change to a generator must come with a regression test that asserts the
rendered HCL, not just the function's return value. Two real incidents motivate
this rule:

- a generator that emitted `tags = tags = {...}` produced invalid HCL, and the
  file was silently dropped from the bundle;
- omitting a ForceNew attribute (`path`, `description`, `permissions_boundary`)
  made the first apply destroy and recreate the resource.

When you add a resource kind, update the baseline candidate kernel, the
generator, and the bundle tests together.

## Adding a ticket type

1. Add the constant and the request shape in `internal/service`.
2. Validate the request (structured `apperr.ValidationError`, not string
   prefixes).
3. Generate the Terraform in `internal/adapter` with a test.
4. Wire the handler and the frontend form.
5. Update `README.md` (ticket types) and `CHANGELOG.md`.

## Database changes

Migrations are append-only and embedded:

- add `NNNN_name.up.sql` and `NNNN_name.down.sql`;
- update the expected list in `migrations/migrations_test.go` and the latest
  version in `migrations/status_test.go`;
- the down migration must actually restore the previous state.

## Commits and pull requests

- Keep commits focused; explain the *why* in the body when it is not obvious.
- Do not commit build output, logs, `.env` files, or test fixtures that contain
  real account IDs or ARNs.
- CI must pass `go build`, `go test`, and the frontend build.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

# Multi-instance authorization boundary

`internal/authz/boundary` is the single, instance-scoped authorization parsing
and token-convergence core. It is storage-agnostic and ships with a
concurrency-safe in-memory implementation (`MemoryStore`,
`MemorySnapshotCache`, `MemoryAuditLog`) so all acceptance scenarios run
without Postgres, CockroachDB, Redis or external OIDC services.

> Integration note: this package is additive and does not change the existing
> OIDC/JWT verification path. The current OIDC user-info and introspection
> adapters already converge on the `Server.userInfo(...)` role assembly in
> `internal/api/oidc/userinfo.go` and `internal/api/oidc/introspect.go`. A
> production rollout should implement this package's `Repository` against the
> query/projection store, then replace that internal assembly with one call to
> `Resolver.Resolve`; protected APIs and permission inventory call the same
> `Boundary.Authorize` / `Boundary.ListMyPermissions` entry points. Existing
> instance-domain resolution and instance-key verification remain in front of
> this package, and `Boundary.Handler(...)` is an optional reference HTTP
> adapter rather than a replacement mount.

## Boundary rules

1. The request instance is taken only from the context populated by the
   existing domain-to-instance resolution. An empty instance returns
   `instance_missing` before any repository or cache access. There is no
   default-instance fallback.
2. Cache keys are `(instanceID, HMAC subject pseudonym)`. Audit records carry
   the same instance dimension and instance-namespaced subject pseudonym.
3. Protected API, user info, OIDC introspection and permission inventory all
   call `Resolver.Resolve`. None of them assembles roles/permissions from
   separate tables.
4. Every resolved set is bound to a monotonic per-`(instance, subject)`
   authorization version.

## Source priority

When the same role is supplied by multiple sources, roles are unioned and the
primary source is selected deterministically by priority:

| Source | Kind | Priority | Scope behavior |
|---|---|---:|---|
| System role | `system_role` | 500 | system resources only; never relaxed to instance/org/project |
| Instance role | `instance_role` | 400 | instance permissions may inherit downward |
| Organization membership | `organization_membership` | 300 | matching organization and projects in that organization |
| Project authorization | `project_authorization` | 200 | matching project; includes project-grant provenance |
| Project membership | `project_membership` | 100 | matching project |

Equal priorities are sorted by kind and stable source ID, so map iteration
order cannot change the result.

## Token staleness and cross-instance errors

`Claims` add two optional claims:

- `instance_id`: owning instance;
- `authz_version`: authorization version used when the token was issued.

The built-in reference token is `zab1.<payload>.<HMAC-SHA256>` and uses a
distinct key per instance. Verification first checks the signature with the
owning instance key, then classifies:

| Situation | Stable code |
|---|---|
| Missing context instance | `instance_missing` |
| Malformed token | `token_malformed` |
| Bad signature | `token_signature_invalid` |
| Expired token | `token_expired` |
| Valid signature, other `instance_id` | `token_instance_mismatch` |
| Version too old + invalidate policy | `stale_authorization` |
| Missing version + deny-legacy policy | `legacy_token_without_authz_version_denied` |
| Version/cache/storage cannot establish freshness | `authorization_freshness_unavailable` |
| Missing source record | `authorization_source_missing` |
| Contradictory source/event | `authorization_source_conflict` |
| Older event would roll version back | `authorization_version_rollback` |

Thus cross-instance rejection is distinguishable from expiry and signature
failure.

## Convergence configuration

`Config` fields are optional. Zero values receive these defaults:

- `ConvergenceWindow = 5 * time.Minute` — documented upper bound. Version
  checks plus immediate cache invalidation make normal convergence immediate.
- `Strategy = recompute` (`DefaultConvergenceStrategy`). A stale versioned
  token remains subject to signature/expiry/instance validation, but the
  current resolver result replaces its embedded authorization set.
- `LegacyTokenPolicy = allow` (`DefaultLegacyTokenPolicy`). Historical tokens
  without `authz_version` remain compatible, while permissions are still
  resolved from the current source of truth. Set this to `deny` for strict
  freshness enforcement.
- `TokenTTL = 1h` for the reference issuer only; PAT, session and machine token
  expiry/revocation semantics elsewhere are untouched.

The alternative strategy is `invalidate`: a token whose claim version is lower
than the current version is rejected with `stale_authorization`.

## Cache and performance

Each request performs one cheap `CurrentVersion` read. A full
`LoadAuthorization` and merge happen only on a cache miss or version mismatch:

```text
CurrentVersion(instance, subject)
  -> cache hit && cache.version == current.version: reuse Snapshot
  -> otherwise: LoadAuthorization -> deterministic merge -> cache Set
```

Writes bump the monotonic version and call `Invalidate`. The next request sees
the new version immediately; there is no long TTL dirty-read window. A version
read error or cache availability error fails closed with
`authorization_freshness_unavailable`; underlying storage/cache error text is
not returned to callers.

## Events

`RoleSetEvent` has a deterministic version guard:

- newer version: apply;
- same event ID redelivered: no mutation, `Duplicate=true`;
- older non-duplicate version: `authorization_version_rollback`;
- same event ID with a different version: `authorization_source_conflict`.

## Audit

`MemoryAuditLog.Query` filters by instance, pseudonymous subject, project,
kind, operation, reason and allow/deny result. Record kinds are:

- `decision`: allow/deny for each outward path;
- `convergence`: recomputation or invalidation of a stale/legacy token;
- `authorization_change`: role, grant, membership or organization/project
  state mutation and before/after role sets.

Records include instance, subject pseudonym, project/organization, before/after
roles, current roles/permissions, sources and token/current versions. They
never include raw tokens, signing secrets, storage DSNs or raw subject IDs.
Raw subject IDs are converted with HMAC-SHA256 namespaced by instance.

## Failure semantics

- Missing instance: deny before storage/cache.
- Version or cache unavailable: deny with the sanitized
  `authorization_freshness_unavailable` classification.
- Missing/contradictory authorization source: deny with distinct source errors;
  an empty role set is never treated as successful authorization.
- Deactivated organization/project: dependent roles are excluded and the
  protected decision is denied.
- Freshness failure is audited once per path attempt and returns the same
  sanitized classification from user info, introspection and permission
  inventory.

## Tests

```sh
gofmt -w internal/authz/boundary/*.go
go test -race -count=1 ./internal/authz/boundary
go test -v -count=1 ./internal/authz/boundary
```

The acceptance tests cover cross-instance lists/single reads/decisions/tokens,
four-path equality, source priority, both convergence strategies, default
legacy behavior, cache counts, immediate version invalidation, out-of-order
and duplicate events, missing instance, storage/cache failure, source
integrity failures, org/project deactivation, membership removal, system-role
scope non-relaxation, distinguishable token errors and audit privacy.

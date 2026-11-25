package boundary

import (
	"time"
)

// ConvergenceStrategy defines how a token whose authz_version is older than
// the current authorization version is handled.
type ConvergenceStrategy string

const (
	// StrategyInvalidate rejects stale versioned access tokens. Clients must
	// obtain a new token. This is the strictest strategy.
	StrategyInvalidate ConvergenceStrategy = "invalidate"

	// StrategyRecompute keeps the token valid if signature, expiry and
	// instance checks pass, but replaces its embedded authorization set with
	// the freshly resolved current set for the current request.
	StrategyRecompute ConvergenceStrategy = "recompute"

	// DefaultConvergenceStrategy is recompute. It immediately drops deleted
	// roles/permissions without forcing every client to reacquire a token,
	// preserving availability while converging on the next request.
	DefaultConvergenceStrategy = StrategyRecompute
)

// LegacyTokenPolicy defines behavior for tokens without an authorization
// version.
type LegacyTokenPolicy string

const (
	// LegacyAllow accepts otherwise valid historical tokens. Their
	// permissions are still resolved from the current source of truth, so
	// revoked roles do not remain effective.
	LegacyAllow LegacyTokenPolicy = "allow"

	// LegacyDeny rejects otherwise valid historical tokens because they do
	// not carry enough information to prove authorization freshness.
	LegacyDeny LegacyTokenPolicy = "deny"

	// DefaultLegacyTokenPolicy is allow to preserve compatibility with
	// already issued tokens. Signature, expiry, revocation and instance-key
	// validation continue unchanged.
	DefaultLegacyTokenPolicy = LegacyAllow
)

const (
	// DefaultConvergenceWindow is the documented upper bound within which a
	// changed authorization must converge. Because the resolver checks the
	// monotonic version before every use and invalidates its cache on change,
	// convergence is normally immediate and therefore below this window.
	DefaultConvergenceWindow = 5 * time.Minute

	// DefaultTokenTTL applies only to tokens issued by this package's
	// in-memory/test token issuer. It does not change PAT, session or machine
	// token expiry semantics elsewhere in ZITADEL.
	DefaultTokenTTL = time.Hour

	// InitialAuthorizationVersion is assigned before the first recorded
	// authorization change.
	InitialAuthorizationVersion uint64 = 1
)

// Config contains optional boundary settings. The zero value is not usable;
// call NewBoundary or normalize with withDefaults.
type Config struct {
	// ConvergenceWindow is the maximum expected delay between an authorization
	// change and enforcement of the new set. Must be positive.
	ConvergenceWindow time.Duration

	// Strategy selects stale-token invalidation or live recomputation.
	Strategy ConvergenceStrategy

	// LegacyTokenPolicy selects compatibility behavior for tokens that do not
	// carry authz_version.
	LegacyTokenPolicy LegacyTokenPolicy

	// TokenTTL is used by the built-in issuer.
	TokenTTL time.Duration

	// PseudonymSecret optionally keys irreversible audit identifiers.
	PseudonymSecret []byte

	// InstanceKeys optionally supplies distinct signing keys per instance for
	// the built-in issuer/verifier.
	InstanceKeys map[string][]byte

	// SigningSecret optionally derives distinct per-instance signing keys when
	// InstanceKeys does not contain an instance.
	SigningSecret []byte

	// RolePermissions is the deterministic role-to-permission catalog. When
	// nil, DefaultRolePermissions is used.
	RolePermissions map[string][]string

	// SourcePriorities overrides source merge priorities. Higher value wins
	// when selecting PrimarySource for a role.
	SourcePriorities map[SourceKind]int

	// Now is an injectable clock.
	Now func() time.Time
}

// Normalize applies documented defaults and validates configuration.
func (c Config) Normalize() (Config, error) {
	return c.withDefaults()
}

func (c Config) withDefaults() (Config, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.ConvergenceWindow == 0 {
		c.ConvergenceWindow = DefaultConvergenceWindow
	}
	if c.ConvergenceWindow < 0 {
		return c, NewError(CodeInvalidRequest, "convergence window must not be negative")
	}
	if c.Strategy == "" {
		c.Strategy = DefaultConvergenceStrategy
	}
	switch c.Strategy {
	case StrategyInvalidate, StrategyRecompute:
	default:
		return c, Errorf(CodeInvalidRequest, "unknown convergence strategy %q", c.Strategy)
	}
	if c.LegacyTokenPolicy == "" {
		c.LegacyTokenPolicy = DefaultLegacyTokenPolicy
	}
	switch c.LegacyTokenPolicy {
	case LegacyAllow, LegacyDeny:
	default:
		return c, Errorf(CodeInvalidRequest, "unknown legacy token policy %q", c.LegacyTokenPolicy)
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = DefaultTokenTTL
	}
	if c.TokenTTL < 0 {
		return c, NewError(CodeInvalidRequest, "token TTL must not be negative")
	}
	if c.RolePermissions == nil {
		c.RolePermissions = DefaultRolePermissions()
	}
	if c.SourcePriorities == nil {
		c.SourcePriorities = DefaultSourcePriorities()
	}
	return c, nil
}

// DefaultRolePermissions returns a small stable catalog used by tests and the
// in-memory implementation. Production deployments can inject the ZITADEL
// role/permission mapping without changing resolution logic.
func DefaultRolePermissions() map[string][]string {
	return map[string][]string{
		"system.owner":   {"system.*"},
		"instance.owner": {"instance.*", "organization.*", "project.*"},
		"instance.admin": {"instance.read", "organization.*", "project.*"},
		"org.owner":      {"organization.*", "project.read", "project.list"},
		"org.member":     {"organization.read", "project.read", "project.list"},
		"project.owner":  {"project.*"},
		"project.editor": {"project.read", "project.write"},
		"project.viewer": {"project.read"},
		"shared.role":    {"shared.read"},
	}
}

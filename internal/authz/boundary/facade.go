package boundary

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Boundary is the single application entry through which protected calls,
// user info, introspection and permission inventory obtain authorization.
type Boundary struct {
	cfg        Config
	store      *MemoryStore
	repo       Repository
	resolver   *Resolver
	tokens     *TokenService
	auditSink  AuditSink
	auditLog   *MemoryAuditLog
	auditCount atomic.Uint64
}

// NewBoundary creates a Boundary backed by a new MemoryStore and
// MemoryAuditLog.
func NewBoundary(cfg Config) (*Boundary, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	store := NewMemoryStore(cfg.Now)
	auditLog := NewMemoryAuditLog()
	return NewBoundaryWithDependencies(cfg, store, nil, auditLog)
}

// NewBoundaryWithRepository creates a Boundary with a custom Repository. It is
// primarily useful for degradation/fault tests.
func NewBoundaryWithRepository(cfg Config, repo Repository, sink AuditSink) (*Boundary, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, NewError(CodeInvalidRequest, "repository is required")
	}
	if sink == nil {
		log := NewMemoryAuditLog()
		sink = log
	}
	b := &Boundary{cfg: cfg, repo: repo, auditSink: sink, tokens: NewTokenService(cfg)}
	if log, ok := sink.(*MemoryAuditLog); ok {
		b.auditLog = log
	}
	b.resolver, err = NewResolver(cfg, repo, nil)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// NewBoundaryWithDependencies wires explicit in-memory adapters.
func NewBoundaryWithDependencies(cfg Config, store *MemoryStore, cache SnapshotCache, sink AuditSink) (*Boundary, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if store == nil {
		store = NewMemoryStore(cfg.Now)
	}
	if sink == nil {
		sink = NewMemoryAuditLog()
	}
	resolver, err := NewResolver(cfg, store, cache)
	if err != nil {
		return nil, err
	}
	b := &Boundary{
		cfg:       cfg,
		store:     store,
		repo:      store,
		resolver:  resolver,
		tokens:    NewTokenService(cfg),
		auditSink: sink,
	}
	if log, ok := sink.(*MemoryAuditLog); ok {
		b.auditLog = log
	}
	return b, nil
}

// Store returns the in-memory store used by the default Boundary.
func (b *Boundary) Store() *MemoryStore { return b.store }

// AuditLog returns the queryable memory audit log when that sink is in use.
func (b *Boundary) AuditLog() *MemoryAuditLog { return b.auditLog }

// Resolver exposes the shared resolver for cache-specific tests/adapters.
func (b *Boundary) Resolver() *Resolver { return b.resolver }

// Tokens exposes the built-in token issuer/verifier.
func (b *Boundary) Tokens() *TokenService { return b.tokens }

func (b *Boundary) newAuditID() string {
	n := b.auditCount.Add(1)
	return fmt.Sprintf("audit-%d-%06d", b.cfg.Now().UnixNano(), n)
}

func (b *Boundary) writeAudit(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return nil
	}
	if event.ID == "" {
		event.ID = b.newAuditID()
	}
	if event.Time.IsZero() {
		event.Time = b.cfg.Now()
	}
	if event.BeforeRoles == nil {
		event.BeforeRoles = []string{}
	}
	if event.AfterRoles == nil {
		event.AfterRoles = []string{}
	}
	if event.Roles == nil {
		event.Roles = []string{}
	}
	if err := b.auditSink.Audit(ctx, *event); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func codeOf(err error) Code {
	var boundaryErr *Error
	if errors.As(err, &boundaryErr) {
		return boundaryErr.Code
	}
	return CodeAuthorizationUnavailable
}

type callResult struct {
	claims         *Claims
	snapshot       *Snapshot
	view           AuthorityView
	resource       Resource
	tokenPseudonym string
	beforeRoles    []string
	convergence    string
	fromVersion    uint64
	toVersion      uint64
	window         time.Duration
	elapsed        time.Duration
	withinWindow   bool
}

//nolint:gocognit // Linear security state machine; splitting it would obscure required audit and error ordering.
func (b *Boundary) authenticate(ctx context.Context, rawToken, operation string, resource Resource) (*callResult, error) {
	resource = resource.normalized()
	instanceID, instanceErr := requireInstance(ctx)
	tokenPseudo := tokenPseudonym(b.cfg.PseudonymSecret, rawToken)
	if instanceErr != nil {
		event := AuditEvent{
			Kind:           AuditKindDecision,
			Operation:      operation,
			ProjectID:      resource.ProjectID,
			OrganizationID: resource.OrganizationID,
			Action:         "",
			Allowed:        boolPtr(false),
			ReasonCode:     CodeInstanceMissing,
			TokenPseudonym: tokenPseudo,
		}
		if auditErr := b.writeAudit(context.WithoutCancel(ctx), &event); auditErr != nil {
			return nil, auditErr
		}
		return nil, instanceErr
	}

	claims, err := b.tokens.Verify(ctx, instanceID, rawToken)
	if err != nil {
		code := codeOf(err)
		event := AuditEvent{
			Kind:           AuditKindDecision,
			Operation:      operation,
			InstanceID:     instanceID,
			ProjectID:      resource.ProjectID,
			OrganizationID: resource.OrganizationID,
			Allowed:        boolPtr(false),
			ReasonCode:     code,
			TokenPseudonym: tokenPseudo,
		}
		if claims != nil {
			event.SubjectPseudonym = SubjectPseudonym(b.cfg.PseudonymSecret, instanceID, claims.Subject)
		}
		if auditErr := b.writeAudit(ctx, &event); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	subjectPseudo := SubjectPseudonym(b.cfg.PseudonymSecret, instanceID, claims.Subject)
	snapshot, err := b.resolver.Resolve(ctx, claims.Subject)
	if err != nil {
		code := codeOf(err)
		event := AuditEvent{
			Kind:                      AuditKindDecision,
			Operation:                 operation,
			InstanceID:                instanceID,
			SubjectPseudonym:          subjectPseudo,
			TokenPseudonym:            tokenPseudo,
			ProjectID:                 resource.ProjectID,
			OrganizationID:            resource.OrganizationID,
			Allowed:                   boolPtr(false),
			ReasonCode:                code,
			BeforeRoles:               append([]string(nil), claims.Roles...),
			TokenAuthorizationVersion: claims.AuthzVersion,
			AuthorizationVersion:      0,
		}
		if auditErr := b.writeAudit(ctx, &event); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}

	now := b.cfg.Now()
	elapsed := now.Sub(snapshot.ChangedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	result := &callResult{
		claims:         claims,
		snapshot:       snapshot,
		view:           ViewFromSnapshot(snapshot),
		resource:       resource,
		tokenPseudonym: tokenPseudo,
		beforeRoles:    append([]string(nil), claims.Roles...),
		fromVersion:    claims.AuthzVersion,
		toVersion:      snapshot.Version,
		window:         b.cfg.ConvergenceWindow,
		elapsed:        elapsed,
		withinWindow:   elapsed <= b.cfg.ConvergenceWindow,
	}

	switch {
	case claims.AuthzVersion == 0:
		if b.cfg.LegacyTokenPolicy == LegacyDeny {
			convEvent := b.convergenceEvent(result, "legacy_denied")
			convEvent.ReasonCode = CodeLegacyTokenDenied
			if err := b.writeAudit(ctx, &convEvent); err != nil {
				return nil, err
			}
			decision := b.decisionEvent(result, operation, "", resource, false, CodeLegacyTokenDenied)
			if err := b.writeAudit(ctx, &decision); err != nil {
				return nil, err
			}
			return nil, ErrLegacyTokenDenied
		}
		result.convergence = "legacy_live_recompute"
		convEvent := b.convergenceEvent(result, result.convergence)
		if err := b.writeAudit(ctx, &convEvent); err != nil {
			return nil, err
		}
	case claims.AuthzVersion < snapshot.Version:
		if b.cfg.Strategy == StrategyInvalidate {
			result.convergence = "invalidated_stale_token"
			convEvent := b.convergenceEvent(result, result.convergence)
			convEvent.ReasonCode = CodeStaleAuthorization
			if err := b.writeAudit(ctx, &convEvent); err != nil {
				return nil, err
			}
			decision := b.decisionEvent(result, operation, "", resource, false, CodeStaleAuthorization)
			if err := b.writeAudit(ctx, &decision); err != nil {
				return nil, err
			}
			return nil, ErrStaleAuthorization
		}
		result.convergence = "recomputed_latest_authorization"
		convEvent := b.convergenceEvent(result, result.convergence)
		if err := b.writeAudit(ctx, &convEvent); err != nil {
			return nil, err
		}
	case claims.AuthzVersion > snapshot.Version:
		decision := b.decisionEvent(result, operation, "", resource, false, CodeVersionRollback)
		if err := b.writeAudit(ctx, &decision); err != nil {
			return nil, err
		}
		return nil, ErrVersionRollback
	default:
		result.convergence = "current"
	}

	return result, nil
}

func (b *Boundary) convergenceEvent(cr *callResult, action string) AuditEvent {
	resource := cr.resource
	return AuditEvent{
		Kind:                      AuditKindConvergence,
		InstanceID:                cr.view.InstanceID,
		SubjectPseudonym:          cr.view.SubjectPseudonym,
		TokenPseudonym:            cr.tokenPseudonym,
		Operation:                 "convergence",
		ProjectID:                 resource.ProjectID,
		OrganizationID:            resource.OrganizationID,
		ReasonCode:                "",
		BeforeRoles:               append([]string(nil), cr.beforeRoles...),
		AfterRoles:                append([]string(nil), cr.view.Roles...),
		Roles:                     append([]string(nil), cr.view.Roles...),
		Permissions:               append([]string(nil), cr.view.Permissions...),
		Sources:                   mergeAuditSources(cr.claims.Sources, sortedSources(cr.snapshot)),
		FromVersion:               cr.fromVersion,
		ToVersion:                 cr.toVersion,
		TokenAuthorizationVersion: cr.fromVersion,
		AuthorizationVersion:      cr.toVersion,
		Strategy:                  b.cfg.Strategy,
		ConvergenceAction:         action,
		ConvergenceWindow:         cr.window,
		ConvergenceElapsed:        cr.elapsed,
		WithinWindow:              cr.withinWindow,
	}
}

func (b *Boundary) decisionEvent(cr *callResult, operation, action string, resource Resource, allowed bool, reason Code) AuditEvent {
	event := AuditEvent{
		Kind:                      AuditKindDecision,
		Operation:                 operation,
		Action:                    action,
		InstanceID:                cr.view.InstanceID,
		SubjectPseudonym:          cr.view.SubjectPseudonym,
		TokenPseudonym:            cr.tokenPseudonym,
		ProjectID:                 resource.ProjectID,
		OrganizationID:            resource.OrganizationID,
		Allowed:                   boolPtr(allowed),
		ReasonCode:                reason,
		BeforeRoles:               append([]string(nil), cr.beforeRoles...),
		AfterRoles:                append([]string(nil), cr.view.Roles...),
		Roles:                     append([]string(nil), cr.view.Roles...),
		Permissions:               append([]string(nil), cr.view.Permissions...),
		Sources:                   mergeAuditSources(cr.claims.Sources, sortedSources(cr.snapshot)),
		FromVersion:               cr.fromVersion,
		ToVersion:                 cr.toVersion,
		AuthorizationVersion:      cr.view.Version,
		TokenAuthorizationVersion: cr.fromVersion,
		Strategy:                  b.cfg.Strategy,
		ConvergenceAction:         cr.convergence,
		ConvergenceWindow:         cr.window,
		ConvergenceElapsed:        cr.elapsed,
		WithinWindow:              cr.withinWindow,
	}
	if resource.Scope == ScopeProject && event.ProjectID == "" {
		event.ProjectID = resource.ProjectID
	}
	return event
}

// Decision is the result for a protected interface call.
type Decision struct {
	Allowed           bool          `json:"allowed"`
	ReasonCode        Code          `json:"reasonCode,omitempty"`
	Operation         string        `json:"operation"`
	Action            string        `json:"action,omitempty"`
	Authority         AuthorityView `json:"authority"`
	AuditID           string        `json:"auditId"`
	ConvergenceAction string        `json:"convergenceAction,omitempty"`
}

// Authorize is the protected-interface policy enforcement point.
func (b *Boundary) Authorize(ctx context.Context, rawToken string, request AccessRequest) (*Decision, error) {
	resource := request.Resource.normalized()
	cr, err := b.authenticate(ctx, rawToken, "protected_api", resource)
	if err != nil {
		return nil, err
	}
	allowed := cr.snapshot.Allows(request.Action, resource)
	reason := Code("")
	if !allowed {
		reason = CodePermissionDenied
	}
	event := b.decisionEvent(cr, "protected_api", request.Action, resource, allowed, reason)
	if err := b.writeAudit(ctx, &event); err != nil {
		return nil, err
	}
	decision := &Decision{
		Allowed:           allowed,
		ReasonCode:        reason,
		Operation:         "protected_api",
		Action:            request.Action,
		Authority:         cr.view,
		AuditID:           event.ID,
		ConvergenceAction: cr.convergence,
	}
	if !allowed {
		return decision, ErrPermissionDenied
	}
	return decision, nil
}

// UserInfoResponse is the canonical user-info view.
type UserInfoResponse struct {
	Sub       string        `json:"sub"`
	Authority AuthorityView `json:"authority"`
	AuditID   string        `json:"auditId"`
}

// UserInfo serves the OIDC user-info path through the shared resolver.
func (b *Boundary) UserInfo(ctx context.Context, rawToken string) (*UserInfoResponse, error) {
	resource := Resource{Scope: ScopeInstance}
	cr, err := b.authenticate(ctx, rawToken, "userinfo", resource)
	if err != nil {
		return nil, err
	}
	event := b.decisionEvent(cr, "userinfo", "userinfo.read", resource, true, "")
	if err := b.writeAudit(ctx, &event); err != nil {
		return nil, err
	}
	return &UserInfoResponse{Sub: cr.view.SubjectPseudonym, Authority: cr.view, AuditID: event.ID}, nil
}

// IntrospectionResponse is a detailed introspection result.
//
// ReasonCode is intended for internal observability/tests. A public OAuth2
// introspection adapter should preserve the standard wire behavior of
// returning {"active":false} for inactive tokens rather than exposing all
// detailed reasons to unauthenticated callers.
type IntrospectionResponse struct {
	Active     bool           `json:"active"`
	ReasonCode Code           `json:"reasonCode,omitempty"`
	CallerID   string         `json:"callerId,omitempty"`
	Authority  *AuthorityView `json:"authority,omitempty"`
	AuditID    string         `json:"auditId,omitempty"`
}

// Introspect serves the OIDC introspection path through the shared resolver.
func (b *Boundary) Introspect(ctx context.Context, targetToken, callerID string) (*IntrospectionResponse, error) {
	resource := Resource{Scope: ScopeInstance}
	cr, err := b.authenticate(ctx, targetToken, "introspection", resource)
	if err != nil {
		if isInactiveTokenError(err) {
			return &IntrospectionResponse{Active: false, ReasonCode: codeOf(err), CallerID: callerID}, nil
		}
		return nil, err
	}
	event := b.decisionEvent(cr, "introspection", "introspection.read", resource, true, "")
	event.CallerID = callerID
	if err := b.writeAudit(ctx, &event); err != nil {
		return nil, err
	}
	view := cr.view
	return &IntrospectionResponse{Active: true, CallerID: callerID, Authority: &view, AuditID: event.ID}, nil
}

var inactiveTokenErrorCodes = map[Code]struct{}{
	CodeTokenMalformed:        {},
	CodeSignatureInvalid:      {},
	CodeTokenExpired:          {},
	CodeTokenInstanceMismatch: {},
	CodeLegacyTokenDenied:     {},
	CodeStaleAuthorization:    {},
}

func isInactiveTokenError(err error) bool {
	_, ok := inactiveTokenErrorCodes[codeOf(err)]
	return ok
}

// PermissionInventory is the permission-list path.
type PermissionInventory struct {
	Authority AuthorityView     `json:"authority"`
	Grants    []PermissionGrant `json:"grants"`
	AuditID   string            `json:"auditId"`
}

// ListMyPermissions serves the permission inventory path through the shared
// resolver.
func (b *Boundary) ListMyPermissions(ctx context.Context, rawToken string) (*PermissionInventory, error) {
	resource := Resource{Scope: ScopeInstance}
	cr, err := b.authenticate(ctx, rawToken, "permission_inventory", resource)
	if err != nil {
		return nil, err
	}
	event := b.decisionEvent(cr, "permission_inventory", "permissions.list", resource, true, "")
	if err := b.writeAudit(ctx, &event); err != nil {
		return nil, err
	}
	return &PermissionInventory{Authority: cr.view, Grants: append([]PermissionGrant(nil), cr.snapshot.PermissionGrants...), AuditID: event.ID}, nil
}

// IssueToken resolves current authorization and issues a versioned token.
func (b *Boundary) IssueToken(ctx context.Context, subjectID string) (string, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return "", err
	}
	snapshot, err := b.resolver.Resolve(ctx, subjectID)
	if err != nil {
		return "", err
	}
	return b.tokens.Issue(Claims{
		Subject:      subjectID,
		InstanceID:   instanceID,
		AuthzVersion: snapshot.Version,
		Roles:        append([]string(nil), snapshot.Roles...),
		Permissions:  append([]string(nil), snapshot.Permissions...),
		Sources:      sortedSources(snapshot),
	})
}

// IssueLegacyToken issues an otherwise valid token without authz_version.
func (b *Boundary) IssueLegacyToken(ctx context.Context, subjectID string) (string, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return "", err
	}
	snapshot, err := b.resolver.Resolve(ctx, subjectID)
	if err != nil {
		return "", err
	}
	return b.tokens.Issue(Claims{
		Subject:     subjectID,
		InstanceID:  instanceID,
		Roles:       append([]string(nil), snapshot.Roles...),
		Permissions: append([]string(nil), snapshot.Permissions...),
		Sources:     sortedSources(snapshot),
	})
}

// IssueClaims issues arbitrary signed claims. It is intended for tests of
// expiry and malformed/future-version behavior.
func (b *Boundary) IssueClaims(claims Claims) (string, error) {
	return b.tokens.Issue(claims)
}

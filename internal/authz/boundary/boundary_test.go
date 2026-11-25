package boundary_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/zitadel/internal/authz/boundary"
)

const (
	instanceA = "inst-a"
	instanceB = "inst-b"
	subject1  = "user-1"
	orgA      = "org-a"
	orgB      = "org-b"
	projectA  = "proj-a"
	projectB  = "proj-b"
	authA     = "auth-a"
	authB     = "auth-b"
)

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time          { return c.now }
func (c *manualClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type fixture struct {
	t      *testing.T
	b      *boundary.Boundary
	store  *boundary.MemoryStore
	clock  *manualClock
	secret []byte
	ctxA   context.Context
	ctxB   context.Context
}

func newFixture(t *testing.T, mutate func(*boundary.Config)) *fixture {
	t.Helper()
	clock := &manualClock{now: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	secret := []byte("test-pseudonym-secret-material")
	cfg := boundary.Config{
		ConvergenceWindow: time.Minute,
		Strategy:          boundary.StrategyRecompute,
		LegacyTokenPolicy: boundary.LegacyAllow,
		PseudonymSecret:   secret,
		InstanceKeys: map[string][]byte{
			instanceA: []byte("signing-key-a-material"),
			instanceB: []byte("signing-key-b-material"),
		},
		Now: clock.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	b, err := boundary.NewBoundary(cfg)
	if err != nil {
		t.Fatalf("NewBoundary: %v", err)
	}
	f := &fixture{
		t:      t,
		b:      b,
		store:  b.Store(),
		clock:  clock,
		secret: secret,
		ctxA:   boundary.WithInstance(context.Background(), instanceA),
		ctxB:   boundary.WithInstance(context.Background(), instanceB),
	}
	f.seedTwoInstances()
	return f
}

func (f *fixture) seedTwoInstances() {
	f.t.Helper()
	must(f.t, f.store.PutOrganization(boundary.OrganizationRecord{InstanceID: instanceA, ID: orgA, Active: true}))
	must(f.t, f.store.PutOrganization(boundary.OrganizationRecord{InstanceID: instanceB, ID: orgB, Active: true}))
	must(f.t, f.store.PutProject(boundary.ProjectRecord{InstanceID: instanceA, ID: projectA, OrganizationID: orgA, Active: true}))
	must(f.t, f.store.PutProject(boundary.ProjectRecord{InstanceID: instanceB, ID: projectB, OrganizationID: orgB, Active: true}))
	must(f.t, f.store.PutAuthorization(boundary.AuthorizationRecord{
		ID: authA, InstanceID: instanceA, SubjectID: subject1,
		ProjectID: projectA, OrgID: orgA, Roles: []string{"project.viewer"}, Active: true,
	}))
	must(f.t, f.store.PutAuthorization(boundary.AuthorizationRecord{
		ID: authB, InstanceID: instanceB, SubjectID: subject1,
		ProjectID: projectB, OrgID: orgB, Roles: []string{"project.owner"}, Active: true,
	}))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustErrIs(t *testing.T, err error, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %v, got nil", target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("error %v does not match %v", err, target)
	}
}

func readProjectRequest() boundary.AccessRequest {
	return boundary.AccessRequest{
		Action:   "project.read",
		Resource: boundary.Resource{ProjectID: projectA, OrganizationID: orgA},
	}
}

func pseudoA(f *fixture) string {
	return boundary.SubjectPseudonym(f.secret, instanceA, subject1)
}

func TestInstanceIsolation_ListsSingleReadsDecisionsAndTokens(t *testing.T) {
	f := newFixture(t, nil)

	tokenA, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)

	// Resolution in A contains only A's viewer role.
	snapA, err := f.b.Resolver().Resolve(f.ctxA, subject1)
	must(t, err)
	if !reflect.DeepEqual(snapA.Roles, []string{"project.viewer"}) {
		t.Fatalf("instance A roles = %v, want only project.viewer", snapA.Roles)
	}

	// Same subject in B has an independent owner role.
	snapB, err := f.b.Resolver().Resolve(f.ctxB, subject1)
	must(t, err)
	if !reflect.DeepEqual(snapB.Roles, []string{"project.owner"}) {
		t.Fatalf("instance B roles = %v, want only project.owner", snapB.Roles)
	}
	if snapA.SubjectPseudonym == snapB.SubjectPseudonym {
		t.Fatal("subject pseudonym must be namespaced by instance")
	}

	// List is instance-scoped.
	listA, err := f.b.ListAuthorizationRecords(f.ctxA, boundary.AuthorizationListFilter{SubjectID: subject1})
	must(t, err)
	if len(listA) != 1 || listA[0].ID != authA {
		t.Fatalf("list A = %+v, want only %s", listA, authA)
	}
	listB, err := f.b.ListAuthorizationRecords(f.ctxB, boundary.AuthorizationListFilter{SubjectID: subject1})
	must(t, err)
	if len(listB) != 1 || listB[0].ID != authB {
		t.Fatalf("list B = %+v, want only %s", listB, authB)
	}

	// Single read cannot cross the boundary.
	if _, err := f.b.GetAuthorizationRecord(f.ctxB, authA); !errors.Is(err, boundary.ErrNotFound) {
		t.Fatalf("cross-instance get error = %v, want ErrNotFound", err)
	}
	gotA, err := f.b.GetAuthorizationRecord(f.ctxA, authA)
	must(t, err)
	if gotA.ID != authA {
		t.Fatalf("get A id = %q", gotA.ID)
	}

	// A token is rejected when presented through B and has the precise code.
	_, err = f.b.Authorize(f.ctxB, tokenA, boundary.AccessRequest{
		Action:   "project.read",
		Resource: boundary.Resource{ProjectID: projectB, OrganizationID: orgB},
	})
	mustErrIs(t, err, boundary.ErrTokenInstanceMismatch)

	intro, err := f.b.Introspect(f.ctxB, tokenA, "client-b")
	must(t, err)
	if intro.Active || intro.ReasonCode != boundary.CodeTokenInstanceMismatch {
		t.Fatalf("cross-instance introspection = %+v, want inactive/%s", intro, boundary.CodeTokenInstanceMismatch)
	}
}

func TestFourPathsShareSingleAuthority(t *testing.T) {
	f := newFixture(t, nil)
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)

	decision, err := f.b.Authorize(f.ctxA, token, readProjectRequest())
	must(t, err)
	if !decision.Allowed {
		t.Fatalf("decision unexpectedly denied: %+v", decision)
	}
	userInfo, err := f.b.UserInfo(f.ctxA, token)
	must(t, err)
	introspection, err := f.b.Introspect(f.ctxA, token, "client-1")
	must(t, err)
	if !introspection.Active || introspection.Authority == nil {
		t.Fatalf("introspection is not active: %+v", introspection)
	}
	inventory, err := f.b.ListMyPermissions(f.ctxA, token)
	must(t, err)

	views := map[string]boundary.AuthorityView{
		"protected":     decision.Authority,
		"userinfo":      userInfo.Authority,
		"introspection": *introspection.Authority,
		"inventory":     inventory.Authority,
	}
	var expected boundary.AuthorityView
	for name, view := range views {
		if expected.InstanceID == "" {
			expected = view
			continue
		}
		if !reflect.DeepEqual(expected, view) {
			t.Fatalf("%s authority mismatch:\nexpected=%+v\nactual=%+v", name, expected, view)
		}
	}
	if !reflect.DeepEqual(expected.Roles, []string{"project.viewer"}) {
		t.Fatalf("roles = %v", expected.Roles)
	}
	if !reflect.DeepEqual(expected.Permissions, []string{"project.read"}) {
		t.Fatalf("permissions = %v", expected.Permissions)
	}

	// The signed current token carries exactly the same role set.
	claims, err := f.b.Tokens().Verify(f.ctxA, instanceA, token)
	must(t, err)
	if !reflect.DeepEqual(claims.Roles, expected.Roles) || claims.AuthzVersion != expected.Version {
		t.Fatalf("token claims version=%d roles=%v, want version=%d roles=%v", claims.AuthzVersion, claims.Roles, expected.Version, expected.Roles)
	}
}

func TestSourceTraceAndDeterministicPriority(t *testing.T) {
	f := newFixture(t, nil)
	ctx := boundary.WithInstance(context.Background(), "inst-trace")
	must(t, f.store.PutOrganization(boundary.OrganizationRecord{InstanceID: "inst-trace", ID: "org-trace", Active: true}))
	must(t, f.store.PutProject(boundary.ProjectRecord{InstanceID: "inst-trace", ID: "proj-trace", OrganizationID: "org-trace", Active: true}))
	must(t, f.store.SetInstanceRoles("inst-trace", "user-trace", "instance.admin"))
	must(t, f.store.PutMembership(boundary.MembershipRecord{
		ID: "mem-org", InstanceID: "inst-trace", SubjectID: "user-trace",
		Scope: boundary.ScopeOrganization, OrgID: "org-trace", Roles: []string{"org.member"}, Active: true,
	}))
	must(t, f.store.PutMembership(boundary.MembershipRecord{
		ID: "mem-project", InstanceID: "inst-trace", SubjectID: "user-trace",
		Scope: boundary.ScopeProject, OrgID: "org-trace", ProjectID: "proj-trace",
		Roles: []string{"project.viewer"}, Active: true,
	}))
	must(t, f.store.PutAuthorization(boundary.AuthorizationRecord{
		ID: "auth-priority", InstanceID: "inst-trace", SubjectID: "user-trace",
		ProjectID: "proj-trace", OrgID: "org-trace", Roles: []string{"project.viewer"}, Active: true,
	}))

	snap, err := f.b.Resolver().Resolve(ctx, "user-trace")
	must(t, err)
	primary := make(map[string]boundary.SourceKind)
	sourceCount := make(map[string]int)
	for _, role := range snap.EffectiveRoles {
		primary[role.Role] = role.PrimarySource.Kind
		sourceCount[role.Role] = len(role.Sources)
	}
	if primary["instance.admin"] != boundary.SourceInstanceRole {
		t.Fatalf("instance.admin primary = %s", primary["instance.admin"])
	}
	if primary["org.member"] != boundary.SourceOrganizationMembership {
		t.Fatalf("org.member primary = %s", primary["org.member"])
	}
	if primary["project.viewer"] != boundary.SourceProjectAuthorization {
		t.Fatalf("project.viewer primary = %s, want explicit project authorization", primary["project.viewer"])
	}
	if sourceCount["project.viewer"] != 2 {
		t.Fatalf("project.viewer sources = %d, want membership + authorization", sourceCount["project.viewer"])
	}

	// Repeated resolution must preserve ordering exactly.
	snap2, err := f.b.Resolver().Resolve(ctx, "user-trace")
	must(t, err)
	if !reflect.DeepEqual(snap.EffectiveRoles, snap2.EffectiveRoles) {
		t.Fatal("source merge order is not deterministic")
	}
}

//nolint:gocognit // Table-driven acceptance coverage intentionally keeps both policy flows and audit assertions together.
func TestConvergenceStrategiesAndAuditDiff(t *testing.T) {
	for _, strategy := range []boundary.ConvergenceStrategy{boundary.StrategyInvalidate, boundary.StrategyRecompute} {
		t.Run(string(strategy), func(t *testing.T) {
			f := newFixture(t, func(cfg *boundary.Config) { cfg.Strategy = strategy })
			token, err := f.b.IssueToken(f.ctxA, subject1)
			must(t, err)

			_, err = f.b.RemoveAuthorizationRoles(f.ctxA, authA, "project.viewer")
			must(t, err)
			f.clock.Advance(30 * time.Second)

			_, err = f.b.Authorize(f.ctxA, token, readProjectRequest())
			if strategy == boundary.StrategyInvalidate {
				mustErrIs(t, err, boundary.ErrStaleAuthorization)
			} else {
				mustErrIs(t, err, boundary.ErrPermissionDenied)
			}

			pseudo := pseudoA(f)
			changes := f.b.AuditLog().Query(boundary.AuditFilter{
				Kind: boundary.AuditKindChange, InstanceID: instanceA, SubjectPseudonym: pseudo,
			})
			if len(changes) == 0 {
				t.Fatal("missing authorization change audit")
			}
			lastChange := changes[len(changes)-1]
			if !reflect.DeepEqual(lastChange.BeforeRoles, []string{"project.viewer"}) ||
				len(lastChange.AfterRoles) != 0 {
				t.Fatalf("change diff = before %v after %v", lastChange.BeforeRoles, lastChange.AfterRoles)
			}

			convergences := f.b.AuditLog().Query(boundary.AuditFilter{
				Kind: boundary.AuditKindConvergence, InstanceID: instanceA, SubjectPseudonym: pseudo,
			})
			if len(convergences) != 1 {
				t.Fatalf("convergence events = %d, want 1: %+v", len(convergences), convergences)
			}
			conv := convergences[0]
			if !reflect.DeepEqual(conv.BeforeRoles, []string{"project.viewer"}) || len(conv.AfterRoles) != 0 {
				t.Fatalf("convergence diff = before %v after %v", conv.BeforeRoles, conv.AfterRoles)
			}
			if conv.FromVersion == 0 || conv.ToVersion <= conv.FromVersion {
				t.Fatalf("bad versions from=%d to=%d", conv.FromVersion, conv.ToVersion)
			}
			if !conv.WithinWindow || conv.ConvergenceElapsed != 30*time.Second || conv.ConvergenceWindow != time.Minute {
				t.Fatalf("window fields = within=%v elapsed=%s window=%s", conv.WithinWindow, conv.ConvergenceElapsed, conv.ConvergenceWindow)
			}
			if conv.ProjectID != projectA {
				t.Fatalf("convergence project = %q, want %q", conv.ProjectID, projectA)
			}
			if len(conv.Sources) == 0 || conv.Sources[0].ID == "" {
				t.Fatalf("convergence sources missing: %+v", conv.Sources)
			}

			denied := f.b.AuditLog().Query(boundary.AuditFilter{
				Kind: boundary.AuditKindDecision, InstanceID: instanceA,
				SubjectPseudonym: pseudo, Allowed: boolFalse(),
			})
			if len(denied) == 0 {
				t.Fatal("missing denied decision audit")
			}
		})
	}
}

func boolFalse() *bool { v := false; return &v }

func TestRecomputePicksUpNewestRoles(t *testing.T) {
	f := newFixture(t, nil) // default recompute
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)
	_, err = f.b.RemoveAuthorizationRoles(f.ctxA, authA, "project.viewer")
	must(t, err)
	_, err = f.b.AddAuthorizationRoles(f.ctxA, authA, "project.editor")
	must(t, err)

	decision, err := f.b.Authorize(f.ctxA, token, boundary.AccessRequest{
		Action:   "project.write",
		Resource: boundary.Resource{ProjectID: projectA, OrganizationID: orgA},
	})
	must(t, err)
	if !decision.Allowed {
		t.Fatalf("recomputed decision denied: %+v", decision)
	}
	if !reflect.DeepEqual(decision.Authority.Roles, []string{"project.editor"}) {
		t.Fatalf("recomputed roles = %v", decision.Authority.Roles)
	}
}

func TestLegacyTokenDefaultAndDenyPolicy(t *testing.T) {
	cfg, err := (boundary.Config{}).Normalize()
	must(t, err)
	if boundary.DefaultConvergenceStrategy != boundary.StrategyRecompute || cfg.Strategy != boundary.StrategyRecompute {
		t.Fatalf("default strategy = %q, want %q", cfg.Strategy, boundary.StrategyRecompute)
	}
	if boundary.DefaultLegacyTokenPolicy != boundary.LegacyAllow || cfg.LegacyTokenPolicy != boundary.LegacyAllow {
		t.Fatalf("default legacy policy = %q, want %q", cfg.LegacyTokenPolicy, boundary.LegacyAllow)
	}
	if cfg.ConvergenceWindow != boundary.DefaultConvergenceWindow {
		t.Fatalf("default window = %s, want %s", cfg.ConvergenceWindow, boundary.DefaultConvergenceWindow)
	}

	f := newFixture(t, nil)
	legacy, err := f.b.IssueLegacyToken(f.ctxA, subject1)
	must(t, err)
	ui, err := f.b.UserInfo(f.ctxA, legacy)
	must(t, err)
	if ui.Authority.Version == 0 {
		t.Fatal("legacy token must still resolve current authority")
	}
	conv := f.b.AuditLog().Query(boundary.AuditFilter{Kind: boundary.AuditKindConvergence})
	if len(conv) != 1 || conv[0].ConvergenceAction != "legacy_live_recompute" {
		t.Fatalf("legacy convergence = %+v", conv)
	}

	deny := newFixture(t, func(cfg *boundary.Config) { cfg.LegacyTokenPolicy = boundary.LegacyDeny })
	legacyDeny, err := deny.b.IssueLegacyToken(deny.ctxA, subject1)
	must(t, err)
	_, err = deny.b.UserInfo(deny.ctxA, legacyDeny)
	mustErrIs(t, err, boundary.ErrLegacyTokenDenied)
	intro, err := deny.b.Introspect(deny.ctxA, legacyDeny, "")
	must(t, err)
	if intro.Active || intro.ReasonCode != boundary.CodeLegacyTokenDenied {
		t.Fatalf("legacy introspection = %+v", intro)
	}
}

func TestCacheReuseAndImmediateVersionInvalidation(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)

	loadsAfterIssue := f.store.LoadCount(instanceA, subject1)
	if loadsAfterIssue != 1 {
		t.Fatalf("loads after issue = %d, want 1", loadsAfterIssue)
	}
	for i := 0; i < 10; i++ {
		_, err := f.b.Resolver().Resolve(f.ctxA, subject1)
		must(t, err)
	}
	if got := f.store.LoadCount(instanceA, subject1); got != loadsAfterIssue {
		t.Fatalf("full loads after repeated same-version resolves = %d, want %d", got, loadsAfterIssue)
	}

	_, err = f.b.RemoveAuthorizationRoles(f.ctxA, authA, "project.viewer")
	must(t, err)
	snap, err := f.b.Resolver().Resolve(f.ctxA, subject1)
	must(t, err)
	if len(snap.Roles) != 0 {
		t.Fatalf("first resolve after version change returned roles %v", snap.Roles)
	}
	if got := f.store.LoadCount(instanceA, subject1); got != loadsAfterIssue+1 {
		t.Fatalf("loads after version change = %d, want %d", got, loadsAfterIssue+1)
	}
	for i := 0; i < 10; i++ {
		_, err := f.b.Resolver().Resolve(f.ctxA, subject1)
		must(t, err)
	}
	if got := f.store.LoadCount(instanceA, subject1); got != loadsAfterIssue+1 {
		t.Fatalf("loads grew after version stabilized: %d", got)
	}
}

func TestConcurrentSameSubjectRequestsRemainIsolatedAndRaceFree(t *testing.T) {
	f := newFixture(t, nil)
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ui, err := f.b.UserInfo(f.ctxA, token)
			if err != nil {
				errs <- err
				return
			}
			if !reflect.DeepEqual(ui.Authority.Roles, []string{"project.viewer"}) {
				errs <- errors.New("concurrent userinfo returned mixed authority")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	if got := f.store.LoadCount(instanceA, subject1); got != 1 {
		t.Fatalf("full loads under concurrency = %d, want one shared resolution", got)
	}
}

func TestVersionEventsOutOfOrderAndDuplicate(t *testing.T) {
	f := newFixture(t, nil)
	eventV3 := boundary.RoleSetEvent{
		EventID: "evt-3", InstanceID: instanceA, SubjectID: subject1,
		AuthorizationID: authA, ProjectID: projectA, OrgID: orgA,
		Version: 3, Roles: []string{"project.editor"},
	}
	res, err := f.b.ApplyRoleSetEvent(f.ctxA, eventV3)
	must(t, err)
	if res.Duplicate || res.Version != 3 {
		t.Fatalf("v3 result = %+v", res)
	}

	old := eventV3
	old.EventID = "evt-2"
	old.Version = 2
	old.Roles = []string{"project.viewer"}
	_, err = f.b.ApplyRoleSetEvent(f.ctxA, old)
	mustErrIs(t, err, boundary.ErrVersionRollback)

	duplicate, err := f.b.ApplyRoleSetEvent(f.ctxA, eventV3)
	must(t, err)
	if !duplicate.Duplicate || !reflect.DeepEqual(duplicate.After, []string{"project.editor"}) {
		t.Fatalf("duplicate result = %+v", duplicate)
	}
	record, err := f.b.GetAuthorizationRecord(f.ctxA, authA)
	must(t, err)
	if !reflect.DeepEqual(record.Roles, []string{"project.editor"}) || record.Version != 3 {
		t.Fatalf("record after out-of-order/duplicate = %+v", record)
	}
	snap, err := f.b.Resolver().Resolve(f.ctxA, subject1)
	must(t, err)
	if !reflect.DeepEqual(snap.Roles, []string{"project.editor"}) || snap.Version != 3 {
		t.Fatalf("snapshot = version %d roles %v", snap.Version, snap.Roles)
	}
}

func TestMissingInstanceAlwaysDenies(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.b.Resolver().Resolve(context.Background(), subject1)
	mustErrIs(t, err, boundary.ErrInstanceMissing)
	_, err = f.b.Authorize(context.Background(), "any-token", readProjectRequest())
	mustErrIs(t, err, boundary.ErrInstanceMissing)
	if got := f.store.LoadCount(instanceA, subject1); got != 0 {
		t.Fatalf("store was queried without instance: loads=%d", got)
	}
}

func TestVersionAndCacheFailuresFailClosedSanitized(t *testing.T) {
	f := newFixture(t, nil)
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)
	f.store.SetFaults(errors.New("postgres unavailable DSN password=storage-secret"), nil)

	_, err = f.b.UserInfo(f.ctxA, token)
	mustErrIs(t, err, boundary.ErrFreshnessUnavailable)
	if strings.Contains(err.Error(), "storage-secret") {
		t.Fatalf("sanitized error leaked storage detail: %v", err)
	}

	clock := &manualClock{now: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	store := boundary.NewMemoryStore(clock.Now)
	cache := boundary.NewMemorySnapshotCache()
	cfg := boundary.Config{Now: clock.Now, PseudonymSecret: []byte("p"), SigningSecret: []byte("s")}
	b, err := boundary.NewBoundaryWithDependencies(cfg, store, cache, boundary.NewMemoryAuditLog())
	must(t, err)
	ctx := boundary.WithInstance(context.Background(), instanceA)
	must(t, store.PutOrganization(boundary.OrganizationRecord{InstanceID: instanceA, ID: orgA, Active: true}))
	must(t, store.PutProject(boundary.ProjectRecord{InstanceID: instanceA, ID: projectA, OrganizationID: orgA, Active: true}))
	must(t, store.PutAuthorization(boundary.AuthorizationRecord{ID: authA, InstanceID: instanceA, SubjectID: subject1, ProjectID: projectA, OrgID: orgA, Roles: []string{"project.viewer"}, Active: true}))
	token2, err := b.IssueToken(ctx, subject1)
	must(t, err)
	cache.SetFaults(errors.New("cache cluster down cache-secret"), nil)
	_, err = b.UserInfo(ctx, token2)
	mustErrIs(t, err, boundary.ErrFreshnessUnavailable)
	if strings.Contains(err.Error(), "cache-secret") {
		t.Fatalf("cache error leaked: %v", err)
	}
}

func TestMissingAndContradictorySourcesDeny(t *testing.T) {
	f := newFixture(t, nil)
	must(t, f.store.PutAuthorization(boundary.AuthorizationRecord{
		ID: "broken-auth", InstanceID: instanceA, SubjectID: "user-broken",
		ProjectID: "missing-project", Active: true, Roles: []string{"project.viewer"},
	}))
	brokenToken, err := f.b.IssueClaims(boundary.Claims{Subject: "user-broken", InstanceID: instanceA})
	must(t, err)
	_, err = f.b.UserInfo(f.ctxA, brokenToken)
	mustErrIs(t, err, boundary.ErrSourceMissing)

	f.store.SetContradiction(instanceA, "user-conflict", true)
	conflictToken, err := f.b.IssueClaims(boundary.Claims{Subject: "user-conflict", InstanceID: instanceA})
	must(t, err)
	_, err = f.b.UserInfo(f.ctxA, conflictToken)
	mustErrIs(t, err, boundary.ErrSourceConflict)
}

func TestDeactivateOrganizationAndProjectConverge(t *testing.T) {
	for _, resource := range []string{"organization", "project"} {
		t.Run(resource, func(t *testing.T) {
			f := newFixture(t, nil)
			token, err := f.b.IssueToken(f.ctxA, subject1)
			must(t, err)
			if resource == "organization" {
				must(t, f.b.SetOrganizationActive(f.ctxA, orgA, false))
			} else {
				must(t, f.b.SetProjectActive(f.ctxA, projectA, false))
			}
			_, err = f.b.Authorize(f.ctxA, token, readProjectRequest())
			mustErrIs(t, err, boundary.ErrPermissionDenied)
			conv := f.b.AuditLog().Query(boundary.AuditFilter{Kind: boundary.AuditKindConvergence})
			if len(conv) != 1 || len(conv[0].AfterRoles) != 0 {
				t.Fatalf("convergence after deactivation = %+v", conv)
			}
		})
	}
}

func TestRemoveMembershipConverges(t *testing.T) {
	f := newFixture(t, nil)
	must(t, f.store.PutMembership(boundary.MembershipRecord{
		ID: "mem-remove", InstanceID: instanceA, SubjectID: "user-member",
		Scope: boundary.ScopeOrganization, OrgID: orgA, Roles: []string{"org.member"}, Active: true,
	}))
	ctx := boundary.WithInstance(context.Background(), instanceA)
	token, err := f.b.IssueToken(ctx, "user-member")
	must(t, err)
	before, err := f.b.UserInfo(ctx, token)
	must(t, err)
	if !reflect.DeepEqual(before.Authority.Roles, []string{"org.member"}) {
		t.Fatalf("before roles = %v", before.Authority.Roles)
	}
	_, err = f.b.RemoveMembership(ctx, "mem-remove")
	must(t, err)
	after, err := f.b.UserInfo(ctx, token)
	must(t, err)
	if len(after.Authority.Roles) != 0 {
		t.Fatalf("after membership removal roles = %v", after.Authority.Roles)
	}
}

func TestCreateAndDeleteProjectAuthorizationConverges(t *testing.T) {
	f := newFixture(t, nil)
	const newSubject = "user-grant"
	token, err := f.b.IssueToken(f.ctxA, newSubject)
	must(t, err)

	created, err := f.b.CreateAuthorization(f.ctxA, boundary.AuthorizationRecord{
		ID: "auth-new", SubjectID: newSubject,
		ProjectID: projectA, OrgID: orgA, Roles: []string{"project.viewer"}, Active: true,
	})
	must(t, err)
	if created.Version <= 1 {
		t.Fatalf("created authorization version = %d", created.Version)
	}
	decision, err := f.b.Authorize(f.ctxA, token, readProjectRequest())
	must(t, err)
	if !decision.Allowed || decision.ConvergenceAction != "recomputed_latest_authorization" {
		t.Fatalf("create convergence decision = %+v err=%v", decision, err)
	}

	if _, err := f.b.DeleteAuthorization(f.ctxA, "auth-new"); err != nil {
		t.Fatal(err)
	}
	_, err = f.b.Authorize(f.ctxA, token, readProjectRequest())
	mustErrIs(t, err, boundary.ErrPermissionDenied)

	records, err := f.b.ListAuthorizationRecords(f.ctxA, boundary.AuthorizationListFilter{SubjectID: newSubject})
	must(t, err)
	if len(records) != 0 {
		t.Fatalf("records after delete = %+v", records)
	}
	convergences := f.b.AuditLog().Query(boundary.AuditFilter{Kind: boundary.AuditKindConvergence})
	if len(convergences) != 2 {
		t.Fatalf("convergence events = %d, want create + delete enforcement", len(convergences))
	}
}

func TestProjectGrantRevocationConverges(t *testing.T) {
	f := newFixture(t, nil)
	const (
		inst  = "inst-grant"
		subj  = "user-granted"
		org   = "org-grant"
		proj  = "proj-grant"
		grant = "grant-1"
		auth  = "auth-granted"
	)
	ctx := boundary.WithInstance(context.Background(), inst)
	must(t, f.store.PutOrganization(boundary.OrganizationRecord{InstanceID: inst, ID: org, Active: true}))
	must(t, f.store.PutProject(boundary.ProjectRecord{InstanceID: inst, ID: proj, OrganizationID: org, Active: true}))
	must(t, f.store.PutProjectGrant(boundary.ProjectGrantRecord{
		InstanceID: inst, ID: grant, ProjectID: proj, GrantedOrganizationID: org, Active: true,
	}))
	must(t, f.store.PutAuthorization(boundary.AuthorizationRecord{
		ID: auth, InstanceID: inst, SubjectID: subj, ProjectID: proj, OrgID: org,
		GrantID: grant, Roles: []string{"project.viewer"}, Active: true,
	}))
	token, err := f.b.IssueToken(ctx, subj)
	must(t, err)
	req := boundary.AccessRequest{Action: "project.read", Resource: boundary.Resource{ProjectID: proj, OrganizationID: org}}
	decision, err := f.b.Authorize(ctx, token, req)
	must(t, err)
	if !decision.Allowed {
		t.Fatal("granted project authorization should initially allow access")
	}

	must(t, f.b.SetProjectGrantActive(ctx, grant, false))
	_, err = f.b.Authorize(ctx, token, req)
	mustErrIs(t, err, boundary.ErrPermissionDenied)
	conv := f.b.AuditLog().Query(boundary.AuditFilter{Kind: boundary.AuditKindConvergence, InstanceID: inst})
	if len(conv) != 1 || conv[0].ProjectID != proj || len(conv[0].AfterRoles) != 0 {
		t.Fatalf("project grant revocation convergence = %+v", conv)
	}

	must(t, f.b.SetProjectGrantActive(ctx, grant, true))
	decision, err = f.b.Authorize(ctx, token, req)
	must(t, err)
	if !decision.Allowed {
		t.Fatal("reactivated grant should restore recomputed access")
	}
}

func TestConvergenceFailureIsObservableAndConsistentAcrossPaths(t *testing.T) {
	f := newFixture(t, nil)
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)
	f.store.SetFaults(errors.New("version table unavailable internal-dsn-secret"), nil)

	_, userInfoErr := f.b.UserInfo(f.ctxA, token)
	_, inventoryErr := f.b.ListMyPermissions(f.ctxA, token)
	intro, introspectErr := f.b.Introspect(f.ctxA, token, "client-1")
	mustErrIs(t, userInfoErr, boundary.ErrFreshnessUnavailable)
	mustErrIs(t, inventoryErr, boundary.ErrFreshnessUnavailable)
	mustErrIs(t, introspectErr, boundary.ErrFreshnessUnavailable)
	if intro != nil {
		t.Fatalf("introspection must not return an active/inactive success body during freshness failure: %+v", intro)
	}
	if codeOfTest(userInfoErr) != codeOfTest(inventoryErr) || codeOfTest(userInfoErr) != codeOfTest(introspectErr) {
		t.Fatalf("error classifications differ: userinfo=%v inventory=%v introspect=%v", userInfoErr, inventoryErr, introspectErr)
	}
	if strings.Contains(userInfoErr.Error(), "internal-dsn-secret") {
		t.Fatalf("internal error leaked: %v", userInfoErr)
	}
	denied := f.b.AuditLog().Query(boundary.AuditFilter{
		Kind: boundary.AuditKindDecision, InstanceID: instanceA, Allowed: boolFalse(),
		ReasonCode: boundary.CodeFreshnessUnavailable,
	})
	if len(denied) < 3 {
		t.Fatalf("freshness failure audit records = %d, want one per path", len(denied))
	}
}

func codeOfTest(err error) boundary.Code {
	var e *boundary.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestSystemRoleIsNotRelaxedToProjectScope(t *testing.T) {
	f := newFixture(t, nil)
	must(t, f.store.SetSystemRoles(instanceA, "user-system", "system.owner"))
	ctx := boundary.WithInstance(context.Background(), instanceA)
	token, err := f.b.IssueToken(ctx, "user-system")
	must(t, err)

	systemDecision, err := f.b.Authorize(ctx, token, boundary.AccessRequest{
		Action:   "system.read",
		Resource: boundary.Resource{System: true},
	})
	must(t, err)
	if !systemDecision.Allowed {
		t.Fatal("system.owner must allow system.read")
	}
	projectDecision, err := f.b.Authorize(ctx, token, readProjectRequest())
	mustErrIs(t, err, boundary.ErrPermissionDenied)
	if projectDecision == nil || projectDecision.Allowed {
		t.Fatalf("system role must not be relaxed to project scope: %+v", projectDecision)
	}
}

func TestTokenFailureClassificationsAreDistinguishable(t *testing.T) {
	f := newFixture(t, nil)
	valid, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)

	expired, err := f.b.IssueClaims(boundary.Claims{
		Subject: subject1, InstanceID: instanceA, AuthzVersion: 1,
		IssuedAt:  f.clock.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: f.clock.Now().Add(-time.Minute).Unix(),
	})
	must(t, err)
	_, err = f.b.Authorize(f.ctxA, expired, readProjectRequest())
	mustErrIs(t, err, boundary.ErrTokenExpired)

	wrongSigner := boundary.NewTokenService(boundary.Config{InstanceKeys: map[string][]byte{instanceA: []byte("wrong-key")}, Now: f.clock.Now})
	tampered, err := wrongSigner.Issue(boundary.Claims{Subject: subject1, InstanceID: instanceA, AuthzVersion: 1})
	must(t, err)
	_, err = f.b.Authorize(f.ctxA, tampered, readProjectRequest())
	mustErrIs(t, err, boundary.ErrSignatureInvalid)

	_, err = f.b.Authorize(f.ctxA, "zab1.not-valid", readProjectRequest())
	mustErrIs(t, err, boundary.ErrTokenMalformed)

	_, err = f.b.Authorize(f.ctxB, valid, boundary.AccessRequest{
		Action: "project.read", Resource: boundary.Resource{ProjectID: projectB},
	})
	mustErrIs(t, err, boundary.ErrTokenInstanceMismatch)
}

func TestAuditNeverContainsTokenSecretsOrRawSubject(t *testing.T) {
	rawSubject := "raw-subject-secret-identifier-9f3c"
	secret := []byte("pseudonym-secret-material-7788")
	clock := &manualClock{now: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	cfg := boundary.Config{
		PseudonymSecret: secret,
		InstanceKeys:    map[string][]byte{instanceA: []byte("signing-secret-material-1234")},
		Now:             clock.Now,
	}
	b, err := boundary.NewBoundary(cfg)
	must(t, err)
	store := b.Store()
	ctx := boundary.WithInstance(context.Background(), instanceA)
	must(t, store.PutOrganization(boundary.OrganizationRecord{InstanceID: instanceA, ID: orgA, Active: true}))
	must(t, store.PutProject(boundary.ProjectRecord{InstanceID: instanceA, ID: projectA, OrganizationID: orgA, Active: true}))
	must(t, store.PutAuthorization(boundary.AuthorizationRecord{
		ID: authA, InstanceID: instanceA, SubjectID: rawSubject,
		ProjectID: projectA, OrgID: orgA, Roles: []string{"project.viewer"}, Active: true,
	}))
	token, err := b.IssueToken(ctx, rawSubject)
	must(t, err)
	_, err = b.Authorize(ctx, token, readProjectRequest())
	must(t, err)
	_, err = b.Authorize(ctx, token, boundary.AccessRequest{
		Action: "project.write", Resource: boundary.Resource{ProjectID: projectA, OrganizationID: orgA},
	})
	mustErrIs(t, err, boundary.ErrPermissionDenied)

	events := b.AuditLog().Events()
	if len(events) < 2 {
		t.Fatalf("audit events = %d", len(events))
	}
	rawJSON, err := json.Marshal(events)
	must(t, err)
	text := string(rawJSON)
	for _, forbidden := range []string{
		token,
		rawSubject,
		"signing-secret-material-1234",
		"pseudonym-secret-material-7788",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("audit output contains forbidden value %q", forbidden)
		}
	}
	pseudo := boundary.SubjectPseudonym(secret, instanceA, rawSubject)
	if !strings.Contains(text, pseudo) {
		t.Fatal("audit output does not contain the irreversible subject pseudonym")
	}
}

type failingAuditSink struct{}

func (failingAuditSink) Audit(context.Context, boundary.AuditEvent) error {
	return errors.New("audit backend unavailable password=audit-secret")
}

func TestAuditWriteFailureFailsClosedAndSanitized(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	store := boundary.NewMemoryStore(clock.Now)
	cfg := boundary.Config{Now: clock.Now, SigningSecret: []byte("signing")}
	b, err := boundary.NewBoundaryWithDependencies(cfg, store, nil, failingAuditSink{})
	must(t, err)
	ctx := boundary.WithInstance(context.Background(), instanceA)
	must(t, store.PutOrganization(boundary.OrganizationRecord{InstanceID: instanceA, ID: orgA, Active: true}))
	must(t, store.PutProject(boundary.ProjectRecord{InstanceID: instanceA, ID: projectA, OrganizationID: orgA, Active: true}))
	must(t, store.PutAuthorization(boundary.AuthorizationRecord{
		ID: authA, InstanceID: instanceA, SubjectID: subject1, ProjectID: projectA, OrgID: orgA,
		Roles: []string{"project.viewer"}, Active: true,
	}))
	token, err := b.IssueToken(ctx, subject1)
	must(t, err)
	_, err = b.UserInfo(ctx, token)
	mustErrIs(t, err, boundary.ErrAuditUnavailable)
	if strings.Contains(err.Error(), "audit-secret") {
		t.Fatalf("audit backend error leaked: %v", err)
	}
}

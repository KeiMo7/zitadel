package boundary

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Repository is the freshness and authorization source needed by Resolver.
//
// Every method takes the request instance explicitly. Implementations must
// scope their queries by that instance and must not fall back to a default.
type Repository interface {
	CurrentVersion(ctx context.Context, instanceID, subjectID string) (uint64, time.Time, error)
	LoadAuthorization(ctx context.Context, instanceID, subjectID string) (*AuthorizationData, error)
}

// RecordRepository adds instance-scoped single-read and list operations.
type RecordRepository interface {
	Repository
	GetAuthorizationRecord(ctx context.Context, instanceID, authorizationID string) (*AuthorizationRecord, error)
	ListAuthorizationRecords(ctx context.Context, instanceID string, filter AuthorizationListFilter) ([]*AuthorizationRecord, error)
}

// AuthorizationRecord is a project authorization/user-grant record.
type AuthorizationRecord struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instanceId"`
	SubjectID  string    `json:"subjectId"`
	ProjectID  string    `json:"projectId"`
	OrgID      string    `json:"orgId,omitempty"`
	GrantID    string    `json:"grantId,omitempty"`
	Roles      []string  `json:"roles"`
	Active     bool      `json:"active"`
	Version    uint64    `json:"version"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// AuthorizationListFilter narrows record listing. Empty SubjectID or
// ProjectID means no restriction on that field.
type AuthorizationListFilter struct {
	SubjectID string
	ProjectID string
}

// OrganizationRecord is the minimal organization state needed to enforce
// deactivation.
type OrganizationRecord struct {
	InstanceID string
	ID         string
	Active     bool
}

// ProjectRecord is the minimal project state needed to enforce deactivation.
type ProjectRecord struct {
	InstanceID     string
	ID             string
	OrganizationID string
	Active         bool
}

// MembershipRecord represents an organization or project membership.
type MembershipRecord struct {
	ID         string
	InstanceID string
	SubjectID  string
	Scope      ScopeKind
	OrgID      string
	ProjectID  string
	Roles      []string
	Active     bool
}

// ProjectGrantRecord represents an organization-to-organization project grant.
type ProjectGrantRecord struct {
	ID                    string
	InstanceID            string
	ProjectID             string
	GrantedOrganizationID string
	Active                bool
}

type subjectKey struct {
	instanceID string
	subjectID  string
}

type appliedEvent struct {
	version uint64
}

type instanceData struct {
	organizations  map[string]OrganizationRecord
	projects       map[string]ProjectRecord
	memberships    map[string]MembershipRecord
	grants         map[string]ProjectGrantRecord
	authorizations map[string]AuthorizationRecord
	systemRoles    map[string][]string
	instanceRoles  map[string][]string
	contradictions map[string]bool
}

func newInstanceData() *instanceData {
	return &instanceData{
		organizations:  make(map[string]OrganizationRecord),
		projects:       make(map[string]ProjectRecord),
		memberships:    make(map[string]MembershipRecord),
		grants:         make(map[string]ProjectGrantRecord),
		authorizations: make(map[string]AuthorizationRecord),
		systemRoles:    make(map[string][]string),
		instanceRoles:  make(map[string][]string),
		contradictions: make(map[string]bool),
	}
}

// MemoryStore is a concurrency-safe in-memory RecordRepository.
type MemoryStore struct {
	mu        sync.RWMutex
	now       func() time.Time
	createdAt time.Time

	data      map[string]*instanceData
	versions  map[subjectKey]uint64
	changedAt map[subjectKey]time.Time
	loads     map[subjectKey]int64
	applied   map[string]appliedEvent

	versionErr error
	loadErr    error
}

var _ RecordRepository = (*MemoryStore)(nil)

// NewMemoryStore creates an empty memory repository.
func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	t := now()
	return &MemoryStore{
		now:       now,
		createdAt: t,
		data:      make(map[string]*instanceData),
		versions:  make(map[subjectKey]uint64),
		changedAt: make(map[subjectKey]time.Time),
		loads:     make(map[subjectKey]int64),
		applied:   make(map[string]appliedEvent),
	}
}

func (m *MemoryStore) instanceDataLocked(instanceID string, create bool) *instanceData {
	d := m.data[instanceID]
	if d == nil && create {
		d = newInstanceData()
		m.data[instanceID] = d
	}
	return d
}

// SetFaults injects storage failures for degradation tests. The supplied
// errors may contain sensitive/internal text; Boundary must sanitize them.
func (m *MemoryStore) SetFaults(versionErr, loadErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versionErr = versionErr
	m.loadErr = loadErr
}

// CurrentVersion implements Repository.
func (m *MemoryStore) CurrentVersion(_ context.Context, instanceID, subjectID string) (uint64, time.Time, error) {
	if instanceID == "" {
		return 0, time.Time{}, ErrInstanceMissing
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.versionErr != nil {
		return 0, time.Time{}, m.versionErr
	}
	key := subjectKey{instanceID, subjectID}
	v := m.versions[key]
	if v == 0 {
		v = InitialAuthorizationVersion
	}
	changedAt := m.changedAt[key]
	if changedAt.IsZero() {
		changedAt = m.createdAt
	}
	return v, changedAt, nil
}

// LoadCount returns the number of full authorization loads for a subject.
// Version checks do not increment this counter.
func (m *MemoryStore) LoadCount(instanceID, subjectID string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loads[subjectKey{instanceID, subjectID}]
}

func (m *MemoryStore) bumpLocked(instanceID, subjectID string) uint64 {
	key := subjectKey{instanceID, subjectID}
	v := m.versions[key]
	if v == 0 {
		v = InitialAuthorizationVersion
	}
	v++
	m.versions[key] = v
	m.changedAt[key] = m.now()
	return v
}

func (m *MemoryStore) bumpSubjectsLocked(instanceID string, subjectIDs ...string) {
	seen := make(map[string]struct{}, len(subjectIDs))
	for _, subjectID := range subjectIDs {
		if subjectID == "" {
			continue
		}
		if _, ok := seen[subjectID]; ok {
			continue
		}
		seen[subjectID] = struct{}{}
		m.bumpLocked(instanceID, subjectID)
	}
}

// PutOrganization stores an organization record.
func (m *MemoryStore) PutOrganization(record OrganizationRecord) error {
	if record.InstanceID == "" || record.ID == "" {
		return ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(record.InstanceID, true)
	d.organizations[record.ID] = record
	for _, membership := range d.memberships {
		if membership.OrgID == record.ID {
			m.bumpLocked(record.InstanceID, membership.SubjectID)
		}
	}
	for _, auth := range d.authorizations {
		if auth.OrgID == record.ID {
			m.bumpLocked(record.InstanceID, auth.SubjectID)
		}
	}
	return nil
}

// PutProject stores a project record.
func (m *MemoryStore) PutProject(record ProjectRecord) error {
	if record.InstanceID == "" || record.ID == "" {
		return ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(record.InstanceID, true)
	d.projects[record.ID] = record
	for _, auth := range d.authorizations {
		if auth.ProjectID == record.ID {
			m.bumpLocked(record.InstanceID, auth.SubjectID)
		}
	}
	for _, membership := range d.memberships {
		if membership.ProjectID == record.ID {
			m.bumpLocked(record.InstanceID, membership.SubjectID)
		}
	}
	return nil
}

// PutMembership stores a membership record.
func (m *MemoryStore) PutMembership(record MembershipRecord) error {
	if record.InstanceID == "" || record.ID == "" || record.SubjectID == "" {
		return ErrInstanceMissing
	}
	if record.Scope == "" {
		if record.ProjectID != "" {
			record.Scope = ScopeProject
		} else {
			record.Scope = ScopeOrganization
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(record.InstanceID, true)
	d.memberships[record.ID] = record
	m.bumpLocked(record.InstanceID, record.SubjectID)
	return nil
}

// PutProjectGrant stores a project grant.
func (m *MemoryStore) PutProjectGrant(record ProjectGrantRecord) error {
	if record.InstanceID == "" || record.ID == "" || record.ProjectID == "" {
		return ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(record.InstanceID, true)
	d.grants[record.ID] = record
	for _, auth := range d.authorizations {
		if auth.GrantID == record.ID {
			m.bumpLocked(record.InstanceID, auth.SubjectID)
		}
	}
	return nil
}

// SetProjectGrantActive flips a project grant state and bumps every linked
// authorization subject.
func (m *MemoryStore) SetProjectGrantActive(_ context.Context, instanceID, grantID string, active bool) (*ProjectGrantRecord, []string, error) {
	if instanceID == "" {
		return nil, nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, nil, ErrNotFound
	}
	grant, ok := d.grants[grantID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	grant.Active = active
	d.grants[grantID] = grant
	subjects := make(map[string]struct{})
	for _, auth := range d.authorizations {
		if auth.GrantID == grantID {
			subjects[auth.SubjectID] = struct{}{}
			m.bumpLocked(instanceID, auth.SubjectID)
		}
	}
	ids := make([]string, 0, len(subjects))
	for id := range subjects {
		ids = append(ids, id)
	}
	return &grant, ids, nil
}

// DeleteProjectGrant deletes a project grant. Linked authorizations then fail
// source-integrity resolution until they are removed or corrected.
func (m *MemoryStore) DeleteProjectGrant(_ context.Context, instanceID, grantID string) (*ProjectGrantRecord, []string, error) {
	if instanceID == "" {
		return nil, nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, nil, ErrNotFound
	}
	grant, ok := d.grants[grantID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	subjects := make([]string, 0)
	for _, auth := range d.authorizations {
		if auth.GrantID == grantID {
			subjects = append(subjects, auth.SubjectID)
			m.bumpLocked(instanceID, auth.SubjectID)
		}
	}
	delete(d.grants, grantID)
	return &grant, subjects, nil
}

// PutAuthorization stores an authorization without additional validation.
// This is useful for setting up missing-source failure fixtures.
func (m *MemoryStore) PutAuthorization(record AuthorizationRecord) error {
	if record.InstanceID == "" || record.ID == "" || record.SubjectID == "" {
		return ErrInstanceMissing
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = m.now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record.Version = m.bumpLocked(record.InstanceID, record.SubjectID)
	d := m.instanceDataLocked(record.InstanceID, true)
	d.authorizations[record.ID] = record
	return nil
}

// SetInstanceRoles replaces instance-level role bindings.
func (m *MemoryStore) SetInstanceRoles(instanceID, subjectID string, roles ...string) error {
	if instanceID == "" || subjectID == "" {
		return ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, true)
	d.instanceRoles[subjectID] = append([]string(nil), roles...)
	m.bumpLocked(instanceID, subjectID)
	return nil
}

// SetSystemRoles replaces system-scoped role bindings for a subject within
// the request's instance key. These roles never authorize lower scopes.
func (m *MemoryStore) SetSystemRoles(instanceID, subjectID string, roles ...string) error {
	if instanceID == "" || subjectID == "" {
		return ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, true)
	d.systemRoles[subjectID] = append([]string(nil), roles...)
	m.bumpLocked(instanceID, subjectID)
	return nil
}

// SetContradiction marks a subject's source data as contradictory.
func (m *MemoryStore) SetContradiction(instanceID, subjectID string, contradictory bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, true)
	d.contradictions[subjectID] = contradictory
	m.bumpLocked(instanceID, subjectID)
}

// RemoveMembership deletes a membership and bumps the affected subject.
func (m *MemoryStore) RemoveMembership(_ context.Context, instanceID, membershipID string) (*MembershipRecord, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, ErrNotFound
	}
	record, ok := d.memberships[membershipID]
	if !ok {
		return nil, ErrNotFound
	}
	delete(d.memberships, membershipID)
	m.bumpLocked(instanceID, record.SubjectID)
	return &record, nil
}

// DeleteAuthorization deletes a project authorization.
func (m *MemoryStore) DeleteAuthorization(_ context.Context, instanceID, authorizationID string) (*AuthorizationRecord, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, ErrNotFound
	}
	record, ok := d.authorizations[authorizationID]
	if !ok {
		return nil, ErrNotFound
	}
	delete(d.authorizations, authorizationID)
	m.bumpLocked(instanceID, record.SubjectID)
	return &record, nil
}

// ModifyAuthorizationRoles atomically applies add/remove role changes.
func (m *MemoryStore) ModifyAuthorizationRoles(_ context.Context, instanceID, authorizationID string, add, remove []string) (before, after []string, record *AuthorizationRecord, version uint64, err error) {
	if instanceID == "" {
		return nil, nil, nil, 0, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, nil, nil, 0, ErrNotFound
	}
	auth, ok := d.authorizations[authorizationID]
	if !ok {
		return nil, nil, nil, 0, ErrNotFound
	}
	before = append([]string(nil), auth.Roles...)
	set := make(map[string]struct{}, len(auth.Roles)+len(add))
	for _, role := range auth.Roles {
		set[role] = struct{}{}
	}
	for _, role := range remove {
		delete(set, role)
	}
	for _, role := range add {
		set[role] = struct{}{}
	}
	roles := make([]string, 0, len(set))
	for role := range set {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	auth.Roles = roles
	auth.Version = m.bumpLocked(instanceID, auth.SubjectID)
	auth.UpdatedAt = m.now()
	d.authorizations[authorizationID] = auth
	return before, append([]string(nil), roles...), &auth, auth.Version, nil
}

// SetOrganizationActive flips organization state and bumps affected subjects.
func (m *MemoryStore) SetOrganizationActive(_ context.Context, instanceID, organizationID string, active bool) ([]string, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, ErrNotFound
	}
	org, ok := d.organizations[organizationID]
	if !ok {
		return nil, ErrNotFound
	}
	org.Active = active
	d.organizations[organizationID] = org
	subjects := make(map[string]struct{})
	projectIDs := make(map[string]struct{})
	for _, project := range d.projects {
		if project.OrganizationID == organizationID {
			projectIDs[project.ID] = struct{}{}
		}
	}
	for _, membership := range d.memberships {
		if membership.OrgID == organizationID {
			subjects[membership.SubjectID] = struct{}{}
		}
		if membership.Scope == ScopeProject {
			if _, ok := projectIDs[membership.ProjectID]; ok {
				subjects[membership.SubjectID] = struct{}{}
			}
		}
	}
	for _, auth := range d.authorizations {
		if auth.OrgID == organizationID {
			subjects[auth.SubjectID] = struct{}{}
		}
		if _, ok := projectIDs[auth.ProjectID]; ok {
			subjects[auth.SubjectID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(subjects))
	for id := range subjects {
		ids = append(ids, id)
	}
	m.bumpSubjectsLocked(instanceID, ids...)
	return ids, nil
}

// SetProjectActive flips project state and bumps affected subjects.
func (m *MemoryStore) SetProjectActive(_ context.Context, instanceID, projectID string, active bool) ([]string, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.instanceDataLocked(instanceID, false)
	if d == nil {
		return nil, ErrNotFound
	}
	project, ok := d.projects[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	project.Active = active
	d.projects[projectID] = project
	subjects := make(map[string]struct{})
	for _, membership := range d.memberships {
		if membership.ProjectID == projectID {
			subjects[membership.SubjectID] = struct{}{}
		}
	}
	for _, auth := range d.authorizations {
		if auth.ProjectID == projectID {
			subjects[auth.SubjectID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(subjects))
	for id := range subjects {
		ids = append(ids, id)
	}
	m.bumpSubjectsLocked(instanceID, ids...)
	return ids, nil
}

// GetAuthorizationRecord implements RecordRepository.
func (m *MemoryStore) GetAuthorizationRecord(_ context.Context, instanceID, authorizationID string) (*AuthorizationRecord, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	d := m.data[instanceID]
	if d == nil {
		return nil, ErrNotFound
	}
	record, ok := d.authorizations[authorizationID]
	if !ok {
		return nil, ErrNotFound
	}
	copyRecord := record
	copyRecord.Roles = append([]string(nil), record.Roles...)
	return &copyRecord, nil
}

// ListAuthorizationRecords implements RecordRepository.
func (m *MemoryStore) ListAuthorizationRecords(_ context.Context, instanceID string, filter AuthorizationListFilter) ([]*AuthorizationRecord, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	d := m.data[instanceID]
	if d == nil {
		return []*AuthorizationRecord{}, nil
	}
	result := make([]*AuthorizationRecord, 0, len(d.authorizations))
	for _, record := range d.authorizations {
		if filter.SubjectID != "" && record.SubjectID != filter.SubjectID {
			continue
		}
		if filter.ProjectID != "" && record.ProjectID != filter.ProjectID {
			continue
		}
		r := record
		r.Roles = append([]string(nil), record.Roles...)
		result = append(result, &r)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// LoadAuthorization implements Repository.
//
//nolint:gocognit // The in-memory source loader intentionally validates every supported source kind and reference in one deterministic scan.
func (m *MemoryStore) LoadAuthorization(_ context.Context, instanceID, subjectID string) (*AuthorizationData, error) {
	if instanceID == "" {
		return nil, ErrInstanceMissing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	key := subjectKey{instanceID, subjectID}
	m.loads[key]++

	version := m.versions[key]
	if version == 0 {
		version = InitialAuthorizationVersion
	}
	changedAt := m.changedAt[key]
	if changedAt.IsZero() {
		changedAt = m.createdAt
	}
	d := m.data[instanceID]
	if d == nil {
		return &AuthorizationData{Version: version, ChangedAt: changedAt}, nil
	}
	if d.contradictions[subjectID] {
		return nil, ErrSourceConflict
	}

	bindings := make([]RoleBinding, 0)
	for _, role := range d.systemRoles[subjectID] {
		bindings = append(bindings, RoleBinding{Role: role, Effect: EffectAllow, Source: Source{Kind: SourceSystemRole, ID: "system-role:" + role}})
	}
	for _, role := range d.instanceRoles[subjectID] {
		bindings = append(bindings, RoleBinding{Role: role, Effect: EffectAllow, Source: Source{Kind: SourceInstanceRole, ID: "instance-role:" + role}})
	}

	for _, membership := range d.memberships {
		if membership.InstanceID != instanceID || membership.SubjectID != subjectID || !membership.Active {
			continue
		}
		roles := membership.Roles
		if len(roles) == 0 {
			if membership.Scope == ScopeProject {
				roles = []string{"project.viewer"}
			} else {
				roles = []string{"org.member"}
			}
		}
		source := Source{
			Kind:      SourceProjectMembership,
			ID:        membership.ID,
			OrgID:     membership.OrgID,
			ProjectID: membership.ProjectID,
		}
		if membership.Scope == ScopeOrganization {
			source.Kind = SourceOrganizationMembership
			source.ProjectID = ""
		}
		allowed, err := m.membershipScopeActiveLocked(d, membership)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		for _, role := range roles {
			bindings = append(bindings, RoleBinding{Role: role, Effect: EffectAllow, Source: source})
		}
	}

	for _, auth := range d.authorizations {
		if auth.InstanceID != instanceID || auth.SubjectID != subjectID || !auth.Active {
			continue
		}
		project, ok := d.projects[auth.ProjectID]
		if !ok {
			return nil, Errorf(CodeAuthorizationSourceMissing, "project source %s is missing", auth.ProjectID)
		}
		if project.InstanceID != instanceID {
			return nil, ErrSourceMissing
		}
		orgID := auth.OrgID
		if orgID == "" {
			orgID = project.OrganizationID
		}
		org, ok := d.organizations[orgID]
		if !ok {
			return nil, Errorf(CodeAuthorizationSourceMissing, "organization source %s is missing", orgID)
		}
		if !project.Active || !org.Active {
			continue
		}
		source := Source{
			Kind:      SourceProjectAuthorization,
			ID:        auth.ID,
			OrgID:     orgID,
			ProjectID: project.ID,
			GrantID:   auth.GrantID,
		}
		if auth.GrantID != "" {
			grant, ok := d.grants[auth.GrantID]
			if !ok {
				return nil, Errorf(CodeAuthorizationSourceMissing, "project grant source %s is missing", auth.GrantID)
			}
			if grant.ProjectID != project.ID || grant.InstanceID != instanceID {
				return nil, Errorf(CodeAuthorizationSourceConflict, "project grant %s does not match authorization", auth.GrantID)
			}
			if !grant.Active {
				continue
			}
		}
		for _, role := range auth.Roles {
			bindings = append(bindings, RoleBinding{Role: role, Effect: EffectAllow, Source: source})
		}
	}

	return &AuthorizationData{Version: version, ChangedAt: changedAt, Bindings: bindings}, nil
}

func (m *MemoryStore) membershipScopeActiveLocked(d *instanceData, membership MembershipRecord) (bool, error) {
	if membership.Scope == ScopeProject {
		project, ok := d.projects[membership.ProjectID]
		if !ok {
			return false, Errorf(CodeAuthorizationSourceMissing, "project membership source %s is missing", membership.ID)
		}
		org, ok := d.organizations[project.OrganizationID]
		if !ok {
			return false, Errorf(CodeAuthorizationSourceMissing, "organization source %s is missing", project.OrganizationID)
		}
		return project.Active && org.Active, nil
	}

	org, ok := d.organizations[membership.OrgID]
	if !ok {
		return false, Errorf(CodeAuthorizationSourceMissing, "organization membership source %s is missing", membership.ID)
	}
	return org.Active, nil
}

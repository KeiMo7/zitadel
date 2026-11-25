package boundary

import (
	"sort"
	"strings"
	"time"
)

// SourceKind identifies the authoritative origin of a role binding.
type SourceKind string

const (
	SourceSystemRole             SourceKind = "system_role"
	SourceInstanceRole           SourceKind = "instance_role"
	SourceOrganizationMembership SourceKind = "organization_membership"
	SourceProjectMembership      SourceKind = "project_membership"
	SourceProjectAuthorization   SourceKind = "project_authorization"
)

// DefaultSourcePriorities defines deterministic merge order. Larger numbers
// win when selecting the primary origin of the same role.
//
// Explicit project authorization is closer to the protected resource than
// generic membership; organization membership outranks project membership for
// organization-wide roles; instance roles are traceable separately. System
// roles have the highest numeric priority but ScopeSystem prevents them from
// being applied to organization or project resources.
func DefaultSourcePriorities() map[SourceKind]int {
	return map[SourceKind]int{
		SourceSystemRole:             500,
		SourceInstanceRole:           400,
		SourceOrganizationMembership: 300,
		SourceProjectAuthorization:   200,
		SourceProjectMembership:      100,
	}
}

// ScopeKind is the administrative/resource scope of a permission grant.
type ScopeKind string

const (
	ScopeSystem       ScopeKind = "system"
	ScopeInstance     ScopeKind = "instance"
	ScopeOrganization ScopeKind = "organization"
	ScopeProject      ScopeKind = "project"
)

// Source is a traceable authorization origin.
type Source struct {
	Kind      SourceKind `json:"kind"`
	ID        string     `json:"id"`
	Priority  int        `json:"priority"`
	OrgID     string     `json:"orgId,omitempty"`
	ProjectID string     `json:"projectId,omitempty"`
	GrantID   string     `json:"grantId,omitempty"`
}

// Effect allows explicit deny entries while retaining the default allow
// behavior for ordinary role bindings.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// RoleBinding is one role supplied by one authorization source.
type RoleBinding struct {
	Role   string `json:"role"`
	Effect Effect `json:"effect,omitempty"`
	Source Source `json:"source"`
}

// AuthorizationData is the full instance-scoped resolution result loaded from
// the single authorization repository.
type AuthorizationData struct {
	Version   uint64
	ChangedAt time.Time
	Bindings  []RoleBinding
}

// EffectiveRole records the merged origins of a role.
type EffectiveRole struct {
	Role          string   `json:"role"`
	PrimarySource Source   `json:"primarySource"`
	Sources       []Source `json:"sources"`
}

// PermissionGrant is a permission plus the scope/source that grants it.
type PermissionGrant struct {
	Permission string    `json:"permission"`
	Role       string    `json:"role"`
	Scope      ScopeKind `json:"scope"`
	ResourceID string    `json:"resourceId,omitempty"`
	OrgID      string    `json:"orgId,omitempty"`
	Source     Source    `json:"source"`
}

// Snapshot is the immutable effective authorization set for one
// (instance, pseudonymous subject, version).
type Snapshot struct {
	InstanceID       string            `json:"instanceId"`
	SubjectPseudonym string            `json:"subjectPseudonym"`
	Version          uint64            `json:"version"`
	Roles            []string          `json:"roles"`
	Permissions      []string          `json:"permissions"`
	EffectiveRoles   []EffectiveRole   `json:"effectiveRoles"`
	PermissionGrants []PermissionGrant `json:"permissionGrants"`
	ResolvedAt       time.Time         `json:"resolvedAt"`
	ChangedAt        time.Time         `json:"changedAt"`
}

// AuthorityView is the canonical set exposed by all four outward paths.
type AuthorityView struct {
	InstanceID       string          `json:"instanceId"`
	SubjectPseudonym string          `json:"subjectPseudonym"`
	Version          uint64          `json:"authzVersion"`
	Roles            []string        `json:"roles"`
	Permissions      []string        `json:"permissions"`
	EffectiveRoles   []EffectiveRole `json:"effectiveRoles"`
}

func ViewFromSnapshot(s *Snapshot) AuthorityView {
	if s == nil {
		return AuthorityView{}
	}
	return AuthorityView{
		InstanceID:       s.InstanceID,
		SubjectPseudonym: s.SubjectPseudonym,
		Version:          s.Version,
		Roles:            append([]string(nil), s.Roles...),
		Permissions:      append([]string(nil), s.Permissions...),
		EffectiveRoles:   append([]EffectiveRole(nil), s.EffectiveRoles...),
	}
}

// Resource identifies the target of an authorization decision.
type Resource struct {
	Scope          ScopeKind `json:"scope,omitempty"`
	System         bool      `json:"system,omitempty"`
	OrganizationID string    `json:"organizationId,omitempty"`
	ProjectID      string    `json:"projectId,omitempty"`
}

// AccessRequest is a protected-interface authorization decision.
type AccessRequest struct {
	// Action/Permission name, for example project.read.
	Action   string
	Resource Resource
}

func (r Resource) normalized() Resource {
	if r.System || r.Scope == ScopeSystem {
		r.Scope = ScopeSystem
		r.System = true
		return r
	}
	if r.Scope == "" {
		switch {
		case r.ProjectID != "":
			r.Scope = ScopeProject
		case r.OrganizationID != "":
			r.Scope = ScopeOrganization
		default:
			r.Scope = ScopeInstance
		}
	}
	return r
}

// Allows reports whether action is granted on resource by this snapshot.
func (s *Snapshot) Allows(action string, resource Resource) bool {
	if s == nil || action == "" {
		return false
	}
	resource = resource.normalized()
	for _, grant := range s.PermissionGrants {
		if !permissionMatches(grant.Permission, action) {
			continue
		}
		switch grant.Scope {
		case ScopeSystem:
			// System roles are never relaxed to instance/org/project checks.
			if resource.Scope == ScopeSystem {
				return true
			}
		case ScopeInstance:
			// Instance permissions may be inherited by lower scopes, matching
			// the existing PermissionChecker contract.
			if resource.Scope == ScopeInstance ||
				resource.Scope == ScopeOrganization ||
				resource.Scope == ScopeProject {
				return true
			}
		case ScopeOrganization:
			if resource.Scope == ScopeOrganization && grant.ResourceID == resource.OrganizationID {
				return true
			}
			if resource.Scope == ScopeProject && resource.OrganizationID != "" && grant.ResourceID == resource.OrganizationID {
				return true
			}
		case ScopeProject:
			if resource.Scope == ScopeProject && grant.ResourceID == resource.ProjectID {
				return true
			}
		}
	}
	return false
}

func permissionMatches(granted, requested string) bool {
	if granted == requested {
		return true
	}
	if strings.HasSuffix(granted, ".*") {
		prefix := strings.TrimSuffix(granted, "*") // keeps trailing dot
		return strings.HasPrefix(requested, prefix)
	}
	if granted == "*" {
		return true
	}
	return false
}

// mergeBindings deterministically merges role bindings.
func mergeBindings(instanceID, subjectPseudonym string, version uint64, changedAt, resolvedAt time.Time, bindings []RoleBinding, catalog map[string][]string, priorities map[SourceKind]int) *Snapshot {
	byRole := make(map[string][]Source)
	denied := make(map[string]bool)
	var grants []PermissionGrant

	for _, b := range bindings {
		role := strings.TrimSpace(b.Role)
		if role == "" {
			continue
		}
		source := b.Source
		if source.Priority == 0 {
			source.Priority = priorities[source.Kind]
		}
		if b.Effect == EffectDeny {
			denied[role] = true
		}
		byRole[role] = append(byRole[role], source)

		scope, resourceID, orgID := scopeForSource(source)
		for _, perm := range catalog[role] {
			grants = append(grants, PermissionGrant{
				Permission: perm,
				Role:       role,
				Scope:      scope,
				ResourceID: resourceID,
				OrgID:      orgID,
				Source:     source,
			})
		}
	}

	roles := make([]string, 0, len(byRole))
	effective := make([]EffectiveRole, 0, len(byRole))
	for role, sources := range byRole {
		if denied[role] {
			// Explicit deny removes the role from the effective set. Conflicting
			// allow/deny data at the same authoritative source is detected by
			// the repository; ordinary deny overrides allow deterministically.
			continue
		}
		sort.SliceStable(sources, func(i, j int) bool {
			if sources[i].Priority != sources[j].Priority {
				return sources[i].Priority > sources[j].Priority
			}
			if sources[i].Kind != sources[j].Kind {
				return sources[i].Kind < sources[j].Kind
			}
			return sources[i].ID < sources[j].ID
		})
		roles = append(roles, role)
		effective = append(effective, EffectiveRole{
			Role:          role,
			PrimarySource: sources[0],
			Sources:       append([]Source(nil), sources...),
		})
	}
	sort.Strings(roles)
	sort.Slice(effective, func(i, j int) bool { return effective[i].Role < effective[j].Role })

	// Remove grants whose role was deterministically denied.
	effectiveGrants := make([]PermissionGrant, 0, len(grants))
	for _, grant := range grants {
		if !denied[grant.Role] {
			effectiveGrants = append(effectiveGrants, grant)
		}
	}
	grants = effectiveGrants

	permSet := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		permSet[g.Permission] = struct{}{}
	}
	permissions := make([]string, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	sort.Strings(permissions)
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Permission != grants[j].Permission {
			return grants[i].Permission < grants[j].Permission
		}
		if grants[i].Role != grants[j].Role {
			return grants[i].Role < grants[j].Role
		}
		return grants[i].Source.ID < grants[j].Source.ID
	})

	return &Snapshot{
		InstanceID:       instanceID,
		SubjectPseudonym: subjectPseudonym,
		Version:          version,
		Roles:            roles,
		Permissions:      permissions,
		EffectiveRoles:   effective,
		PermissionGrants: grants,
		ResolvedAt:       resolvedAt,
		ChangedAt:        changedAt,
	}
}

func scopeForSource(source Source) (ScopeKind, string, string) {
	switch source.Kind {
	case SourceSystemRole:
		return ScopeSystem, "", ""
	case SourceInstanceRole:
		return ScopeInstance, "", ""
	case SourceOrganizationMembership:
		return ScopeOrganization, source.OrgID, source.OrgID
	case SourceProjectMembership, SourceProjectAuthorization:
		return ScopeProject, source.ProjectID, source.OrgID
	default:
		return ScopeInstance, "", ""
	}
}

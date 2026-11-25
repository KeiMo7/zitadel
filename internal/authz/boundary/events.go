package boundary

import (
	"context"
	"sort"
)

// RoleSetEvent is an idempotent authorization role-set change.
//
// Version is monotonic per (instance, subject). An older non-duplicate event
// is rejected and never rolls the aggregate version backwards.
type RoleSetEvent struct {
	EventID         string
	InstanceID      string
	SubjectID       string
	AuthorizationID string
	ProjectID       string
	OrgID           string
	Version         uint64
	Roles           []string
}

// ApplyEventResult reports the applied or duplicate event.
type ApplyEventResult struct {
	Duplicate bool
	Before    []string
	After     []string
	Version   uint64
}

// ApplyRoleSetEvent applies an ordered/redelivered change through the version
// guard and records an authorization-change audit event.
func (b *Boundary) ApplyRoleSetEvent(ctx context.Context, event RoleSetEvent) (*ApplyEventResult, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if event.InstanceID != "" && event.InstanceID != instanceID {
		return nil, ErrInstanceMismatch
	}
	event.InstanceID = instanceID
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory event application is not wired")
	}
	result, err := b.store.ApplyRoleSetEvent(ctx, event)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, event.SubjectID)
	if !result.Duplicate {
		b.writeChangeAudit(
			ctx,
			instanceID,
			event.SubjectID,
			event.ProjectID,
			event.OrgID,
			event.AuthorizationID,
			"role_set_event_applied",
			result.Before,
			result.After,
			0,
			result.Version,
			event.EventID,
		)
	}
	return result, nil
}

// ApplyRoleSetEvent applies the event to MemoryStore.
func (m *MemoryStore) ApplyRoleSetEvent(_ context.Context, event RoleSetEvent) (*ApplyEventResult, error) {
	if event.InstanceID == "" {
		return nil, ErrInstanceMissing
	}
	if event.EventID == "" || event.SubjectID == "" || event.AuthorizationID == "" || event.Version == 0 {
		return nil, NewError(CodeInvalidRequest, "event id, subject, authorization and positive version are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if applied, ok := m.applied[event.EventID]; ok {
		if applied.version != event.Version {
			return nil, Errorf(CodeAuthorizationSourceConflict, "event id %s was already applied at another version", event.EventID)
		}
		d := m.instanceDataLocked(event.InstanceID, false)
		if d == nil {
			return &ApplyEventResult{Duplicate: true, Version: applied.version, Before: []string{}, After: []string{}}, nil
		}
		auth, ok := d.authorizations[event.AuthorizationID]
		if !ok {
			return &ApplyEventResult{Duplicate: true, Version: applied.version, Before: []string{}, After: []string{}}, nil
		}
		return &ApplyEventResult{Duplicate: true, Version: applied.version, Before: append([]string(nil), auth.Roles...), After: append([]string(nil), auth.Roles...)}, nil
	}

	key := subjectKey{event.InstanceID, event.SubjectID}
	current := m.versions[key]
	if current == 0 {
		current = InitialAuthorizationVersion
	}
	if event.Version < current {
		return nil, Errorf(CodeVersionRollback, "event version %d is older than current version %d", event.Version, current)
	}

	d := m.instanceDataLocked(event.InstanceID, false)
	if d == nil {
		return nil, ErrNotFound
	}
	auth, ok := d.authorizations[event.AuthorizationID]
	if !ok {
		return nil, ErrNotFound
	}
	before := append([]string(nil), auth.Roles...)
	after := append([]string(nil), event.Roles...)
	sort.Strings(after)
	auth.Roles = after
	auth.Version = event.Version
	auth.UpdatedAt = m.now()
	d.authorizations[event.AuthorizationID] = auth

	m.versions[key] = event.Version
	m.changedAt[key] = m.now()
	m.applied[event.EventID] = appliedEvent{version: event.Version}
	return &ApplyEventResult{Duplicate: false, Before: before, After: append([]string(nil), after...), Version: event.Version}, nil
}

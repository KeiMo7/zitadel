package boundary

import (
	"context"
)

// CreateAuthorization creates a project authorization and writes its initial
// before/after change audit.
func (b *Boundary) CreateAuthorization(ctx context.Context, record AuthorizationRecord) (*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	if record.InstanceID == "" {
		record.InstanceID = instanceID
	} else if record.InstanceID != instanceID {
		return nil, ErrInstanceMismatch
	}
	if err := b.store.PutAuthorization(record); err != nil {
		return nil, err
	}
	stored, err := b.store.GetAuthorizationRecord(ctx, instanceID, record.ID)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, stored.SubjectID)
	b.writeChangeAudit(ctx, instanceID, stored.SubjectID, stored.ProjectID, stored.OrgID, stored.ID,
		"project_authorization_created", nil, stored.Roles, 0, stored.Version, "")
	return stored, nil
}

// AddAuthorizationRoles adds roles to a project authorization and records the
// before/after difference.
func (b *Boundary) AddAuthorizationRoles(ctx context.Context, authorizationID string, roles ...string) (*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	before, after, record, version, err := b.store.ModifyAuthorizationRoles(ctx, instanceID, authorizationID, roles, nil)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, record.SubjectID)
	b.writeChangeAudit(ctx, instanceID, record.SubjectID, record.ProjectID, record.OrgID, authorizationID, "roles_added", before, after, 0, version, "")
	return record, nil
}

// RemoveAuthorizationRoles removes roles from a project authorization.
func (b *Boundary) RemoveAuthorizationRoles(ctx context.Context, authorizationID string, roles ...string) (*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	before, after, record, version, err := b.store.ModifyAuthorizationRoles(ctx, instanceID, authorizationID, nil, roles)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, record.SubjectID)
	b.writeChangeAudit(ctx, instanceID, record.SubjectID, record.ProjectID, record.OrgID, authorizationID, "roles_removed", before, after, 0, version, "")
	return record, nil
}

// DeleteAuthorization removes a project authorization.
func (b *Boundary) DeleteAuthorization(ctx context.Context, authorizationID string) (*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	record, err := b.store.DeleteAuthorization(ctx, instanceID, authorizationID)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, record.SubjectID)
	b.writeChangeAudit(ctx, instanceID, record.SubjectID, record.ProjectID, record.OrgID, record.ID, "project_authorization_deleted", record.Roles, []string{}, 0, record.Version, "")
	return record, nil
}

// SetProjectGrantActive revokes or restores a project grant. Revocation makes
// linked granted roles disappear on the next version check.
func (b *Boundary) SetProjectGrantActive(ctx context.Context, grantID string, active bool) error {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return err
	}
	if b.store == nil {
		return NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	grant, subjects, err := b.store.SetProjectGrantActive(ctx, instanceID, grantID, active)
	if err != nil {
		return err
	}
	action := "project_grant_activated"
	if !active {
		action = "project_grant_revoked"
	}
	for _, subjectID := range subjects {
		_ = b.resolver.Invalidate(ctx, subjectID)
		b.writeChangeAudit(ctx, instanceID, subjectID, grant.ProjectID, grant.GrantedOrganizationID,
			grant.ID, action, nil, nil, 0, 0, "")
	}
	return nil
}

// DeleteProjectGrant removes a project grant; subsequent resolution reports
// the linked authorization source as missing.
func (b *Boundary) DeleteProjectGrant(ctx context.Context, grantID string) error {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return err
	}
	if b.store == nil {
		return NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	grant, subjects, err := b.store.DeleteProjectGrant(ctx, instanceID, grantID)
	if err != nil {
		return err
	}
	for _, subjectID := range subjects {
		_ = b.resolver.Invalidate(ctx, subjectID)
		b.writeChangeAudit(ctx, instanceID, subjectID, grant.ProjectID, grant.GrantedOrganizationID,
			grant.ID, "project_grant_deleted", nil, nil, 0, 0, "")
	}
	return nil
}

// RemoveMembership removes an organization or project membership.
func (b *Boundary) RemoveMembership(ctx context.Context, membershipID string) (*MembershipRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if b.store == nil {
		return nil, NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	record, err := b.store.RemoveMembership(ctx, instanceID, membershipID)
	if err != nil {
		return nil, err
	}
	_ = b.resolver.Invalidate(ctx, record.SubjectID)
	b.writeChangeAudit(ctx, instanceID, record.SubjectID, record.ProjectID, record.OrgID, record.ID, "membership_removed", record.Roles, []string{}, 0, 0, "")
	return record, nil
}

// SetOrganizationActive deactivates/reactivates an organization.
func (b *Boundary) SetOrganizationActive(ctx context.Context, organizationID string, active bool) error {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return err
	}
	if b.store == nil {
		return NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	subjects, err := b.store.SetOrganizationActive(ctx, instanceID, organizationID, active)
	if err != nil {
		return err
	}
	action := "organization_activated"
	if !active {
		action = "organization_deactivated"
	}
	for _, subjectID := range subjects {
		_ = b.resolver.Invalidate(ctx, subjectID)
		b.writeChangeAudit(ctx, instanceID, subjectID, "", organizationID, organizationID, action, nil, nil, 0, 0, "")
	}
	return nil
}

// SetProjectActive deactivates/reactivates a project.
func (b *Boundary) SetProjectActive(ctx context.Context, projectID string, active bool) error {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return err
	}
	if b.store == nil {
		return NewError(CodeInvalidRequest, "memory administration is not wired")
	}
	subjects, err := b.store.SetProjectActive(ctx, instanceID, projectID, active)
	if err != nil {
		return err
	}
	action := "project_activated"
	if !active {
		action = "project_deactivated"
	}
	for _, subjectID := range subjects {
		_ = b.resolver.Invalidate(ctx, subjectID)
		b.writeChangeAudit(ctx, instanceID, subjectID, projectID, "", projectID, action, nil, nil, 0, 0, "")
	}
	return nil
}

// GetAuthorizationRecord reads one instance-scoped authorization record.
func (b *Boundary) GetAuthorizationRecord(ctx context.Context, authorizationID string) (*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	recordRepo, ok := b.repo.(RecordRepository)
	if !ok {
		return nil, NewError(CodeInvalidRequest, "repository does not support record reads")
	}
	return recordRepo.GetAuthorizationRecord(ctx, instanceID, authorizationID)
}

// ListAuthorizationRecords lists instance-scoped authorization records.
func (b *Boundary) ListAuthorizationRecords(ctx context.Context, filter AuthorizationListFilter) ([]*AuthorizationRecord, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	recordRepo, ok := b.repo.(RecordRepository)
	if !ok {
		return nil, NewError(CodeInvalidRequest, "repository does not support record listing")
	}
	return recordRepo.ListAuthorizationRecords(ctx, instanceID, filter)
}

func (b *Boundary) writeChangeAudit(ctx context.Context, instanceID, rawSubjectID, projectID, orgID, sourceID, action string, before, after []string, fromVersion, toVersion uint64, eventID string) {
	pseudo := SubjectPseudonym(b.cfg.PseudonymSecret, instanceID, rawSubjectID)
	event := AuditEvent{
		Kind:             AuditKindChange,
		InstanceID:       instanceID,
		SubjectPseudonym: pseudo,
		Operation:        action,
		ProjectID:        projectID,
		OrganizationID:   orgID,
		BeforeRoles:      append([]string(nil), before...),
		AfterRoles:       append([]string(nil), after...),
		Roles:            append([]string(nil), after...),
		FromVersion:      fromVersion,
		ToVersion:        toVersion,
		EventID:          eventID,
	}
	if sourceID != "" {
		event.Sources = []Source{{Kind: SourceProjectAuthorization, ID: sourceID, ProjectID: projectID, OrgID: orgID}}
	}
	_ = b.writeAudit(ctx, &event)
}

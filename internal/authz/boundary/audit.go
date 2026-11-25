package boundary

import (
	"context"
	"sort"
	"sync"
	"time"
)

// AuditKind identifies the record category.
type AuditKind string

const (
	AuditKindDecision    AuditKind = "decision"
	AuditKindConvergence AuditKind = "convergence"
	AuditKindChange      AuditKind = "authorization_change"
)

// AuditEvent is the queryable authorization audit record.
//
// It contains instance and irreversible subject identifiers, project scope,
// before/after role sets, source trace and versions. It must never contain
// raw access tokens, signing secrets, ciphertext or password material.
type AuditEvent struct {
	ID                        string              `json:"id"`
	Kind                      AuditKind           `json:"kind"`
	Time                      time.Time           `json:"time"`
	InstanceID                string              `json:"instanceId"`
	SubjectPseudonym          string              `json:"subjectPseudonym,omitempty"`
	TokenPseudonym            string              `json:"tokenPseudonym,omitempty"`
	CallerID                  string              `json:"callerId,omitempty"`
	Operation                 string              `json:"operation"`
	ProjectID                 string              `json:"projectId,omitempty"`
	OrganizationID            string              `json:"organizationId,omitempty"`
	Action                    string              `json:"action,omitempty"`
	Allowed                   *bool               `json:"allowed,omitempty"`
	ReasonCode                Code                `json:"reasonCode,omitempty"`
	BeforeRoles               []string            `json:"beforeRoles"`
	AfterRoles                []string            `json:"afterRoles"`
	Roles                     []string            `json:"roles"`
	Permissions               []string            `json:"permissions,omitempty"`
	Sources                   []Source            `json:"sources,omitempty"`
	FromVersion               uint64              `json:"fromVersion,omitempty"`
	ToVersion                 uint64              `json:"toVersion,omitempty"`
	AuthorizationVersion      uint64              `json:"authorizationVersion,omitempty"`
	TokenAuthorizationVersion uint64              `json:"tokenAuthorizationVersion,omitempty"`
	Strategy                  ConvergenceStrategy `json:"strategy,omitempty"`
	ConvergenceAction         string              `json:"convergenceAction,omitempty"`
	ConvergenceWindow         time.Duration       `json:"convergenceWindowNs,omitempty"`
	ConvergenceElapsed        time.Duration       `json:"convergenceElapsedNs,omitempty"`
	WithinWindow              bool                `json:"withinWindow,omitempty"`
	EventID                   string              `json:"eventId,omitempty"`
}

// AuditSink persists audit events.
type AuditSink interface {
	Audit(ctx context.Context, event AuditEvent) error
}

// AuditFilter queries the in-memory audit log. Empty fields do not filter.
type AuditFilter struct {
	InstanceID       string
	SubjectPseudonym string
	ProjectID        string
	Kind             AuditKind
	Operation        string
	ReasonCode       Code
	Allowed          *bool
}

// MemoryAuditLog is an in-memory AuditSink and query API.
type MemoryAuditLog struct {
	mu     sync.RWMutex
	events []AuditEvent
	next   int
}

var _ AuditSink = (*MemoryAuditLog)(nil)

func NewMemoryAuditLog() *MemoryAuditLog {
	return &MemoryAuditLog{}
}

func (l *MemoryAuditLog) Audit(_ context.Context, event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	if event.ID == "" {
		event.ID = "audit-" + time.Now().UTC().Format("20060102T150405.000000000") + "-" + itoa(l.next)
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
	l.events = append(l.events, event)
	return nil
}

// Query returns matching audit events in insertion order.
func (l *MemoryAuditLog) Query(filter AuditFilter) []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]AuditEvent, 0)
	for _, event := range l.events {
		if filter.InstanceID != "" && event.InstanceID != filter.InstanceID {
			continue
		}
		if filter.SubjectPseudonym != "" && event.SubjectPseudonym != filter.SubjectPseudonym {
			continue
		}
		if filter.ProjectID != "" && event.ProjectID != filter.ProjectID {
			continue
		}
		if filter.Kind != "" && event.Kind != filter.Kind {
			continue
		}
		if filter.Operation != "" && event.Operation != filter.Operation {
			continue
		}
		if filter.ReasonCode != "" && event.ReasonCode != filter.ReasonCode {
			continue
		}
		if filter.Allowed != nil && (event.Allowed == nil || *event.Allowed != *filter.Allowed) {
			continue
		}
		result = append(result, cloneAuditEvent(event))
	}
	return result
}

// Events returns all audit events in insertion order.
func (l *MemoryAuditLog) Events() []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]AuditEvent, len(l.events))
	for i, e := range l.events {
		result[i] = cloneAuditEvent(e)
	}
	return result
}

func cloneAuditEvent(e AuditEvent) AuditEvent {
	e.BeforeRoles = append([]string(nil), e.BeforeRoles...)
	e.AfterRoles = append([]string(nil), e.AfterRoles...)
	e.Roles = append([]string(nil), e.Roles...)
	e.Permissions = append([]string(nil), e.Permissions...)
	e.Sources = append([]Source(nil), e.Sources...)
	return e
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func sortedSources(snapshot *Snapshot) []Source {
	if snapshot == nil {
		return []Source{}
	}
	return mergeAuditSources(nil, func() []Source {
		sources := make([]Source, 0)
		for _, role := range snapshot.EffectiveRoles {
			sources = append(sources, role.Sources...)
		}
		return sources
	}())
}

func mergeAuditSources(groups ...[]Source) []Source {
	seen := make(map[string]Source)
	for _, group := range groups {
		for _, source := range group {
			key := string(source.Kind) + "|" + source.ID + "|" + source.ProjectID + "|" + source.OrgID
			seen[key] = source
		}
	}
	sources := make([]Source, 0, len(seen))
	for _, source := range seen {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Kind != sources[j].Kind {
			return sources[i].Kind < sources[j].Kind
		}
		if sources[i].ID != sources[j].ID {
			return sources[i].ID < sources[j].ID
		}
		return sources[i].ProjectID < sources[j].ProjectID
	})
	return sources
}

func boolPtr(v bool) *bool { return &v }

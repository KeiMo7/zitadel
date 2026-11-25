package boundary

import (
	"context"
	"errors"
	"sync"
	"time"
)

// CacheKey is always instance-scoped and uses the irreversible subject
// pseudonym rather than the raw subject identifier.
type CacheKey struct {
	InstanceID       string
	SubjectPseudonym string
}

// SnapshotCache is the reuse boundary for full authorization resolutions.
type SnapshotCache interface {
	Get(key CacheKey) (*Snapshot, bool, error)
	Set(snapshot *Snapshot) error
	Invalidate(key CacheKey)
}

// MemorySnapshotCache is the default concurrency-safe cache.
type MemorySnapshotCache struct {
	mu      sync.RWMutex
	entries map[CacheKey]*Snapshot
	getErr  error
	setErr  error
}

var _ SnapshotCache = (*MemorySnapshotCache)(nil)

func NewMemorySnapshotCache() *MemorySnapshotCache {
	return &MemorySnapshotCache{entries: make(map[CacheKey]*Snapshot)}
}

func (c *MemorySnapshotCache) Get(key CacheKey) (*Snapshot, bool, error) {
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	snap, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	copySnap := *snap
	return &copySnap, true, nil
}

func (c *MemorySnapshotCache) Set(snapshot *Snapshot) error {
	if c.setErr != nil {
		return c.setErr
	}
	if snapshot == nil {
		return nil
	}
	key := CacheKey{InstanceID: snapshot.InstanceID, SubjectPseudonym: snapshot.SubjectPseudonym}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = snapshot
	return nil
}

func (c *MemorySnapshotCache) Invalidate(key CacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// SetFaults injects cache availability failures.
func (c *MemorySnapshotCache) SetFaults(getErr, setErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getErr = getErr
	c.setErr = setErr
}

// Resolver is the single authorization parsing entry used by all four paths.
type Resolver struct {
	repo       Repository
	cache      SnapshotCache
	secret     []byte
	now        func() time.Time
	catalog    map[string][]string
	priorities map[SourceKind]int
}

// NewResolver constructs a Resolver. Config is normalized when necessary.
func NewResolver(cfg Config, repo Repository, cache SnapshotCache) (*Resolver, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, NewError(CodeInvalidRequest, "authorization repository is required")
	}
	if cache == nil {
		cache = NewMemorySnapshotCache()
	}
	return &Resolver{
		repo:       repo,
		cache:      cache,
		secret:     cfg.PseudonymSecret,
		now:        cfg.Now,
		catalog:    cfg.RolePermissions,
		priorities: cfg.SourcePriorities,
	}, nil
}

// Resolve returns the current effective authorization snapshot for subjectID.
//
// The instance is taken from ctx and is mandatory. A cheap version read is
// performed on every call; full source resolution happens only on a version
// mismatch/cache miss.
func (r *Resolver) Resolve(ctx context.Context, subjectID string) (*Snapshot, error) {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return nil, err
	}
	if subjectID == "" {
		return nil, NewError(CodeInvalidRequest, "subject identifier is required")
	}
	pseudonym := SubjectPseudonym(r.secret, instanceID, subjectID)
	key := CacheKey{InstanceID: instanceID, SubjectPseudonym: pseudonym}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		version, changedAt, err := r.repo.CurrentVersion(ctx, instanceID, subjectID)
		if err != nil {
			return nil, ErrFreshnessUnavailable
		}

		cached, ok, err := r.cache.Get(key)
		if err != nil {
			return nil, ErrFreshnessUnavailable
		}
		if ok && cached != nil && cached.InstanceID == instanceID && cached.Version == version {
			return cached, nil
		}

		data, err := r.repo.LoadAuthorization(ctx, instanceID, subjectID)
		if err != nil {
			// Preserve stable source-integrity classifications. Arbitrary
			// storage errors are sanitized by the caller-facing boundary.
			var boundaryErr *Error
			if errors.As(err, &boundaryErr) {
				return nil, boundaryErr
			}
			return nil, ErrFreshnessUnavailable
		}
		if data == nil {
			return nil, ErrFreshnessUnavailable
		}
		// A mutation may have committed between version read and load. Retry
		// so the returned snapshot can never carry an old version label.
		if data.Version != version {
			continue
		}

		snapshot := mergeBindings(
			instanceID,
			pseudonym,
			version,
			changedAtOr(data.ChangedAt, changedAt),
			r.now(),
			data.Bindings,
			r.catalog,
			r.priorities,
		)
		if err := r.cache.Set(snapshot); err != nil {
			return nil, ErrFreshnessUnavailable
		}
		return snapshot, nil
	}
	return nil, ErrFreshnessUnavailable
}

// Invalidate removes the subject's instance-scoped cache entry. Version checks
// already guarantee immediate convergence; this is used after local writes to
// make invalidation deterministic without waiting for any external cache TTL.
func (r *Resolver) Invalidate(ctx context.Context, subjectID string) error {
	instanceID, err := requireInstance(ctx)
	if err != nil {
		return err
	}
	r.cache.Invalidate(CacheKey{
		InstanceID:       instanceID,
		SubjectPseudonym: SubjectPseudonym(r.secret, instanceID, subjectID),
	})
	return nil
}

func changedAtOr(primary, fallback time.Time) time.Time {
	if !primary.IsZero() {
		return primary
	}
	return fallback
}

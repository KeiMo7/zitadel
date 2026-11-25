package boundary

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

type instanceContextKey struct{}

// WithInstance binds the resolved request instance to ctx.
//
// In production the instance must be resolved from the request domain before
// this boundary is called. This package intentionally has no fallback to a
// default instance.
func WithInstance(ctx context.Context, instanceID string) context.Context {
	return context.WithValue(ctx, instanceContextKey{}, strings.TrimSpace(instanceID))
}

// InstanceFromContext returns the request's instance boundary.
func InstanceFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	id, _ := ctx.Value(instanceContextKey{}).(string)
	id = strings.TrimSpace(id)
	return id, id != ""
}

func requireInstance(ctx context.Context) (string, error) {
	id, ok := InstanceFromContext(ctx)
	if !ok {
		return "", ErrInstanceMissing
	}
	return id, nil
}

const pseudonymVersion = "zitadel-authz-boundary/pseudonym/v1"

// Pseudonym returns an irreversible, keyed correlation identifier.
//
// HMAC is used so pseudonyms remain queryable/correlatable by operators but
// raw user identifiers are not written to audit records, errors or logs.
func Pseudonym(secret []byte, parts ...string) string {
	key := secret
	if len(key) == 0 {
		// A non-empty domain-separated fallback keeps zero Config usable in
		// tests. Deployments should configure PseudonymSecret.
		key = []byte("zitadel-dev-authz-boundary-pseudonym")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(pseudonymVersion + "\n"))
	for _, part := range parts {
		length := uint64(len(part))
		var buf [8]byte
		buf[0] = byte(length >> 56)
		buf[1] = byte(length >> 48)
		buf[2] = byte(length >> 40)
		buf[3] = byte(length >> 32)
		buf[4] = byte(length >> 24)
		buf[5] = byte(length >> 16)
		buf[6] = byte(length >> 8)
		buf[7] = byte(length)
		_, _ = mac.Write(buf[:])
		_, _ = mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SubjectPseudonym namespaces the irreversible subject identifier by instance.
// This also prevents a pseudonym from being correlated across instances.
func SubjectPseudonym(secret []byte, instanceID, subjectID string) string {
	return Pseudonym(secret, "subject", instanceID, subjectID)
}

func tokenPseudonym(secret []byte, rawToken string) string {
	return Pseudonym(secret, "access-token", rawToken)
}

// Package boundary implements the instance-scoped authorization resolution
// and access-token convergence boundary used by protected APIs, user info,
// OIDC introspection and permission inventory reads.
//
// The package is deliberately storage-agnostic. Repository is the minimal
// persistence contract and MemoryStore is the deterministic in-memory
// implementation used by tests and local development.
package boundary

import (
	"fmt"
)

// Code is the stable, machine-readable error classification.
type Code string

const (
	CodeInvalidRequest              Code = "invalid_request"
	CodeInstanceMissing             Code = "instance_missing"
	CodeInstanceMismatch            Code = "instance_context_mismatch"
	CodeNotFound                    Code = "authorization_not_found"
	CodeTokenMalformed              Code = "token_malformed"
	CodeSignatureInvalid            Code = "token_signature_invalid"
	CodeTokenExpired                Code = "token_expired"
	CodeTokenInstanceMismatch       Code = "token_instance_mismatch"
	CodeSigningKeyUnavailable       Code = "token_signing_key_unavailable"
	CodeLegacyTokenDenied           Code = "legacy_token_without_authz_version_denied"
	CodeStaleAuthorization          Code = "stale_authorization"
	CodeFreshnessUnavailable        Code = "authorization_freshness_unavailable"
	CodeAuthorizationUnavailable    Code = "authorization_unavailable"
	CodeAuthorizationSourceMissing  Code = "authorization_source_missing"
	CodeAuthorizationSourceConflict Code = "authorization_source_conflict"
	CodeVersionRollback             Code = "authorization_version_rollback"
	CodePermissionDenied            Code = "permission_denied"
	CodeAuditUnavailable            Code = "audit_unavailable"
)

// Error is the sanitized error type returned by the boundary.
//
// Error messages are safe for API responses and logs. In particular, they
// never contain token values, signing/key material, passwords or raw storage
// errors.
type Error struct {
	Code    Code
	Message string
}

func NewError(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

// Is enables errors.Is(err, ErrInstanceMissing) even when a returned error
// carries additional request-specific detail.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.Code == t.Code
}

var (
	ErrInstanceMissing       = NewError(CodeInstanceMissing, "request has no instance boundary; refusing unscoped authorization query")
	ErrInstanceMismatch      = NewError(CodeInstanceMismatch, "instance in context does not match the requested instance")
	ErrNotFound              = NewError(CodeNotFound, "authorization record was not found in this instance")
	ErrTokenMalformed        = NewError(CodeTokenMalformed, "access token is malformed")
	ErrSignatureInvalid      = NewError(CodeSignatureInvalid, "access token signature does not match the owning instance key")
	ErrTokenExpired          = NewError(CodeTokenExpired, "access token is expired")
	ErrTokenInstanceMismatch = NewError(CodeTokenInstanceMismatch, "access token was issued by another instance")
	ErrSigningKeyUnavailable = NewError(CodeSigningKeyUnavailable, "no signing key is available for the token owning instance")
	ErrStaleAuthorization    = NewError(CodeStaleAuthorization, "access token carries stale authorization and the convergence policy invalidates it")
	ErrLegacyTokenDenied     = NewError(CodeLegacyTokenDenied, "legacy access token without authorization version is denied by configuration")
	ErrFreshnessUnavailable  = NewError(CodeFreshnessUnavailable, "unable to confirm authorization is current")
	ErrSourceMissing         = NewError(CodeAuthorizationSourceMissing, "one or more authorization sources are missing; refusing to treat empty permissions as success")
	ErrSourceConflict        = NewError(CodeAuthorizationSourceConflict, "authorization sources are contradictory; refusing to merge")
	ErrVersionRollback       = NewError(CodeVersionRollback, "refusing to apply an older authorization version")
	ErrPermissionDenied      = NewError(CodePermissionDenied, "permission is not granted")
	ErrAuditUnavailable      = NewError(CodeAuditUnavailable, "authorization decision could not be audited")
)

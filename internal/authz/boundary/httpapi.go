package boundary

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// InstanceResolver adapts ZITADEL's existing domain-based instance resolution
// to the boundary context. Production implementations must resolve the
// instance from the request domain; tests may use a header-backed resolver.
type InstanceResolver func(r *http.Request) (string, error)

// Handler exposes the four boundary paths over HTTP:
//
//	POST /authz/authorize       protected interface PEP
//	GET  /authz/userinfo        user info path
//	POST /authz/introspect      OIDC introspection-compatible path
//	GET  /authz/permissions     permission inventory path
//
// These are optional reference adapters. Existing ZITADEL transports can call
// the same Boundary methods directly without mounting this mux.
func (b *Boundary) Handler(resolveInstance InstanceResolver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authz/authorize", b.handleAuthorize)
	mux.HandleFunc("GET /authz/userinfo", b.handleUserInfo)
	mux.HandleFunc("POST /authz/introspect", b.handleIntrospect)
	mux.HandleFunc("GET /authz/permissions", b.handlePermissions)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, ok := InstanceFromContext(ctx); !ok && resolveInstance != nil {
			instanceID, err := resolveInstance(r)
			if err != nil || instanceID == "" {
				writeBoundaryError(w, ErrInstanceMissing)
				return
			}
			ctx = WithInstance(ctx, instanceID)
			r = r.WithContext(ctx)
		}
		mux.ServeHTTP(w, r)
	})
}

type authorizeHTTPRequest struct {
	Action   string   `json:"action"`
	Resource Resource `json:"resource"`
}

func (b *Boundary) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeBoundaryError(w, NewError(CodeTokenMalformed, "missing bearer token"))
		return
	}
	var req authorizeHTTPRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBoundaryError(w, NewError(CodeInvalidRequest, "invalid JSON request body"))
			return
		}
	}
	decision, err := b.Authorize(r.Context(), token, AccessRequest(req))
	if decision != nil {
		status := http.StatusOK
		if !decision.Allowed {
			status = http.StatusForbidden
		}
		writeJSON(w, status, decision)
		return
	}
	writeBoundaryError(w, err)
}

func (b *Boundary) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeBoundaryError(w, NewError(CodeTokenMalformed, "missing bearer token"))
		return
	}
	resp, err := b.UserInfo(r.Context(), token)
	if err != nil {
		writeBoundaryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Boundary) handlePermissions(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok {
		writeBoundaryError(w, NewError(CodeTokenMalformed, "missing bearer token"))
		return
	}
	resp, err := b.ListMyPermissions(r.Context(), token)
	if err != nil {
		writeBoundaryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Boundary) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeBoundaryError(w, NewError(CodeInvalidRequest, "invalid form body"))
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		writeBoundaryError(w, NewError(CodeInvalidRequest, "token form field is required"))
		return
	}
	callerID := r.PostForm.Get("client_id")
	if username, _, ok := r.BasicAuth(); ok && username != "" {
		callerID = username
	}
	resp, err := b.Introspect(r.Context(), token, callerID)
	if err != nil {
		writeBoundaryError(w, err)
		return
	}
	// OAuth2 introspection represents inactive tokens as a normal 200 body
	// with active=false; ReasonCode is an internal extension for operators.
	writeJSON(w, http.StatusOK, resp)
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return strings.TrimSpace(parts[1]), true
}

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func writeBoundaryError(w http.ResponseWriter, err error) {
	var boundaryErr *Error
	if !errors.As(err, &boundaryErr) {
		boundaryErr = ErrFreshnessUnavailable
	}
	writeJSON(w, httpStatusForCode(boundaryErr.Code), errorBody{Error: errorPayload{Code: boundaryErr.Code, Message: boundaryErr.Message}})
}

func httpStatusForCode(code Code) int {
	switch code {
	case CodeInvalidRequest, CodeTokenMalformed:
		return http.StatusBadRequest
	case CodeInstanceMissing, CodeInstanceMismatch:
		return http.StatusBadRequest
	case CodeSignatureInvalid, CodeTokenExpired, CodeTokenInstanceMismatch,
		CodeLegacyTokenDenied, CodeStaleAuthorization:
		return http.StatusUnauthorized
	case CodePermissionDenied:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeVersionRollback, CodeAuthorizationSourceConflict:
		return http.StatusConflict
	case CodeFreshnessUnavailable, CodeAuthorizationUnavailable,
		CodeAuthorizationSourceMissing, CodeSigningKeyUnavailable, CodeAuditUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

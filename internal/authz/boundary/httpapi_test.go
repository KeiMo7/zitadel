package boundary_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/zitadel/internal/authz/boundary"
)

func TestHTTPFourPathsAndCrossInstanceClassification(t *testing.T) {
	f := newFixture(t, nil)
	token, err := f.b.IssueToken(f.ctxA, subject1)
	must(t, err)
	handler := f.b.Handler(func(r *http.Request) (string, error) {
		return r.Header.Get("X-Test-Instance"), nil
	})

	// User info.
	req := httptest.NewRequest(http.MethodGet, "/authz/userinfo", nil)
	req.Header.Set("X-Test-Instance", instanceA)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d body=%s", rec.Code, rec.Body.String())
	}
	var userInfo boundary.UserInfoResponse
	must(t, json.Unmarshal(rec.Body.Bytes(), &userInfo))

	// Permission inventory.
	req = httptest.NewRequest(http.MethodGet, "/authz/permissions", nil)
	req.Header.Set("X-Test-Instance", instanceA)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("permissions status=%d body=%s", rec.Code, rec.Body.String())
	}
	var inventory boundary.PermissionInventory
	must(t, json.Unmarshal(rec.Body.Bytes(), &inventory))

	// Protected interface allow decision.
	body := bytes.NewBufferString(`{"action":"project.read","resource":{"projectId":"proj-a","organizationId":"org-a"}}`)
	req = httptest.NewRequest(http.MethodPost, "/authz/authorize", body)
	req.Header.Set("X-Test-Instance", instanceA)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	var allowed boundary.Decision
	must(t, json.Unmarshal(rec.Body.Bytes(), &allowed))
	if !allowed.Allowed || !reflect.DeepEqual(allowed.Authority, userInfo.Authority) || !reflect.DeepEqual(allowed.Authority, inventory.Authority) {
		t.Fatalf("protected/userinfo/inventory authorities differ: %+v %+v %+v", allowed.Authority, userInfo.Authority, inventory.Authority)
	}

	// Protected interface deny decision remains an explicit 403 body.
	body = bytes.NewBufferString(`{"action":"project.write","resource":{"projectId":"proj-a","organizationId":"org-a"}}`)
	req = httptest.NewRequest(http.MethodPost, "/authz/authorize", body)
	req.Header.Set("X-Test-Instance", instanceA)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("write status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}

	// OIDC introspection form path.
	form := url.Values{"token": {token}, "client_id": {"client-1"}}
	req = httptest.NewRequest(http.MethodPost, "/authz/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("X-Test-Instance", instanceA)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("introspect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var intro boundary.IntrospectionResponse
	must(t, json.Unmarshal(rec.Body.Bytes(), &intro))
	if !intro.Active || intro.Authority == nil || !reflect.DeepEqual(*intro.Authority, userInfo.Authority) {
		t.Fatalf("introspection authority mismatch: %+v vs %+v", intro.Authority, userInfo.Authority)
	}

	// Cross-instance use is 401 on userinfo with a precise code.
	req = httptest.NewRequest(http.MethodGet, "/authz/userinfo", nil)
	req.Header.Set("X-Test-Instance", instanceB)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), string(boundary.CodeTokenInstanceMismatch)) {
		t.Fatalf("cross-instance userinfo status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Standard introspection still returns active=false with the internal reason.
	form = url.Values{"token": {token}}
	req = httptest.NewRequest(http.MethodPost, "/authz/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("X-Test-Instance", instanceB)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cross-instance introspection status=%d body=%s", rec.Code, rec.Body.String())
	}
	var crossIntro boundary.IntrospectionResponse
	must(t, json.Unmarshal(rec.Body.Bytes(), &crossIntro))
	if crossIntro.Active || crossIntro.ReasonCode != boundary.CodeTokenInstanceMismatch {
		t.Fatalf("cross-instance introspection = %+v", crossIntro)
	}

	// Missing instance fails closed even before token parsing.
	req = httptest.NewRequest(http.MethodGet, "/authz/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), string(boundary.CodeInstanceMissing)) {
		t.Fatalf("missing instance status=%d body=%s", rec.Code, rec.Body.String())
	}
}

package boundary

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const tokenPrefix = "zab1"

// Claims are the signed metadata carried by the built-in access token.
//
// AuthzVersion is the staleness marker. InstanceID identifies the owning
// instance and enables a precise cross-instance rejection reason. The
// roles/permissions are signed informational claims; enforcement always uses
// the Resolver result after convergence.
type Claims struct {
	Issuer       string   `json:"iss,omitempty"`
	Subject      string   `json:"sub"`
	InstanceID   string   `json:"instance_id"`
	TokenID      string   `json:"jti"`
	AuthzVersion uint64   `json:"authz_version,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Sources      []Source `json:"sources,omitempty"`
	IssuedAt     int64    `json:"iat"`
	ExpiresAt    int64    `json:"exp"`
	NotBefore    int64    `json:"nbf,omitempty"`
}

// TokenService issues and verifies instance-bound HMAC test/reference tokens.
//
// Production ZITADEL keeps its existing JWT/OIDC verification path and key
// management. This type is the in-memory implementation used to exercise the
// boundary without a database or external service.
type TokenService struct {
	instanceKeys  map[string][]byte
	signingSecret []byte
	now           func() time.Time
	ttl           time.Duration
}

func NewTokenService(cfg Config) *TokenService {
	cfg, _ = cfg.withDefaults()
	keys := make(map[string][]byte, len(cfg.InstanceKeys))
	for k, v := range cfg.InstanceKeys {
		keys[k] = append([]byte(nil), v...)
	}
	secret := append([]byte(nil), cfg.SigningSecret...)
	if len(secret) == 0 {
		// A fallback derivation key lets the in-memory issuer support
		// dynamically created test instances. Explicit InstanceKeys still
		// take precedence for known instances.
		secret = randomSecret()
	}
	return &TokenService{
		instanceKeys:  keys,
		signingSecret: secret,
		now:           cfg.Now,
		ttl:           cfg.TokenTTL,
	}
}

func randomSecret() []byte {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read is documented to always fill the buffer and return nil in
		// supported environments. Keep a deterministic fallback only for the
		// impossible failure case.
		return []byte("zitadel-boundary-insecure-fallback-key")
	}
	return buf
}

func (t *TokenService) keyForInstance(instanceID string) ([]byte, bool) {
	if key, ok := t.instanceKeys[instanceID]; ok && len(key) > 0 {
		return key, true
	}
	if len(t.signingSecret) > 0 {
		mac := hmac.New(sha256.New, t.signingSecret)
		_, _ = mac.Write([]byte("zitadel-authz-boundary/instance-token-key/v1\x00"))
		_, _ = mac.Write([]byte(instanceID))
		return mac.Sum(nil), true
	}
	return nil, false
}

// Issue creates a signed token. Claims.InstanceID and Claims.Subject must be
// supplied by the caller/Boundary.
func (t *TokenService) Issue(claims Claims) (string, error) {
	if claims.InstanceID == "" || claims.Subject == "" {
		return "", NewError(CodeInvalidRequest, "instance and subject are required to issue a token")
	}
	now := t.now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(t.ttl).Unix()
	}
	if claims.TokenID == "" {
		claims.TokenID = randomTokenID()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", NewError(CodeInvalidRequest, "token claims cannot be encoded")
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := tokenPrefix + "." + encodedPayload
	key, ok := t.keyForInstance(claims.InstanceID)
	if !ok {
		return "", ErrSigningKeyUnavailable
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

// Verify validates structure, signature using the token owner's instance key,
// instance boundary and expiry.
func (t *TokenService) Verify(ctx context.Context, requestInstanceID, rawToken string) (*Claims, error) {
	if requestInstanceID == "" {
		return nil, ErrInstanceMissing
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return nil, ErrTokenMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTokenMalformed
	}
	if claims.InstanceID == "" {
		// Historical token: verify against the domain-resolved request
		// instance key, preserving the legacy verification path.
		claims.InstanceID = requestInstanceID
	}
	key, ok := t.keyForInstance(claims.InstanceID)
	if !ok {
		return nil, NewError(CodeSigningKeyUnavailable, "no signing key for token owning instance")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, ErrSignatureInvalid
	}

	// Signature is now trusted. Check the owning instance before expiry so a
	// cross-instance token has a stable, distinguishable classification.
	if claims.InstanceID != requestInstanceID {
		return nil, ErrTokenInstanceMismatch
	}
	now := t.now().Unix()
	if claims.NotBefore > 0 && now < claims.NotBefore {
		return nil, NewError(CodeTokenMalformed, "token is not yet valid")
	}
	if claims.ExpiresAt > 0 && now >= claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	_ = ctx
	return &claims, nil
}

func randomTokenID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

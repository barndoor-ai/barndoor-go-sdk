package barndoor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OidcConfig holds the OIDC discovery configuration.
type OidcConfig struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

var (
	oidcConfigCache   = make(map[string]*OidcConfig)
	oidcConfigCacheMu sync.RWMutex
)

// GetOidcConfig fetches and caches OIDC configuration from the issuer's discovery endpoint.
func GetOidcConfig(ctx context.Context, issuer string) (*OidcConfig, error) {
	oidcConfigCacheMu.RLock()
	if cfg, ok := oidcConfigCache[issuer]; ok {
		oidcConfigCacheMu.RUnlock()
		return cfg, nil
	}
	oidcConfigCacheMu.RUnlock()

	normalizedIssuer := strings.TrimRight(issuer, "/")
	discoveryURL := normalizedIssuer + "/.well-known/openid-configuration"

	logger := createScopedLogger("auth")

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return oidcFallback(normalizedIssuer, logger), nil
	}

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL derived from SDK config issuer
	if err != nil {
		logger.Warn(fmt.Sprintf("OIDC discovery failed for %s: %v", issuer, err))
		return oidcFallback(normalizedIssuer, logger), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn(fmt.Sprintf("OIDC discovery failed for %s: HTTP %d", issuer, resp.StatusCode))
		return oidcFallback(normalizedIssuer, logger), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oidcFallback(normalizedIssuer, logger), nil
	}

	var config OidcConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return oidcFallback(normalizedIssuer, logger), nil
	}

	// Validate that the discovery response contains the required endpoints.
	// An incomplete response (e.g. missing authorization_endpoint) would produce
	// broken auth URLs, so fall back to well-known endpoint patterns instead.
	if config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" {
		logger.Warn(fmt.Sprintf("OIDC discovery for %s returned incomplete config, using fallback", issuer))
		return oidcFallback(normalizedIssuer, logger), nil
	}

	oidcConfigCacheMu.Lock()
	oidcConfigCache[issuer] = &config
	oidcConfigCacheMu.Unlock()

	logger.Debug(fmt.Sprintf("OIDC discovery successful for %s", issuer))
	return &config, nil
}

// oidcFallback returns a fallback OIDC config based on issuer URL patterns.
func oidcFallback(normalizedIssuer string, logger Logger) *OidcConfig {
	normalizedIssuer = strings.TrimRight(normalizedIssuer, "/")
	logger.Debug(fmt.Sprintf("Using OIDC fallback for %s", normalizedIssuer))
	if strings.Contains(normalizedIssuer, "/realms/") {
		// Keycloak-style issuer
		return &OidcConfig{
			Issuer:                normalizedIssuer,
			TokenEndpoint:         normalizedIssuer + "/protocol/openid-connect/token",
			AuthorizationEndpoint: normalizedIssuer + "/protocol/openid-connect/auth",
			UserinfoEndpoint:      normalizedIssuer + "/protocol/openid-connect/userinfo",
			JWKSURI:               normalizedIssuer + "/protocol/openid-connect/certs",
		}
	}
	// Auth0/generic OIDC provider
	return &OidcConfig{
		Issuer:                normalizedIssuer,
		TokenEndpoint:         normalizedIssuer + "/oauth/token",
		AuthorizationEndpoint: normalizedIssuer + "/authorize",
		UserinfoEndpoint:      normalizedIssuer + "/userinfo",
		JWKSURI:               normalizedIssuer + "/.well-known/jwks.json",
	}
}

// ClearOidcConfigCache clears the OIDC config cache.
func ClearOidcConfigCache() {
	oidcConfigCacheMu.Lock()
	oidcConfigCache = make(map[string]*OidcConfig)
	oidcConfigCacheMu.Unlock()
}

// JWTVerificationResult represents the result of JWT verification.
type JWTVerificationResult int

const (
	JWTValid   JWTVerificationResult = iota
	JWTExpired
	JWTInvalid
)

// JWKS cache
var (
	jwksCache   = make(map[string]*jwksKeySet)
	jwksCacheMu sync.RWMutex
)

type jwksKeySet struct {
	keys    json.RawMessage
	fetched time.Time
}

// VerifyJWTLocal verifies a JWT token locally using JWKS.
// It returns the verification result.
func VerifyJWTLocal(ctx context.Context, tokenString, issuer, audience string) JWTVerificationResult {
	logger := createScopedLogger("token")

	oidcConfig, err := GetOidcConfig(ctx, issuer)
	if err != nil || oidcConfig.JWKSURI == "" {
		logger.Debug("No JWKS URI available for local verification")
		return JWTInvalid
	}

	// Fetch JWKS
	keyFunc, err := getJWKSKeyFunc(ctx, oidcConfig.JWKSURI)
	if err != nil {
		logger.Debug(fmt.Sprintf("Failed to get JWKS: %v", err))
		return JWTInvalid
	}

	expectedIssuer := strings.TrimRight(issuer, "/") + "/"

	token, err := jwt.Parse(tokenString, keyFunc,
		jwt.WithIssuer(expectedIssuer),
		jwt.WithAudience(audience),
	)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			logger.Debug("Token expired (verified locally)")
			return JWTExpired
		}
		logger.Debug(fmt.Sprintf("JWT verification failed: %v", err))
		return JWTInvalid
	}

	if !token.Valid {
		return JWTInvalid
	}

	logger.Debug("Token verified locally using JWKS")
	return JWTValid
}

// getJWKSKeyFunc fetches JWKS and returns a jwt.Keyfunc.
func getJWKSKeyFunc(ctx context.Context, jwksURI string) (jwt.Keyfunc, error) {
	jwksCacheMu.RLock()
	cached, ok := jwksCache[jwksURI]
	jwksCacheMu.RUnlock()

	// Refresh JWKS every 5 minutes
	if ok && time.Since(cached.fetched) < 5*time.Minute {
		return makeKeyFunc(cached.keys), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery jwks_uri
	if err != nil {
		// Return cached if available on fetch failure
		if ok {
			return makeKeyFunc(cached.keys), nil
		}
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	jwksCacheMu.Lock()
	jwksCache[jwksURI] = &jwksKeySet{keys: json.RawMessage(body), fetched: time.Now()}
	jwksCacheMu.Unlock()

	return makeKeyFunc(json.RawMessage(body)), nil
}

// makeKeyFunc creates a jwt.Keyfunc from raw JWKS JSON.
func makeKeyFunc(jwksJSON json.RawMessage) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
			return nil, fmt.Errorf("failed to parse JWKS: %w", err)
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token header missing kid")
		}

		for _, rawKey := range jwks.Keys {
			var keyHeader struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				Alg string `json:"alg"`
			}
			if err := json.Unmarshal(rawKey, &keyHeader); err != nil {
				continue
			}
			if keyHeader.Kid == kid {
				// Use the jwt library's built-in key parsing
				return jwt.ParseRSAPublicKeyFromPEM(jwkToPEM(rawKey))
			}
		}

		return nil, fmt.Errorf("key with kid %q not found in JWKS", kid)
	}
}

// jwkToPEM converts a JWK to PEM format for RSA keys.
func jwkToPEM(rawKey json.RawMessage) []byte {
	var key struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(rawKey, &key); err != nil {
		return nil
	}

	if key.Kty != "RSA" {
		return nil
	}

	// Decode the modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil
	}

	// Build DER-encoded RSA public key
	der := buildRSAPublicKeyDER(nBytes, eBytes)

	// Encode as PEM
	pem := "-----BEGIN PUBLIC KEY-----\n"
	b64 := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		pem += b64[i:end] + "\n"
	}
	pem += "-----END PUBLIC KEY-----\n"

	return []byte(pem)
}

// buildRSAPublicKeyDER builds a DER-encoded SubjectPublicKeyInfo for RSA.
func buildRSAPublicKeyDER(n, e []byte) []byte {
	// Ensure n has leading zero if high bit set
	if len(n) > 0 && n[0]&0x80 != 0 {
		n = append([]byte{0}, n...)
	}
	// Ensure e has leading zero if high bit set
	if len(e) > 0 && e[0]&0x80 != 0 {
		e = append([]byte{0}, e...)
	}

	nASN1 := asn1Integer(n)
	eASN1 := asn1Integer(e)
	rsaKeySeq := asn1Sequence(append(nASN1, eASN1...))

	// Wrap in BIT STRING
	bitString := append([]byte{0x03}, asn1Length(len(rsaKeySeq)+1)...)
	bitString = append(bitString, 0x00) // unused bits
	bitString = append(bitString, rsaKeySeq...)

	// RSA algorithm identifier OID: 1.2.840.113549.1.1.1
	algOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}
	algNull := []byte{0x05, 0x00}
	algSeq := asn1Sequence(append(algOID, algNull...))

	return asn1Sequence(append(algSeq, bitString...))
}

func asn1Integer(b []byte) []byte {
	result := []byte{0x02}
	result = append(result, asn1Length(len(b))...)
	return append(result, b...)
}

func asn1Sequence(content []byte) []byte {
	result := []byte{0x30}
	result = append(result, asn1Length(len(content))...)
	return append(result, content...)
}

func asn1Length(length int) []byte {
	if length < 0 || length > 0xFFFFFF {
		// Unreachable for valid RSA keys; guard against misuse.
		panic("asn1Length: length out of range")
	}
	if length < 128 {
		return []byte{byte(length)} // #nosec G115 -- guarded above: 0 <= length < 128
	}
	var lenBytes []byte
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...) // #nosec G115 -- masked to 0xff
		l >>= 8
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...) // #nosec G115 -- len(lenBytes) <= 3
}

// PKCEManager handles PKCE OAuth flow state.
type PKCEManager struct {
	codeVerifier string
	state        string
	logger       Logger
}

// NewPKCEManager creates a new PKCE manager.
func NewPKCEManager() *PKCEManager {
	return &PKCEManager{
		logger: createScopedLogger("pkce"),
	}
}

// AuthorizationURLParams holds parameters for building an authorization URL.
type AuthorizationURLParams struct {
	Domain      string // deprecated: use Issuer
	ClientID    string
	RedirectURI string
	Audience    string
	Scope       string
	Issuer      string
}

// TokenExchangeParams holds parameters for exchanging a code for tokens.
type TokenExchangeParams struct {
	Domain       string // deprecated: use Issuer
	ClientID     string
	Code         string
	RedirectURI  string
	ClientSecret string // #nosec G117 -- OAuth client secret param
	Issuer       string
}

// BuildAuthorizationURL generates PKCE parameters and builds an authorization URL.
func (p *PKCEManager) BuildAuthorizationURL(ctx context.Context, params AuthorizationURLParams) (string, error) {
	// Generate PKCE parameters
	p.codeVerifier = generateRandomString(32)
	codeChallenge := base64URLEncode(sha256Hash([]byte(p.codeVerifier)))
	p.state = generateRandomString(16)

	scope := params.Scope
	if scope == "" {
		scope = "openid profile email"
	}

	queryParams := url.Values{
		"response_type":         {"code"},
		"client_id":             {params.ClientID},
		"redirect_uri":          {params.RedirectURI},
		"scope":                 {scope},
		"audience":              {params.Audience},
		"state":                 {p.state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	// Determine authorization endpoint
	var authEndpoint string
	if params.Issuer != "" {
		oidcConfig, err := GetOidcConfig(ctx, params.Issuer)
		if err != nil {
			return "", fmt.Errorf("failed to get OIDC config: %w", err)
		}
		authEndpoint = oidcConfig.AuthorizationEndpoint
	} else if params.Domain != "" {
		authEndpoint = "https://" + params.Domain + "/authorize"
	} else {
		return "", NewOAuthError("Either issuer or domain must be provided")
	}

	return authEndpoint + "?" + queryParams.Encode(), nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens.
func (p *PKCEManager) ExchangeCodeForToken(ctx context.Context, params TokenExchangeParams) (map[string]any, error) {
	payload := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {params.ClientID},
		"code":         {params.Code},
		"redirect_uri": {params.RedirectURI},
	}

	if params.ClientSecret != "" {
		payload.Set("client_secret", params.ClientSecret)
	}

	if p.codeVerifier != "" {
		payload.Set("code_verifier", p.codeVerifier)
	}

	if params.ClientSecret == "" && p.codeVerifier == "" {
		return nil, NewOAuthError("Either client_secret or PKCE verifier must be provided")
	}

	// Determine token endpoint
	var tokenEndpoint string
	if params.Issuer != "" {
		oidcConfig, err := GetOidcConfig(ctx, params.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to get OIDC config: %w", err)
		}
		tokenEndpoint = oidcConfig.TokenEndpoint
	} else if params.Domain != "" {
		tokenEndpoint = "https://" + params.Domain + "/oauth/token"
	} else {
		return nil, NewOAuthError("Either issuer or domain must be provided")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, NewOAuthError(fmt.Sprintf("Token exchange failed: %v", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- URL from OIDC discovery token_endpoint
	if err != nil {
		return nil, NewOAuthError(fmt.Sprintf("Token exchange failed: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewOAuthError(fmt.Sprintf("Token exchange failed: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		var errorData map[string]any
		_ = json.Unmarshal(body, &errorData)
		errMsg := "unknown error"
		if desc, ok := errorData["error"].(string); ok {
			errMsg = desc
		} else if desc, ok := errorData["error_description"].(string); ok {
			errMsg = desc
		}
		return nil, NewOAuthError(fmt.Sprintf("Token exchange failed: %s", errMsg))
	}

	var tokenData map[string]any
	if err := json.Unmarshal(body, &tokenData); err != nil {
		return nil, NewOAuthError(fmt.Sprintf("Token exchange failed: invalid response: %v", err))
	}

	// Clear PKCE state after successful exchange
	p.ClearState()

	return tokenData, nil
}

// ValidateState validates the state parameter to prevent CSRF attacks.
func (p *PKCEManager) ValidateState(receivedState string) bool {
	return p.state != "" && receivedState == p.state
}

// ClearState clears the PKCE state.
func (p *PKCEManager) ClearState() {
	p.codeVerifier = ""
	p.state = ""
}

// GetState returns the current PKCE state (for debugging/testing).
func (p *PKCEManager) GetState() (codeVerifier, state string) {
	return p.codeVerifier, p.state
}

// StartLocalCallbackServer starts a local HTTP server for OAuth callback.
// It returns the redirect URI and a channel that receives (code, state) on callback.
func StartLocalCallbackServer(port int) (string, <-chan callbackResult, error) {
	if port == 0 {
		port = 52765
	}

	redirectHost := getEnvVar("BARNDOOR_REDIRECT_HOST", "127.0.0.1")
	var redirectURI string
	if strings.HasPrefix(redirectHost, "http") {
		redirectURI = fmt.Sprintf("%s:%d/cb", redirectHost, port)
	} else {
		redirectURI = fmt.Sprintf("http://%s:%d/cb", redirectHost, port)
	}

	resultCh := make(chan callbackResult, 1)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return "", nil, NewOAuthError(fmt.Sprintf("Failed to start callback server: %v", err))
	}

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	mux.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		oauthErr := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")

		w.Header().Set("Content-Type", "text/html")

		if oauthErr != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body><h1>Authentication Failed</h1><p>Error: %s</p><p>You can close this window.</p></body></html>`, html.EscapeString(oauthErr)) // #nosec G705 -- output is HTML-escaped
			go server.Close()
			resultCh <- callbackResult{err: NewOAuthError(fmt.Sprintf("OAuth error: %s - %s", oauthErr, errDesc))}
			return
		}

		if code != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Authentication Successful</h1><p>You can close this window and return to your application.</p><script>setTimeout(() => window.close(), 1000);</script></body></html>`)
			go server.Close()
			resultCh <- callbackResult{code: code, state: state}
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Authentication Failed</h1><p>No authorization code received.</p><p>You can close this window.</p></body></html>`)
		go server.Close()
		resultCh <- callbackResult{err: NewOAuthError("No authorization code received")}
	})

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			resultCh <- callbackResult{err: NewOAuthError(fmt.Sprintf("Callback server error: %v", err))}
		}
	}()

	fmt.Printf("OAuth callback server listening on %s\n", redirectURI)
	return redirectURI, resultCh, nil
}

type callbackResult struct {
	code  string
	state string
	err   error
}

// generateRandomString creates a cryptographically secure random string.
func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return base64URLEncode(b)
}

// sha256Hash returns the SHA256 hash of data.
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// base64URLEncode encodes bytes as base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeJWTPayload decodes the payload section of a JWT without verification.
func decodeJWTPayload(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return claims, nil
}

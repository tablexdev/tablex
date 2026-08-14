package auth

// OpenID Connect, authorization-code flow, no new dependency.
//
// TableX has four modules and a rule that every one has to be justified, so this
// is written against net/http and encoding/json rather than pulling in an OIDC
// library. That is affordable because the flow used here is deliberately the
// small one:
//
//   - Authorization code with PKCE. No implicit flow, no hybrid flow, and no
//     acceptance of an ID token that arrived through the browser.
//   - The ID token's claims are read WITHOUT verifying its signature, and that is
//     sound here for one specific reason: the token is fetched by this process
//     over a direct TLS connection to the provider's token endpoint, with the
//     server certificate validated. OIDC Core §3.1.3.7 says a client MAY skip
//     signature validation in exactly that case, because TLS already establishes
//     that the issuer sent it. That reasoning collapses the moment a token
//     reaches us any other way, which is why the front-channel flows are not
//     merely unused but unsupported: `parseIDToken` is never called on anything
//     but a token-endpoint response.
//
// Everything the signature would otherwise protect is checked explicitly: iss,
// aud, exp, and the nonce bound to this browser's session. state and PKCE cover
// the redirect itself.
//
// If this ever feels too clever, the supported alternative is to drop the ID
// token and call the UserInfo endpoint with the access token instead — same
// trust argument, one more round trip.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// oidcHTTPTimeout bounds every call to the provider. A provider that hangs must
// not hold a request (and therefore a session) open indefinitely.
const oidcHTTPTimeout = 15 * time.Second

// maxProviderBody caps what is read from the provider. Discovery documents and
// token responses are a few KB; without a cap a hostile or broken endpoint could
// stream indefinitely into memory.
const maxProviderBody = 1 << 20 // 1 MiB

// OIDCProvider is a configured, discovered provider. Build one with
// NewOIDCProvider at startup; it is safe for concurrent use.
type OIDCProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string

	authEndpoint  string
	tokenEndpoint string

	client *http.Client
	now    func() time.Time // injectable for tests
}

// discovery is the subset of the provider metadata this flow needs.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// NewOIDCProvider fetches the provider's metadata and returns a ready provider.
//
// Discovery happens once, at startup, and a failure is fatal to it: a gate that
// silently does not engage because its provider was unreachable at boot is worse
// than a server that refuses to start.
func NewOIDCProvider(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, scopes []string) (*OIDCProvider, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	p := &OIDCProvider{
		issuer:       issuer,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
		client:       &http.Client{Timeout: oidcHTTPTimeout},
		now:          time.Now,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("sso: building the discovery request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sso: fetching %s: %w", issuer+"/.well-known/openid-configuration", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso: discovery at %s returned %d", issuer, resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderBody)).Decode(&d); err != nil {
		return nil, fmt.Errorf("sso: parsing the discovery document: %w", err)
	}

	// The issuer in the document must be the one configured. Otherwise a
	// misconfigured or hijacked discovery URL could point the whole flow at
	// another provider, and the iss check on the ID token — which compares
	// against this value — would then be checking the attacker's own claim.
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return nil, fmt.Errorf("sso: discovery document declares issuer %q but sso.issuer is %q", d.Issuer, issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("sso: discovery document is missing the authorization or token endpoint")
	}
	p.authEndpoint, p.tokenEndpoint = d.AuthorizationEndpoint, d.TokenEndpoint
	return p, nil
}

// Handshake is the per-attempt secret set. State and Nonce are compared on the
// way back; Verifier proves to the token endpoint that the code was redeemed by
// whoever started the flow.
type Handshake struct {
	State    string
	Nonce    string
	Verifier string
}

// NewHandshake mints a fresh handshake. Each value is 256 bits of crypto/rand,
// base64url without padding — the PKCE code_verifier charset (RFC 7636 §4.1).
func NewHandshake() (Handshake, error) {
	var h Handshake
	for _, dst := range []*string{&h.State, &h.Nonce, &h.Verifier} {
		v, err := randomToken()
		if err != nil {
			return Handshake{}, err
		}
		*dst = v
	}
	return h, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sso: generating a random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthCodeURL is where the browser is sent to authenticate.
func (p *OIDCProvider) AuthCodeURL(h Handshake) string {
	challenge := sha256.Sum256([]byte(h.Verifier))
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {h.State},
		"nonce":         {h.Nonce},
		// S256, never "plain": a plain verifier in the authorization request
		// would be visible to anything that sees the URL, which is the attack
		// PKCE exists to stop.
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.authEndpoint, "?") {
		sep = "&"
	}
	return p.authEndpoint + sep + q.Encode()
}

// Identity is a verified person, as vouched for by the provider. It is
// deliberately not a database identity: TableX still needs the user's own
// credentials, and the audit trail keeps reporting the database account.
type Identity struct {
	Subject string // the provider's stable "sub"
	Email   string
	Name    string
	// EmailVerified is the provider's email_verified claim, with absent
	// counting as false: on a self-service provider an UNVERIFIED email is an
	// attacker-choosable string, so any policy that matches on Email (the
	// sso.allowed_* lists) must require this to be true. Some providers never
	// send the claim (OneLogin; some Microsoft configurations) — such a
	// deployment reads as unverified, deliberately.
	EmailVerified bool
}

// idTokenClaims is the subset of the ID token this flow verifies and uses.
type idTokenClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      audience `json:"aud"`
	AZP           string   `json:"azp"`
	Expiry        int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Nonce         string   `json:"nonce"`
	Email         string   `json:"email"`
	EmailVerified boolish  `json:"email_verified"`
	Name          string   `json:"name"`
}

// boolish decodes a claim that is specified as a JSON boolean but that some
// providers emit as the STRING "true"/"false" — the same both-shapes problem
// audience solves for aud. Anything else is an error: a token whose
// email_verified cannot be read must not read as verified.
type boolish bool

func (b *boolish) UnmarshalJSON(raw []byte) error {
	var v bool
	if err := json.Unmarshal(raw, &v); err == nil {
		*b = boolish(v)
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("neither a boolean nor a string")
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return fmt.Errorf("string %q is not a boolean", s)
	}
	return nil
}

// audience decodes the aud claim, which the spec allows to be a single string OR
// an array of strings. A decoder that only handled one shape would fail against
// half of all providers.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		// Constant time is not required for a public identifier, but it costs
		// nothing and keeps every credential-shaped comparison in this package
		// uniform.
		if subtle.ConstantTimeCompare([]byte(v), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// tokenResponse is the token endpoint's reply.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Exchange redeems an authorization code and returns the verified identity.
//
// The handshake is the one this browser started, read from its session. Callers
// MUST have already compared the returned state against h.State — Exchange
// re-checks the nonce, which is the half that has to be verified against the
// token rather than against the redirect.
func (p *OIDCProvider) Exchange(ctx context.Context, code string, h Handshake) (Identity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"code_verifier": {h.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, fmt.Errorf("sso: building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic: the secret goes in the Authorization header rather
	// than the body, which is the method every provider supports and the one
	// least likely to be logged by something in between.
	req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))

	resp, err := p.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("sso: calling the token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
	if err != nil {
		return Identity{}, fmt.Errorf("sso: reading the token response: %w", err)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Identity{}, fmt.Errorf("sso: parsing the token response: %w", err)
	}
	if tr.Error != "" {
		// The provider's own error text, not the raw body: the body may contain
		// the code or other material that has no business in a log.
		return Identity{}, fmt.Errorf("sso: the provider refused the exchange: %s", tr.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("sso: the token endpoint returned %d", resp.StatusCode)
	}
	if tr.IDToken == "" {
		return Identity{}, fmt.Errorf("sso: the token response carried no id_token")
	}
	return p.verifyIDToken(tr.IDToken, h.Nonce)
}

// verifyIDToken reads the claims and checks everything the (skipped) signature
// would otherwise be standing in for. See the file comment for why skipping it is
// sound HERE and nowhere else.
func (p *OIDCProvider) verifyIDToken(raw, nonce string) (Identity, error) {
	claims, err := parseIDToken(raw)
	if err != nil {
		return Identity{}, err
	}
	if strings.TrimRight(claims.Issuer, "/") != p.issuer {
		return Identity{}, fmt.Errorf("sso: id_token issuer %q is not %q", claims.Issuer, p.issuer)
	}
	if !claims.Audience.contains(p.clientID) {
		return Identity{}, fmt.Errorf("sso: id_token is not addressed to this client")
	}
	// OIDC Core §3.1.3.7 rules 4-5: a present azp MUST equal this client.
	// The aud check above only asks whether we appear SOMEWHERE in the list;
	// on a provider that co-lists this client as an audience of another
	// relying party's tokens, azp is what says who the token was minted FOR.
	if claims.AZP != "" && subtle.ConstantTimeCompare([]byte(claims.AZP), []byte(p.clientID)) != 1 {
		return Identity{}, fmt.Errorf("sso: id_token azp names another client")
	}
	if claims.Subject == "" {
		return Identity{}, fmt.Errorf("sso: id_token carries no subject")
	}
	if claims.Expiry <= 0 || p.now().After(time.Unix(claims.Expiry, 0)) {
		return Identity{}, fmt.Errorf("sso: id_token has expired")
	}
	// iat is REQUIRED by OIDC Core §2, and a bound that only applied when the
	// claim was present would be a bound a forger could omit their way out of.
	// The allowance is generous — this is a sanity check on the provider's
	// clock, not a replay guard (exp and the nonce carry those).
	const maxClockSkew = 5 * time.Minute
	if claims.IssuedAt <= 0 {
		return Identity{}, fmt.Errorf("sso: id_token carries no iat")
	}
	if time.Unix(claims.IssuedAt, 0).After(p.now().Add(maxClockSkew)) {
		return Identity{}, fmt.Errorf("sso: id_token iat is in the future")
	}
	// The nonce binds this token to the session that started the flow. Without
	// it, a token obtained for one browser could be replayed into another.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return Identity{}, fmt.Errorf("sso: id_token nonce does not match this session")
	}
	return Identity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		Name:          claims.Name,
		EmailVerified: bool(claims.EmailVerified),
	}, nil
}

// parseIDToken decodes a JWT's payload. It does NOT verify the signature — the
// caller's trust comes from having fetched the token itself over TLS from the
// token endpoint (file comment). Never call it on a token from any other source.
func parseIDToken(raw string) (idTokenClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, fmt.Errorf("sso: id_token is not a three-part JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("sso: id_token payload is not base64url: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, fmt.Errorf("sso: id_token payload is not JSON: %w", err)
	}
	return claims, nil
}

// StateMatches compares a returned state against the stored one in constant
// time, and refuses an empty stored state outright — an absent handshake means
// this browser never started a flow, so there is nothing a callback could be
// completing.
func StateMatches(stored, returned string) bool {
	if stored == "" || returned == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(returned)) == 1
}

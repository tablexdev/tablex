package auth_test

// A fake OpenID provider, so the flow is tested rather than reasoned about.
//
// The ID token's signature is deliberately not verified by the implementation
// (see internal/auth/oidc.go for why that is sound for a token fetched over TLS
// from the token endpoint, and only there). That makes the checks which DO run —
// iss, aud, exp, nonce, state, PKCE — the entire security of this flow, so each
// one gets a case that breaks exactly it and expects a refusal.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/auth"
)

// idp is a minimal provider: discovery, an authorization endpoint that redirects
// straight back, and a token endpoint returning a hand-built ID token.
type idp struct {
	srv      *httptest.Server
	clientID string

	// Knobs, so a test can break one thing at a time.
	issuerOverride   string // the iss claim, when it should not match
	audOverride      string // the aud claim, when it should not match
	audArray         bool   // emit aud as an array (the other legal shape)
	nonceOverride    string // the nonce claim, when it should not match
	azp              string // the azp claim; "" omits it
	expiry           time.Time
	iatOverride      int64 // the iat claim; 0 = now
	omitIAT          bool
	omitIDToken      bool
	tokenError       string
	subject          string
	email            string
	emailVerified    any // the email_verified claim: nil = absent, else emitted verbatim (bool or string)
	lastCodeVerifier string
	lastRedirectURI  string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	p := &idp{clientID: "tablex-test", subject: "sub-123", email: "dana@example.com"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.srv.URL,
			"authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint":         p.srv.URL + "/token",
		})
	})

	// The authorization endpoint bounces straight back with a code, echoing state.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("code", "the-code")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.lastCodeVerifier = r.PostFormValue("code_verifier")
		p.lastRedirectURI = r.PostFormValue("redirect_uri")
		w.Header().Set("Content-Type", "application/json")
		if p.tokenError != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": p.tokenError})
			return
		}
		resp := map[string]any{"access_token": "at", "token_type": "Bearer"}
		if !p.omitIDToken {
			resp["id_token"] = p.idToken(r.PostFormValue("code"))
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// nonceForCode is set by the test before the exchange: the real nonce travels in
// the authorization request, and the provider echoes it into the token.
var nonceForCode string

func (p *idp) idToken(string) string {
	iss := p.srv.URL
	if p.issuerOverride != "" {
		iss = p.issuerOverride
	}
	nonce := nonceForCode
	if p.nonceOverride != "" {
		nonce = p.nonceOverride
	}
	exp := p.expiry
	if exp.IsZero() {
		exp = time.Now().Add(5 * time.Minute)
	}
	aud := any(p.clientID)
	if p.audOverride != "" {
		aud = p.audOverride
	}
	if p.audArray {
		if s, ok := aud.(string); ok {
			aud = []string{"someone-else", s}
		}
	}
	claims := map[string]any{
		"iss": iss, "sub": p.subject, "aud": aud,
		"exp": exp.Unix(), "iat": time.Now().Unix(),
		"nonce": nonce, "email": p.email, "name": "Dana Example",
	}
	if p.emailVerified != nil {
		claims["email_verified"] = p.emailVerified
	}
	if p.azp != "" {
		claims["azp"] = p.azp
	}
	if p.iatOverride != 0 {
		claims["iat"] = p.iatOverride
	}
	if p.omitIAT {
		delete(claims, "iat")
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	// The signature is not checked, so any third segment will do. That is the
	// point being relied on, and it is why every OTHER claim is checked.
	return enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + ".not-a-signature"
}

// run drives one whole flow and returns the identity or the error.
func (p *idp) run(t *testing.T) (auth.Identity, error) {
	t.Helper()
	prov, err := auth.NewOIDCProvider(context.Background(), p.srv.URL,
		p.clientID, "secret", "http://tablex.example/auth/sso/callback",
		[]string{"openid", "email"})
	if err != nil {
		return auth.Identity{}, err
	}
	hs, err := auth.NewHandshake()
	if err != nil {
		t.Fatalf("NewHandshake: %v", err)
	}
	nonceForCode = hs.Nonce

	// Walk the authorization redirect the way a browser would, so the URL this
	// code builds is the URL the provider actually parses.
	authURL := prov.AuthCodeURL(hs)
	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize returned no redirect: %v", err)
	}
	if got := loc.Query().Get("state"); !auth.StateMatches(hs.State, got) {
		t.Fatalf("provider echoed state %q, want %q", got, hs.State)
	}
	return prov.Exchange(context.Background(), loc.Query().Get("code"), hs)
}

func TestOIDCHappyPath(t *testing.T) {
	p := newIDP(t)
	id, err := p.run(t)
	if err != nil {
		t.Fatalf("the flow should succeed: %v", err)
	}
	if id.Subject != "sub-123" || id.Email != "dana@example.com" {
		t.Errorf("identity = %+v, want subject sub-123 / dana@example.com", id)
	}
	// PKCE: the verifier must reach the token endpoint, or the code could be
	// redeemed by anyone who intercepted it.
	if p.lastCodeVerifier == "" {
		t.Error("no code_verifier was sent; PKCE is not in effect")
	}
	// The redirect_uri must be re-sent on the exchange (OIDC requires the two to
	// match, and providers reject a mismatch).
	if p.lastRedirectURI != "http://tablex.example/auth/sso/callback" {
		t.Errorf("redirect_uri on exchange = %q", p.lastRedirectURI)
	}
}

// TestOIDCEmailVerifiedClaim pins the strict reading of email_verified:
// absent or non-true is UNVERIFIED (an unverified email is attacker-choosable
// on a self-service provider, and the sso allowlists match on it), while the
// string forms some providers emit decode like their boolean counterparts. A
// value that is neither refuses the token outright — it must never read as
// verified.
func TestOIDCEmailVerifiedClaim(t *testing.T) {
	cases := []struct {
		name    string
		claim   any // nil = absent
		want    bool
		wantErr bool
	}{
		{"absent counts as unverified", nil, false, false},
		{"boolean false", false, false, false},
		{"string false", "false", false, false},
		{"boolean true", true, true, false},
		{"string true (the shape some providers emit)", "true", true, false},
		{"garbage refuses the token", "banana", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			p.emailVerified = tc.claim
			id, err := p.run(t)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("an unreadable email_verified should refuse the token; got %+v", id)
				}
				return
			}
			if err != nil {
				t.Fatalf("the flow should succeed: %v", err)
			}
			if id.EmailVerified != tc.want {
				t.Errorf("EmailVerified = %v, want %v", id.EmailVerified, tc.want)
			}
		})
	}
}

func TestOIDCAudienceMayBeAnArray(t *testing.T) {
	// Half of all providers send aud as a list. A decoder that handled only the
	// string form would fail against them, so this is a compatibility case, not a
	// security one.
	p := newIDP(t)
	p.audArray = true
	if _, err := p.run(t); err != nil {
		t.Errorf("an aud array should be accepted: %v", err)
	}
}

func TestOIDCAZPNamingThisClientIsAccepted(t *testing.T) {
	// The positive half of the azp rule: providers routinely send azp on
	// multi-audience tokens, and one naming THIS client must pass.
	p := newIDP(t)
	p.audArray = true
	p.azp = p.clientID
	if _, err := p.run(t); err != nil {
		t.Errorf("azp naming this client should be accepted: %v", err)
	}
}

// Each case breaks exactly one check. The message must not leak into the
// user-facing path, but it does have to identify what failed for the operator.
func TestOIDCRefusals(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*idp)
		want   string
	}{
		{"issuer does not match the configured one", func(p *idp) { p.issuerOverride = "https://evil.example" }, "issuer"},
		{"token is addressed to another client", func(p *idp) { p.audOverride = "another-client" }, "not addressed to this client"},
		// OIDC Core §3.1.3.7 rules 4-5: aud only says we appear somewhere in
		// the list; a present azp says who the token was minted FOR, and it
		// must be us.
		{"multi-audience token minted for another client (azp)", func(p *idp) { p.audArray = true; p.azp = "another-client" }, "azp"},
		{"token has expired", func(p *idp) { p.expiry = time.Now().Add(-time.Minute) }, "expired"},
		{"iat in the future", func(p *idp) { p.iatOverride = time.Now().Add(time.Hour).Unix() }, "iat"},
		{"no iat at all", func(p *idp) { p.omitIAT = true }, "iat"},
		{"nonce is not this session's", func(p *idp) { p.nonceOverride = "someone-elses-nonce" }, "nonce"},
		{"no subject", func(p *idp) { p.subject = "" }, "subject"},
		{"provider refuses the exchange", func(p *idp) { p.tokenError = "invalid_grant" }, "refused the exchange"},
		{"no id_token in the response", func(p *idp) { p.omitIDToken = true }, "no id_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			tc.break_(p)
			id, err := p.run(t)
			if err == nil {
				t.Fatalf("the flow should have been refused; got identity %+v", id)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestOIDCDiscoveryRefusals(t *testing.T) {
	t.Run("issuer in the document must match the configured issuer", func(t *testing.T) {
		// Otherwise a hijacked or mistyped discovery URL could point the flow at
		// another provider, and the iss check on the token would then be checking
		// the attacker's own claim.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "https://somewhere.else",
				"authorization_endpoint": "https://somewhere.else/a",
				"token_endpoint":         "https://somewhere.else/t",
			})
		}))
		defer srv.Close()
		_, err := auth.NewOIDCProvider(context.Background(), srv.URL, "id", "secret", "http://x/cb", nil)
		if err == nil || !strings.Contains(err.Error(), "declares issuer") {
			t.Fatalf("err = %v, want a refusal about the declared issuer", err)
		}
	})

	t.Run("missing endpoints", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"issuer":%q}`, "http://"+r.Host)
		}))
		defer srv.Close()
		_, err := auth.NewOIDCProvider(context.Background(), srv.URL, "id", "secret", "http://x/cb", nil)
		if err == nil || !strings.Contains(err.Error(), "missing the authorization or token endpoint") {
			t.Fatalf("err = %v, want a refusal about missing endpoints", err)
		}
	})

	t.Run("unreachable provider", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close() // nothing is listening now
		if _, err := auth.NewOIDCProvider(context.Background(), url, "id", "secret", "http://x/cb", nil); err == nil {
			t.Fatal("discovery against a dead provider should fail, so startup refuses")
		}
	})
}

func TestAuthCodeURLUsesS256PKCE(t *testing.T) {
	p := newIDP(t)
	prov, err := auth.NewOIDCProvider(context.Background(), p.srv.URL, p.clientID, "secret", "http://x/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	hs, _ := auth.NewHandshake()
	u, err := url.Parse(prov.AuthCodeURL(hs))
	if err != nil {
		t.Fatalf("AuthCodeURL is not a URL: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code", // never "token"/"id_token": no front-channel token
		"code_challenge_method": "S256", // never "plain"
		"client_id":             p.clientID,
		"state":                 hs.State,
		"nonce":                 hs.Nonce,
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// The verifier itself must NOT be in the URL — that is the whole point of the
	// challenge.
	if strings.Contains(u.RawQuery, hs.Verifier) {
		t.Error("the PKCE verifier appears in the authorization URL")
	}
	if q.Get("code_challenge") == "" {
		t.Error("no code_challenge")
	}
}

func TestHandshakeValuesAreDistinctAndFresh(t *testing.T) {
	// state, nonce and verifier must be independent: reusing one value for two
	// purposes would let a match on one imply a match on another.
	seen := map[string]bool{}
	for range 20 {
		h, err := auth.NewHandshake()
		if err != nil {
			t.Fatalf("NewHandshake: %v", err)
		}
		for _, v := range []string{h.State, h.Nonce, h.Verifier} {
			if len(v) < 40 {
				t.Fatalf("handshake value %q is too short to be 256 bits of base64url", v)
			}
			if seen[v] {
				t.Fatalf("handshake value %q was issued twice", v)
			}
			seen[v] = true
		}
	}
}

func TestStateMatchesRefusesEmpty(t *testing.T) {
	// An empty stored state means this browser never started a flow, so there is
	// nothing a callback could be completing. Treating "" == "" as a match would
	// accept a bare callback URL.
	if auth.StateMatches("", "") {
		t.Error("two empty states must not match")
	}
	if auth.StateMatches("abc", "") || auth.StateMatches("", "abc") {
		t.Error("an empty state must never match")
	}
	if !auth.StateMatches("abc", "abc") {
		t.Error("equal states must match")
	}
}

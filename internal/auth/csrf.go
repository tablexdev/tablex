// Package auth holds TableX's authentication-adjacent primitives: CSRF token
// verification, login rate limiting, and the SSRF host guard for ad-hoc logins.
// Credential validation itself is just "open a pool with the user's input" and
// lives in the auth handler; this package provides the surrounding guards.
package auth

import (
	"crypto/subtle"
	"net/http"
)

// CSRF header and form field names. htmx sends the token via an
// htmx:configRequest hook that sets the X-CSRF-Token header (app.js); plain
// (no-JS) forms carry it in a hidden input read from the form body.
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf_token"
)

// CheckCSRF reports whether provided matches the session token in constant time.
func CheckCSRF(sessionToken, provided string) bool {
	if sessionToken == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sessionToken), []byte(provided)) == 1
}

// TokenFromRequest extracts the CSRF token from the header first, then the form.
func TokenFromRequest(r *http.Request) string {
	if v := r.Header.Get(CSRFHeader); v != "" {
		return v
	}
	return r.PostFormValue(CSRFField)
}

// SafeMethod reports whether the HTTP method cannot change state, and so needs
// no CSRF check.
//
// This is the ONE definition of "safe" in TableX: restricted mode reads it too,
// so the CSRF gate and the [restrict] policy cannot disagree about which methods
// change things. They did — this used to include TRACE while restricted mode
// treated it as state-changing. Nothing was reachable through the gap (only GET
// and POST are ever registered), but two definitions of "safe" in one security
// path is the kind of thing that stops being harmless the moment a third method
// is registered. TRACE is excluded: it is not a read, it is an echo, and RFC
// 9110 gives it no safe-method guarantee worth staking a CSRF exemption on.
func SafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

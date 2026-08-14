// Test adapters: unexported internals re-exported to the external test
// package (package server_test). Compiled only into the test binary. The file
// is deliberately not named export_test.go — the handlers package uses that
// name with Go's other conventional meaning (the tests FOR export.go), and one
// repository should not carry both readings of one filename.
package server

// BodyLimitFor exposes bodyLimitFor so the route-body tests size each request
// from the same three-way rule the middleware applies, instead of duplicating
// the cap constants and drifting when they change.
var BodyLimitFor = bodyLimitFor

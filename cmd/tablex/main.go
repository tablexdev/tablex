// Command tablex is the single-binary, multi-database web administration tool.
//
// It parses configuration (flags + env + TOML), builds the HTTP server with all
// assets embedded, registers the database dialects, and serves until SIGINT/
// SIGTERM triggers a graceful shutdown that closes every session's pools.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/server"

	// Register the database dialects. Adding or removing an engine is one line.
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tablex:", err)
		os.Exit(1)
	}
}

// runHealthcheck probes GET /healthz on the configured listen address and
// returns an error (→ exit 1) unless the server answers 200. It is the container
// HEALTHCHECK's self-check: the distroless runtime image has no shell or curl, so
// the binary probes itself. TLS is verified with InsecureSkipVerify because it is
// a local self-check against the server's own (possibly self-signed) cert.
func runHealthcheck(cfg config.Config) error {
	client := &http.Client{Timeout: 5 * time.Second}
	if cfg.TLSEnabled() {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Get(healthcheckURL(cfg.Listen, cfg.TLSEnabled()))
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: GET /healthz returned %d", resp.StatusCode)
	}
	return nil
}

// healthcheckURL resolves the probe target from the configured listen address.
// A wildcard or empty bind host is probed via loopback (the container's own
// 127.0.0.1 reaches a wildcard listener); a CONCRETE bind host is probed
// directly — probing loopback there would false-negative a healthy server
// that only listens on its bound interface (TABLEX_LISTEN=10.0.0.5:8080).
// Wildcards are detected with net.ParseIP(...).IsUnspecified(), not string
// compares, and the URL is built via net/url so an IPv6 host stays bracketed
// and a scoped literal's zone (%eth0) is escaped to %25eth0 per RFC 6874.
func healthcheckURL(listen string, useTLS bool) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		host, port = "", "8080"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A zone-scoped literal (fe80::1%eth0) does not ParseIP whole; strip
		// the zone for the wildcard test only — the probe keeps the zone.
		if i := strings.IndexByte(host, '%'); i >= 0 {
			ip = net.ParseIP(host[:i])
		}
	}
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port), Path: "/healthz"}
	return u.String()
}

func run() error {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		if config.IsVersionRequest(err) {
			fmt.Println("tablex", version)
			return nil
		}
		if config.IsHealthcheckRequest(err) {
			return runHealthcheck(cfg)
		}
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	srv, err := server.New(cfg, logger, version)
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	// Bind first, so a listen failure is reported before we announce "listening"
	// and so the log carries the ACTUAL bound address (cfg.Listen may be ":0").
	ln, err := srv.Listen()
	if err != nil {
		return fmt.Errorf("listen on %q: %w", cfg.Listen, err)
	}
	scheme := "http"
	if srv.TLS() {
		scheme = "https"
	}
	logger.Info("TableX listening", "addr", ln.Addr().String(), "url", scheme+"://"+humanAddr(ln.Addr().String()), "version", version)

	// Serve in the background; surface a fatal serve error via errCh.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Wait for a termination signal or a fatal serve error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	var serveErr error
	select {
	case serveErr = <-errCh:
		logger.Error("server error; shutting down", "err", serveErr)
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	}

	// A second interrupt during graceful shutdown means "stop waiting" — force an
	// immediate exit instead of blocking for the 20s timeout. Re-notify so the
	// SIGTERM/Interrupt default handler is not restored while we wait.
	go func() {
		<-sigCh
		logger.Warn("second signal received; forcing immediate exit")
		os.Exit(1)
	}()

	// Both paths drain and close every session's pools — the fatal serve-error
	// branch must release pools/goroutines/credentials too, not just the signal
	// branch.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	shutdownErr := srv.Shutdown(ctx)
	switch {
	case serveErr != nil:
		return fmt.Errorf("server error: %w", serveErr)
	case shutdownErr != nil:
		return fmt.Errorf("graceful shutdown: %w", shutdownErr)
	}
	logger.Info("stopped cleanly")
	return nil
}

// humanAddr turns a listen address into a browsable URL host. A wildcard bind
// (":8080", "0.0.0.0:8080", "[::]:8080") isn't connectable as-is, so it is shown
// as localhost; concrete hosts are returned unchanged.
func humanAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

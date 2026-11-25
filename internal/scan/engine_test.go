package scan_test

import (
	"context"
	"testing"
	"time"

	"grpcscope/internal/config"
	"grpcscope/internal/model"
	"grpcscope/internal/scan"
	"grpcscope/internal/testserver"
)

func newEngine(t *testing.T, cfg *config.Config) *scan.Engine {
	t.Helper()
	e, err := scan.NewEngine(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func baseConfig() *config.Config {
	c := config.Default()
	c.Probe.Timeout = 2 * time.Second
	c.Probe.ConnectTimeout = 2 * time.Second
	c.Probe.ReflectionTimeout = 3 * time.Second
	c.Discovery.GuessServices = false
	c.Discovery.GuessMethods = false
	return c
}

func scanOne(t *testing.T, srv *testserver.Server, cfg *config.Config) model.Endpoint {
	t.Helper()
	eng := newEngine(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return eng.ScanEndpoint(ctx, srv.Addr)
}

// TestSafeModeNeverInvokesAHandler is the invariant that makes the tool safe
// to point at production: in safe mode no handler may run for any shape.
func TestSafeModeNeverInvokesAHandler(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Mode = config.ModeSafe

	ep := scanOne(t, srv, cfg)

	if ep.Protocol != model.ProtoGRPC {
		t.Fatalf("expected grpc, got %s (%s)", ep.Protocol, ep.Detail)
	}
	if n := srv.GlobalEntries().Count(); n != 0 {
		t.Fatalf("safe-mode scan ran %d handler(s): %s", n, srv.AllEffects())
	}
	for name, eff := range srv.SideEffects() {
		if eff.Count() != 0 {
			t.Errorf("handler %s ran %d time(s)", name, eff.Count())
		}
	}
}

// TestReflectionEnumerationIsExact checks that reflection yields the real
// inventory, including method shapes.
func TestReflectionEnumerationIsExact(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	ep := scanOne(t, srv, baseConfig())

	if ep.Reflection != model.ReflectionV1 && ep.Reflection != model.ReflectionV1Alpha {
		t.Fatalf("reflection = %s", ep.Reflection)
	}
	want := map[string]model.Shape{
		"/demo.AdminService/FlushCache": model.ShapeUnary,
		"/demo.AdminService/WatchAdmin": model.ShapeServerStream,
		"/demo.AdminService/BulkImport": model.ShapeClientStream,
		"/demo.BizService/CreateUser":   model.ShapeUnary,
	}
	got := map[string]model.Method{}
	for _, m := range ep.AllMethods() {
		got[m.FullName] = *m
	}
	for name, shape := range want {
		m, ok := got[name]
		if !ok {
			t.Errorf("missing method %s", name)
			continue
		}
		if m.Shape != shape {
			t.Errorf("%s: shape = %s, want %s", name, m.Shape, shape)
		}
		if !m.Exists {
			t.Errorf("%s: should be confirmed present", name)
		}
	}
}

// TestSensitiveMethodsFlaggedWithoutCallingThem checks the central verdict:
// destructive admin methods are flagged reachable, inferred from the
// unauthenticated health check, and never called.
func TestSensitiveMethodsFlaggedWithoutCallingThem(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	ep := scanOne(t, srv, baseConfig())

	var destructive []*model.Method
	for _, m := range ep.SensitiveMethods() {
		if m.Service == "demo.AdminService" {
			destructive = append(destructive, m)
		}
	}
	if len(destructive) < 3 {
		t.Fatalf("expected several sensitive admin methods, got %d", len(destructive))
	}
	for _, m := range destructive {
		if m.Auth != model.AuthInferredOpen {
			t.Errorf("%s: auth = %s, want inferred-open", m.FullName, m.Auth)
		}
	}
	for name, eff := range srv.SideEffects() {
		if eff.Count() != 0 {
			t.Errorf("handler %s ran %d time(s) while judging sensitivity", name, eff.Count())
		}
	}
}

// TestAuthInterceptorDetected proves the tool notices a global interceptor
// and reports the sensitive methods as gated rather than open.
func TestAuthInterceptorDetected(t *testing.T) {
	srv, err := testserver.New(testserver.WithUnaryAuth(), testserver.WithStreamAuth())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	ep := scanOne(t, srv, baseConfig())

	if ep.Health != model.HealthGated {
		t.Fatalf("health = %s, want gated", ep.Health)
	}
	if ep.ServerWideUnaryAuth != model.AuthProvenGated {
		t.Fatalf("server-wide auth = %s", ep.ServerWideUnaryAuth)
	}
	for _, m := range ep.SensitiveMethods() {
		if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
			t.Errorf("%s: reported open on an auth-required server", m.FullName)
		}
	}
}

// TestNoReflectionFallsBackToDescriptors checks the "reflection off" case
// where the operator supplies a descriptor.
func TestNoReflectionFallsBackToDescriptors(t *testing.T) {
	// Stub test: the descriptor-fed path is exercised by the CLI's -proto flag;
	// here we only assert reflection absence is reported.
	srv, err := testserver.New(testserver.WithoutReflection())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Discovery.GuessServices = false
	cfg.Discovery.GuessMethods = false
	ep := scanOne(t, srv, cfg)

	if ep.Reflection != model.ReflectionAbsent {
		t.Fatalf("reflection = %s, want absent", ep.Reflection)
	}
}

package scan_test

import (
	"context"
	"testing"
	"time"

	"grpcscope/internal/config"
	"grpcscope/internal/descriptors"
	"grpcscope/internal/model"
	"grpcscope/internal/scan"
	"grpcscope/internal/testserver"
)

// TestStandardModeOnlyCallsReadOnlyMethods is the precise contract of the
// middle mode: with descriptors in hand, the scanner sends an empty request
// only to methods whose names mark them read-only. Every state-changing method
// must remain uncalled, and the read-only call proves or disproves auth.
func TestStandardModeOnlyCallsReadOnlyMethods(t *testing.T) {
	reg, err := descriptors.Load([]string{"../../testdata/demo.proto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testserver.New(testserver.WithoutReflection())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Mode = config.ModeStandard
	cfg.Discovery.GuessServices = false
	cfg.Discovery.GuessMethods = false

	eng, err := scan.NewEngine(cfg, nil, nil, nil, reg.Files)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	// In standard mode a body probe is permitted only on a read-only-named
	// method that is NOT on an administrative service. On this demo server that
	// leaves the BizService read methods; every AdminService method, even
	// GetStatus, must stay uncalled because the service name is management-facing.
	readOnlyRan := map[string]int64{}
	for name, eff := range srv.SideEffects() {
		if eff.Count() > 0 {
			readOnlyRan[name] = eff.Count()
		}
	}
	for name := range readOnlyRan {
		switch name {
		case "demo.BizService/GetUser", "demo.BizService/ListUsers":
			// allowed: read-only verb, non-administrative service
		default:
			t.Errorf("standard mode invoked handler %s (%d times) outside the read-only, non-admin allowance", name, readOnlyRan[name])
		}
	}

	// Every proved-open method must be a read-only, non-admin one.
	var proven int
	for _, m := range ep.AllMethods() {
		if m.Auth == model.AuthProvenOpen {
			proven++
			if m.Risk.Level != model.RiskReadOnly {
				t.Errorf("%s proven open but risk = %s", m.FullName, m.Risk.Level)
			}
		}
	}
	if proven == 0 {
		t.Errorf("expected at least one read-only method proven open against an unauthenticated server")
	}

	// AdminService methods must remain inferred, never proven, because the
	// service is administrative and no body may reach it.
	for _, m := range ep.AllMethods() {
		if m.Service == "demo.AdminService" && m.Auth == model.AuthProvenOpen {
			t.Errorf("%s on an admin service was proven open by calling it", m.FullName)
		}
	}

	// And nothing destructive ever ran.
	for _, m := range ep.SensitiveMethods() {
		if eff := srv.SideEffects()[m.Service+"/"+m.Name]; eff != nil && eff.Count() > 0 {
			t.Errorf("sensitive method %s was invoked", m.FullName)
		}
	}
}

// TestStandardModeWithAuthProvesReadOnlyGated is the mirror image: on an
// authenticated server the read-only probe is rejected, so the verdict should
// be proven-gated rather than inferred.
func TestStandardModeWithAuthProvesReadOnlyGated(t *testing.T) {
	reg, err := descriptors.Load([]string{"../../testdata/demo.proto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testserver.New(testserver.WithoutReflection(), testserver.WithUnaryAuth(), testserver.WithStreamAuth())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Mode = config.ModeStandard
	cfg.Discovery.GuessServices = false
	cfg.Discovery.GuessMethods = false

	eng, err := scan.NewEngine(cfg, nil, nil, nil, reg.Files)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	for _, m := range ep.AllMethods() {
		if m.Risk.Level == model.RiskReadOnly && m.Origin == model.ConfExact {
			if m.Auth == model.AuthProvenOpen {
				t.Errorf("%s proven open on an authenticated server", m.FullName)
			}
		}
	}
}

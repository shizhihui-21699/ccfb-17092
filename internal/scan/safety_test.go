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

// TestNeverTouchExcludesWholeService checks that a never_touch pattern keeps a
// service out of the inventory entirely, since the oracle is not sent to it
// either, and nothing is claimed about it without wire proof.
func TestNeverTouchExcludesWholeService(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Mode = config.ModeSafe
	cfg.Safety.NeverTouch = []string{`^/demo\.AdminService/`}

	eng, err := scan.NewEngine(cfg, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	for _, m := range ep.AllMethods() {
		if m.Service == "demo.AdminService" {
			t.Errorf("%s present despite never_touch", m.FullName)
			_ = model.RiskUnknown
		}
	}
	// The other service is still enumerated.
	var sawBiz bool
	for _, s := range ep.Services {
		if s.Name == "demo.BizService" {
			sawBiz = true
		}
	}
	if !sawBiz {
		t.Errorf("never_touch on one service must not suppress the others; got %v", ep.Services)
	}
	if n := srv.GlobalEntries().Count(); n != 0 {
		t.Fatalf("never_touch scan ran %d handler(s)", n)
	}
}

// TestNeverCallKeepsMethodButBarsBody checks that a never_call pattern still
// lists the method (reflection enumerated it) but no body probe reaches it in
// standard mode.
func TestNeverCallKeepsMethodButBarsBody(t *testing.T) {
	reg, err := loadDemoDescriptors(t)
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
	cfg.Safety.NeverCall = []string{`^/demo\.BizService/GetUser$`}

	eng, err := scan.NewEngine(cfg, nil, nil, nil, reg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	eff := srv.SideEffects()["demo.BizService/GetUser"]
	if eff != nil && eff.Count() > 0 {
		t.Errorf("GetUser was called %d times despite never_call", eff.Count())
	}
	var found bool
	for _, m := range ep.AllMethods() {
		if m.FullName == "/demo.BizService/GetUser" {
			found = true
			if m.Auth == model.AuthProvenOpen {
				t.Errorf("GetUser reported proven-open despite never_call barring the body")
			}
		}
	}
	if !found {
		t.Error("never_call should keep the method in the inventory, not drop it")
	}
}

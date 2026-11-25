package scan_test

import (
	"context"
	"testing"
	"time"

	"grpcscope/internal/descriptors"
	"grpcscope/internal/model"
	"grpcscope/internal/scan"
	"grpcscope/internal/testserver"
)

// TestDescriptorSuppliedInventory exercises the "描述文件" path: reflection is
// off, but the operator supplied the .proto, so the scanner has the exact
// inventory and can verify each method against the live server.
func TestDescriptorSuppliedInventory(t *testing.T) {
	reg, err := descriptors.Load([]string{"../../testdata/demo.proto"}, nil)
	if err != nil {
		t.Fatalf("load descriptors: %v", err)
	}

	srv, err := testserver.New(testserver.WithoutReflection())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Discovery.GuessServices = false
	cfg.Discovery.GuessMethods = false

	eng, err := scan.NewEngine(cfg, nil, nil, nil, reg.Files)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	var admin *model.Service
	for i := range ep.Services {
		if ep.Services[i].Name == "demo.AdminService" {
			admin = &ep.Services[i]
		}
	}
	if admin == nil {
		t.Fatalf("AdminService missing from descriptor-fed inventory; services: %v", names(ep))
	}
	if len(admin.Methods) != 7 {
		t.Errorf("AdminService has %d methods, want 7", len(admin.Methods))
	}
	for _, m := range admin.Methods {
		if m.Origin != model.ConfExact {
			t.Errorf("%s origin = %s, want exact", m.Name, m.Origin)
		}
		if !m.Exists {
			t.Errorf("%s not confirmed present by the oracle", m.Name)
		}
		if len(m.InputFields) == 0 && m.Input != "demo.Empty" {
			t.Errorf("%s: descriptor fields missing", m.Name)
		}
	}
	// Shapes must come from the descriptor, including the stream one.
	for _, m := range ep.AllMethods() {
		if m.Name == "WatchAdmin" && m.Shape != model.ShapeServerStream {
			t.Errorf("WatchAdmin shape = %s, want server-stream", m.Shape)
		}
		if m.Name == "FlushCache" && m.Risk.Level != model.RiskDestructive {
			t.Errorf("FlushCache risk = %s, want destructive", m.Risk.Level)
		}
	}

	// The BizService types exist in the descriptor but the proto only declares
	// AdminService, so methods the server does not run are dropped, not reported.
	if n := srv.GlobalEntries().Count(); n != 0 {
		t.Fatalf("descriptor scan ran %d handler(s): %s", n, srv.AllEffects())
	}
}

func names(ep model.Endpoint) []string {
	var out []string
	for _, s := range ep.Services {
		out = append(out, s.Name)
	}
	return out
}

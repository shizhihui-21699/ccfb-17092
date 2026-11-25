package scan_test

import (
	"context"
	"testing"
	"time"

	"grpcscope/internal/model"
	"grpcscope/internal/scan"
	"grpcscope/internal/testserver"
)

// TestGuessingFindsServicesWhenReflectionIsOff exercises the path the incident
// implies: reflection disabled, so enumeration falls back to a wordlist, and
// the existence oracle decides what is really there.
func TestGuessingFindsServicesWhenReflectionIsOff(t *testing.T) {
	srv, err := testserver.New(testserver.WithoutReflection())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Discovery.GuessServices = true
	cfg.Discovery.GuessMethods = true
	cfg.Discovery.MaxGuessServices = 40
	cfg.Discovery.MaxGuessMethodsPerService = 30

	eng, err := scan.NewEngine(cfg,
		[]string{"AdminService", "BizService", "NopeService"},
		[]string{"FlushCache", "GetStatus", "PurgeAll", "GetUser", "NoSuchMethod"},
		[]string{"demo", ""}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	// Both real services should be discovered via "unknown method" proof.
	names := map[string]bool{}
	for _, svc := range ep.Services {
		names[svc.Name] = true
	}
	if !names["demo.AdminService"] {
		t.Errorf("demo.AdminService not discovered; found %v", names)
	}
	if !names["demo.BizService"] {
		t.Errorf("demo.BizService not discovered; found %v", names)
	}
	if names["demo.NopeService"] || names["NopeService"] {
		t.Errorf("invented service reported as present")
	}

	// A guessed method that the oracle confirms must be marked guessed + present.
	var flush *model.Method
	for _, m := range ep.AllMethods() {
		if m.FullName == "/demo.AdminService/FlushCache" {
			flush = m
		}
	}
	if flush == nil {
		t.Fatal("FlushCache not found by method guessing")
	}
	if !flush.Exists {
		t.Errorf("FlushCache: oracle confirmed it but Exists=false")
	}
	if flush.Origin != model.ConfGuessed {
		t.Errorf("FlushCache origin = %s, want guessed", flush.Origin)
	}
	if flush.Risk.Level != model.RiskDestructive {
		t.Errorf("FlushCache risk = %s, want destructive", flush.Risk.Level)
	}

	// And, as always, no handler may have run.
	if n := srv.GlobalEntries().Count(); n != 0 {
		t.Fatalf("guessing scan ran %d handler(s): %s", n, srv.AllEffects())
	}
}

// TestGuessedAbsenceIsNotReported guards the opposite error: a wordlist entry
// the server denies must not appear.
func TestGuessedAbsenceIsNotReported(t *testing.T) {
	srv, err := testserver.New(testserver.WithoutReflection())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	cfg := baseConfig()
	cfg.Discovery.GuessServices = true
	cfg.Discovery.GuessMethods = true
	cfg.Discovery.MaxGuessServices = 20
	cfg.Discovery.MaxGuessMethodsPerService = 20

	eng, err := scan.NewEngine(cfg, []string{"MadeUpService"}, []string{"NoSuchThing"}, []string{"demo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ep := eng.ScanEndpoint(ctx, srv.Addr)

	for _, svc := range ep.Services {
		if svc.Name == "demo.MadeUpService" {
			t.Errorf("invented service reported: %s", svc.Name)
		}
		for _, m := range svc.Methods {
			if m.Name == "NoSuchThing" {
				t.Errorf("invented method reported: %s", m.FullName)
			}
		}
	}
}

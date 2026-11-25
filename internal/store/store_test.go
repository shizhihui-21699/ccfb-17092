package store_test

import (
	"testing"
	"time"

	"grpcscope/internal/model"
	"grpcscope/internal/store"
)

func scanFixture(t time.Time, endpoints []model.Endpoint) *model.Scan {
	return &model.Scan{
		Meta:      model.ScanMeta{StartedAt: t, FinishedAt: t.Add(time.Second), Version: "test", Mode: "safe"},
		Endpoints: endpoints,
	}
}

func epWith(addr string, methods map[string]model.AuthState) model.Endpoint {
	ep := model.Endpoint{Addr: addr, Protocol: model.ProtoGRPC, Reflection: model.ReflectionV1, Health: model.HealthOpen}
	svc := model.Service{Name: "demo.AdminService", Origin: model.ConfExact}
	for name, auth := range methods {
		svc.Methods = append(svc.Methods, model.Method{
			FullName: "/demo.AdminService/" + name,
			Service:  "demo.AdminService",
			Name:     name,
			Shape:    model.ShapeUnary,
			Origin:   model.ConfExact,
			Exists:   true,
			Auth:     auth,
			Risk:     model.Risk{Level: model.RiskMutating},
		})
	}
	ep.Services = []model.Service{svc}
	return ep
}

func TestDiffDetectsAuthChangeAndNewMethods(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old := scanFixture(base, []model.Endpoint{
		epWith("10.0.0.1:50051", map[string]model.AuthState{
			"FlushCache": model.AuthInferredGated,
			"GetStatus":  model.AuthInferredOpen,
		}),
		epWith("10.0.0.2:50051", map[string]model.AuthState{"GetUser": model.AuthInferredOpen}),
	})
	new := scanFixture(base.Add(time.Hour), []model.Endpoint{
		epWith("10.0.0.1:50051", map[string]model.AuthState{
			"FlushCache":   model.AuthInferredOpen, // auth regressed
			"GetStatus":    model.AuthInferredOpen,
			"UpdateConfig": model.AuthUnknown, // new method appeared
		}),
		epWith("10.0.0.3:50051", map[string]model.AuthState{"GetUser": model.AuthInferredOpen}), // new endpoint
	})

	changes := store.Diff(old, new)

	var kinds = map[string]int{}
	var authChanged bool
	for _, c := range changes {
		kinds[c.Kind]++
		if c.Kind == "auth-changed" && c.Method == "/demo.AdminService/FlushCache" {
			authChanged = true
			if c.Severity != "high" {
				t.Errorf("an auth regression to open should be high severity, got %s", c.Severity)
			}
		}
	}
	if !authChanged {
		t.Error("expected an auth-changed entry for FlushCache")
	}
	if kinds["method-appeared"] != 1 {
		t.Errorf("method-appeared = %d, want 1", kinds["method-appeared"])
	}
	if kinds["endpoint-appeared"] != 1 {
		t.Errorf("endpoint-appeared = %d, want 1", kinds["endpoint-appeared"])
	}
	if kinds["endpoint-disappeared"] != 1 {
		t.Errorf("endpoint-disappeared = %d, want 1 (10.0.0.2 went away)", kinds["endpoint-disappeared"])
	}
}

func TestSaveAndLatestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := scanFixture(base, []model.Endpoint{epWith("10.0.0.1:50051", map[string]model.AuthState{"GetUser": model.AuthInferredOpen})})
	if _, err := st.Save(s); err != nil {
		t.Fatal(err)
	}
	got, path, err := st.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("Latest returned nil after Save")
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].Addr != "10.0.0.1:50051" {
		t.Errorf("round trip lost data; path=%s endpoints=%v", path, got.Endpoints)
	}
}

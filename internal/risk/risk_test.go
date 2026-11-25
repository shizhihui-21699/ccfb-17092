package risk_test

import (
	"testing"

	"grpcscope/internal/model"
	"grpcscope/internal/risk"
)

func TestClassifyCore(t *testing.T) {
	cases := []struct {
		svc, method string
		fields      []model.FieldInfo
		want        model.SideEffectRisk
	}{
		{"demo.AdminService", "FlushCache", nil, model.RiskDestructive},
		{"demo.AdminService", "PurgeAll", nil, model.RiskDestructive},
		{"demo.AdminService", "DeleteByID", nil, model.RiskDestructive},
		{"demo.AdminService", "Shutdown", nil, model.RiskDestructive},
		{"demo.AdminService", "UpdateConfig", nil, model.RiskMutating},
		{"demo.BizService", "CreateUser", nil, model.RiskMutating},
		{"demo.BizService", "SendEmail", nil, model.RiskMutating},
		{"demo.BizService", "GetUser", nil, model.RiskReadOnly},
		{"demo.BizService", "ListUsers", nil, model.RiskReadOnly},
		{"demo.BizService", "GetStatus", nil, model.RiskReadOnly},
		{"demo.BizService", "SearchProducts", nil, model.RiskReadOnly},
		{"demo.BizService", "Frobnicate", nil, model.RiskUnknown},
	}
	for _, c := range cases {
		got := risk.Classify(c.svc, c.method, c.fields)
		if got.Level != c.want {
			t.Errorf("Classify(%q,%q) = %s, want %s (reasons %v)",
				c.svc, c.method, got.Level, c.want, got.Reasons)
		}
	}
}

// A credential-bearing input cannot be read as harmless even under a
// read-only verb.
func TestSensitiveInputPromotesRead(t *testing.T) {
	r := risk.Classify("demo.BizService", "GetUser", []model.FieldInfo{
		{Name: "password_hash"},
	})
	if r.Level != model.RiskMutating {
		t.Errorf("GetUser with password input = %s, want mutating", r.Level)
	}
}

// A bare "key" field is a map key far more often than a credential, so it must
// not promote a read on its own.
func TestBareKeyFieldDoesNotPromote(t *testing.T) {
	r := risk.Classify("demo.BizService", "GetUser", []model.FieldInfo{{Name: "key"}})
	if r.Level != model.RiskReadOnly {
		t.Errorf("GetUser with a plain key field = %s, want read-only", r.Level)
	}
}

func TestAdminServiceDetected(t *testing.T) {
	for _, name := range []string{"demo.AdminService", "internal.OpsService", "admin.v1.Users"} {
		if !risk.ServiceRisk(name).Adminish {
			t.Errorf("%s should be flagged administrative", name)
		}
	}
	for _, name := range []string{"demo.BizService", "public.UserService"} {
		if risk.ServiceRisk(name).Adminish {
			t.Errorf("%s should not be flagged administrative", name)
		}
	}
}

func TestBodyProbeSafeRefusesAdminService(t *testing.T) {
	// Read-only verb, but on an administrative service: no body.
	if risk.BodyProbeSafe("demo.AdminService", "GetStatus") {
		t.Error("GetStatus on AdminService must not receive a body")
	}
	// Read-only verb on a business service: body allowed.
	if !risk.BodyProbeSafe("demo.BizService", "GetStatus") {
		t.Error("GetStatus on BizService should be probe-safe")
	}
	// Mutating verb: never.
	if risk.BodyProbeSafe("demo.BizService", "CreateUser") {
		t.Error("CreateUser must never be probe-safe")
	}
}

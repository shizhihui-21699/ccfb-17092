package classify

import (
	"testing"

	"github.com/internal/rpcrecon/internal/model"
)

func TestClassifySensitiveMethods(t *testing.T) {
	engine := NewEngine(nil)

	tests := []struct {
		name     string
		service  string
		method   string
		wantKind model.SensitiveKind
		wantSev  model.Severity
		wantHit  bool
	}{
		{"清空缓存", "cache.CacheService", "FlushAll", model.KindCache, model.SeverityCritical, true},
		{"修改配置", "admin.ConfigService", "UpdateConfig", model.KindConfig, model.SeverityHigh, true},
		{"管理服务命名", "admin.AdminService", "ListUsers", model.KindAdmin, model.SeverityHigh, true},
		{"权限提升", "iam.RoleService", "GrantRole", model.KindAdmin, model.SeverityHigh, true},
		{"调试原语", "debug.DebugService", "Pprof", model.KindDebug, model.SeverityHigh, true},
		{"破坏性数据操作", "data.Cleaner", "Truncate", model.KindDataWrite, model.SeverityCritical, true},
		{"普通读", "biz.OrderService", "GetOrder", model.KindDataRead, model.SeverityLow, true},
		{"健康检查", "grpc.health.v1.Health", "Check", model.KindHealth, model.SeverityInfo, true},
		{"健康检查List不应被通用读规则升级", "grpc.health.v1.Health", "List", model.KindHealth, model.SeverityInfo, true},
		{"无关方法", "biz.OrderService", "Ping", model.KindUnknown, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &model.MethodInfo{
				Service:  tt.service,
				Name:     tt.method,
				FullName: "/" + tt.service + "/" + tt.method,
			}
			got := engine.Classify(m)
			if !tt.wantHit {
				if got != nil {
					t.Fatalf("期望无命中，实际 %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("期望命中敏感规则，实际为 nil")
			}
			if got.Kind != tt.wantKind {
				t.Errorf("Kind=%s, want %s", got.Kind, tt.wantKind)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("Severity=%s, want %s", got.Severity, tt.wantSev)
			}
		})
	}
}

func TestClassifyPicksHighestSeverity(t *testing.T) {
	engine := NewEngine(nil)
	// UpdateConfig 同时命中 config-write(high) 与 generic-write(medium)
	m := &model.MethodInfo{Service: "admin.ConfigService", Name: "UpdateConfig",
		FullName: "/admin.ConfigService/UpdateConfig"}
	got := engine.Classify(m)
	if got == nil || got.Severity != model.SeverityHigh {
		t.Fatalf("应取最高等级 high，得到 %+v", got)
	}
	if len(got.Keywords) < 1 {
		t.Fatal("应记录命中规则名作为证据")
	}
}

func TestCustomRules(t *testing.T) {
	custom := []Rule{{
		Name:           "internal-flag",
		Kind:           model.KindInternal,
		Severity:       model.SeverityHigh,
		MethodKeywords: []string{"snapshot"},
	}}
	engine := NewEngine(custom)
	m := &model.MethodInfo{Service: "x.Y", Name: "TakeSnapshot", FullName: "/x.Y/TakeSnapshot"}
	got := engine.Classify(m)
	if got == nil || got.Kind != model.KindInternal {
		t.Fatalf("自定义规则未生效: %+v", got)
	}
}

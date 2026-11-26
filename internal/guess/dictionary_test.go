package guess

import (
	"testing"

	"github.com/internal/rpcrecon/internal/model"
)

func TestCandidatesDedupAndCap(t *testing.T) {
	d := Dictionary{
		Services: []string{"admin.AdminService", "admin.AdminService"},
		Methods:  []string{"FlushAll", "FlushAll", "UpdateConfig"},
	}
	got := Candidates(d, 100)
	if len(got) != 2 {
		t.Fatalf("应去重为 2 个候选，得到 %d", len(got))
	}
	seen := map[string]bool{}
	for _, m := range got {
		seen[m.FullName] = true
	}
	if !seen["/admin.AdminService/FlushAll"] || !seen["/admin.AdminService/UpdateConfig"] {
		t.Fatalf("候选内容错误: %v", seen)
	}
}

func TestCandidatesCap(t *testing.T) {
	d := DefaultDictionary()
	got := Candidates(d, 10)
	if len(got) != 10 {
		t.Fatalf("应严格遵守上限 10，得到 %d", len(got))
	}
}

func TestMarkGuessed(t *testing.T) {
	methods := []*model.MethodInfo{
		{Service: "a.S", Name: "M1", FullName: "/a.S/M1"},
		{Service: "a.S", Name: "M2", FullName: "/a.S/M2"},
		{Service: "b.S", Name: "M3", FullName: "/b.S/M3"},
	}
	svcs := MarkGuessed(methods)
	if len(svcs) != 2 {
		t.Fatalf("应归并为 2 个服务，得到 %d", len(svcs))
	}
	for _, s := range svcs {
		if s.Source != model.SourceGuess || s.Confidence >= 1.0 {
			t.Fatalf("猜测来源标记错误: %+v", s)
		}
	}
}

func TestDefaultDictionaryCoversHotspots(t *testing.T) {
	d := DefaultDictionary()
	all := Candidates(d, 10000)
	var hasFlushAll, hasUpdateConfig bool
	for _, m := range all {
		if m.Name == "FlushAll" {
			hasFlushAll = true
		}
		if m.Name == "UpdateConfig" {
			hasUpdateConfig = true
		}
	}
	if !hasFlushAll || !hasUpdateConfig {
		t.Fatal("内置字典必须覆盖 FlushAll/UpdateConfig 等事故高发方法")
	}
}

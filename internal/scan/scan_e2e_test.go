package scan_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/ratelimit"
	"github.com/internal/rpcrecon/internal/safe"
	"github.com/internal/rpcrecon/internal/scan"
	"github.com/internal/rpcrecon/internal/testutil/harness"
)

func newTestPolicy() safe.Policy {
	p := safe.DefaultPolicy()
	p.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	return p
}

func hostPort(t *testing.T, addr string) model.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return model.Target{Host: host, Port: port, Source: "test"}
}

// TestEndToEndReflection 验证完整流水线在反射开启时的结论与零副作用。
func TestEndToEndReflection(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	scanner, err := scan.New(scan.Config{
		Policy:      newTestPolicy(),
		Concurrency: ratelimit.Config{GlobalConcurrency: 4, HostConcurrency: 2, QPS: 50},
		EnableGuess: false, // 本用例只验证反射路径
		ScanID:      "e2e-reflection",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rep := scanner.Run(ctx, []model.Target{hostPort(t, h.GRPCAddr)})

	if rep.LiveEndpoints != 1 {
		t.Fatalf("应识别 1 个存活端点，得到 %d", rep.LiveEndpoints)
	}
	if rep.Stats.ReflectionOpen != 1 {
		t.Fatal("反射应被识别为未授权开放")
	}

	ep := rep.Endpoints[0]
	if !ep.Reflection.Enabled || !ep.Reflection.Unauth || !ep.Reflection.V1 {
		t.Fatalf("反射状态错误: %+v", ep.Reflection)
	}

	// 必须枚举出两个服务
	services := map[string]*model.ServiceInfo{}
	for _, s := range ep.Services {
		services[s.Name] = s
	}
	if _, ok := services[harness.AdminService]; !ok {
		t.Fatalf("未枚举出 AdminService: %v", serviceNames(ep.Services))
	}
	if _, ok := services[harness.BizService]; !ok {
		t.Fatalf("未枚举出 BizService: %v", serviceNames(ep.Services))
	}

	// 找方法结论
	findings := indexFindings(rep)
	if f, ok := findings["/testcorp.v1.AdminService/FlushAll"]; !ok {
		t.Fatal("FlushAll 应产生发现项")
	} else {
		if f.Exposure != model.ExposureUnauthenticated {
			t.Fatalf("FlushAll 应未授权可触达，得到 %s", f.Exposure)
		}
		if f.Severity != model.SeverityCritical {
			t.Fatalf("FlushAll 应为 critical，得到 %s", f.Severity)
		}
	}
	if f, ok := findings["/testcorp.v1.AdminService/UpdateConfig"]; !ok {
		t.Fatal("UpdateConfig 应产生发现项")
	} else if f.Exposure != model.ExposureUnauthenticated {
		t.Fatalf("UpdateConfig 应未授权可触达，得到 %s", f.Exposure)
	}

	// BizService 受鉴权保护，不得出现在未授权发现里
	if _, ok := findings["/testcorp.v1.BizService/GetData"]; ok {
		t.Fatal("受保护的 BizService.GetData 不应判为未授权")
	}

	// 关键安全断言：整个扫描过程中 FlushAll 的业务体一次都没执行
	if got := h.FlushCount.Load(); got != 0 {
		t.Fatalf("探测触发了副作用！FlushAll 实际执行 %d 次", got)
	}

	// 反射开放本身应是一条发现
	var hasReflectionFinding bool
	for _, f := range rep.Findings {
		if f.Kind == model.KindReflection {
			hasReflectionFinding = true
		}
	}
	if !hasReflectionFinding {
		t.Fatal("缺少反射开放发现项")
	}
}

// TestEndToEndGuessMode 验证反射关闭场景下字典猜测仍能定位管理方法。
func TestEndToEndGuessMode(t *testing.T) {
	// 同一靶场：反射仍在，但本用例显式禁用反射枚举，强制走猜测路径
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	policy := newTestPolicy()
	policy.EnableReflection = false // 模拟"服务关了反射"

	// 自定义字典注入靶场服务名（等价于内网团队按自家命名习惯维护字典）
	dictPath := writeGuessDictionary(t)

	scanner, err := scan.New(scan.Config{
		Policy:      policy,
		Concurrency: ratelimit.Config{GlobalConcurrency: 4, HostConcurrency: 2, QPS: 100},
		EnableGuess: true,
		MaxGuesses:  400,
		DictFile:    dictPath,
		ScanID:      "e2e-guess",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep := scanner.Run(ctx, []model.Target{hostPort(t, h.GRPCAddr)})

	findings := indexFindings(rep)
	f, ok := findings["/testcorp.v1.AdminService/FlushAll"]
	if !ok {
		t.Fatal("猜测模式也应通过返回码差异定位到真实存在的 FlushAll")
	}
	if f.Source != model.SourceGuess {
		t.Fatalf("来源应标记为 guess，得到 %s", f.Source)
	}
	if f.Exposure != model.ExposureUnauthenticated {
		t.Fatalf("FlushAll 应判未授权，得到 %s", f.Exposure)
	}

	// 猜测产生的大量不存在方法必须被判 skipped，而不是误报
	var skippedUnimplemented int
	for _, ep := range rep.Endpoints {
		for _, svc := range ep.Services {
			for _, m := range svc.Methods {
				if m.Probe != nil && m.Probe.Exposure == model.ExposureSkipped &&
					m.Probe.GRPCCode == "Unimplemented" {
					skippedUnimplemented++
				}
			}
		}
	}
	if skippedUnimplemented == 0 {
		t.Fatal("猜测未命中的方法应留下 Unimplemented→skipped 记录")
	}

	if got := h.FlushCount.Load(); got != 0 {
		t.Fatalf("猜测探测同样不能触发副作用，实际执行 %d 次", got)
	}
}

func indexFindings(rep *model.Report) map[string]model.Finding {
	out := make(map[string]model.Finding)
	for _, f := range rep.Findings {
		if f.Method != "" {
			out[f.Method] = f
		}
	}
	return out
}

func serviceNames(in []*model.ServiceInfo) []string {
	var out []string
	for _, s := range in {
		out = append(out, s.Name)
	}
	return out
}

// writeGuessDictionary 写一份包含靶场服务名和若干诱饵方法的字典。
func writeGuessDictionary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dict.json")
	content := `{
  "services": ["testcorp.v1.AdminService"],
  "methods": ["FlushAll", "UpdateConfig", "Debug", "DoesNotExist", "GhostMethod"]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

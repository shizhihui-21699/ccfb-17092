package discover

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/internal/rpcrecon/internal/safe"
)

func TestEnumerateCIDR(t *testing.T) {
	policy := safe.DefaultPolicy()
	policy.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

	targets, err := Enumerate(context.Background(), Spec{
		CIDRs: []string{"127.0.0.0/30"},
		Ports: []int{50051},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	// /30 有 4 个地址，去掉网络地址与广播地址后剩 2 个
	if len(targets) != 2 {
		t.Fatalf("应生成 2 个可用主机目标，得到 %d: %+v", len(targets), targets)
	}
	for _, tg := range targets {
		if tg.Port != 50051 || tg.Source == "" {
			t.Fatalf("目标字段异常: %+v", tg)
		}
	}
}

func TestEnumerateRejectsOversizedCIDR(t *testing.T) {
	policy := safe.DefaultPolicy()
	_, err := Enumerate(context.Background(), Spec{
		CIDRs: []string{"10.0.0.0/16"},
		Ports: []int{80},
	}, policy)
	if err == nil {
		t.Fatal("/16 必须被拒绝以防扫全网")
	}
}

func TestEnumerateDenyWins(t *testing.T) {
	policy := safe.DefaultPolicy()
	policy.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	policy.DenyCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/30")}
	_, err := Enumerate(context.Background(), Spec{
		CIDRs: []string{"127.0.0.0/30"},
		Ports: []int{80},
	}, policy)
	if err == nil {
		t.Fatal("拒绝网段优先级应高于允许网段")
	}
}

func TestParsePortSpec(t *testing.T) {
	ports, ranges, err := ParsePortSpec("50051,9000-9002, 9100")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 50051 || ports[1] != 9100 {
		t.Fatalf("离散端口解析错误: %v", ports)
	}
	if len(ranges) != 1 || ranges[0].From != 9000 || ranges[0].To != 9002 {
		t.Fatalf("端口段解析错误: %+v", ranges)
	}
}

func TestTargetFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	// 仅包含 IP 目标 + 注释 + 重复行（主机名目标的处理见 TestHostnameRejected）
	content := "# 注释行\n127.0.0.1:50051\n\n127.0.0.1:50051\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := safe.DefaultPolicy()
	policy.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

	targets, err := Enumerate(context.Background(), Spec{TargetFiles: []string{path}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	// 两个 127.0.0.1:50051 去重后只剩 1 个
	if len(targets) != 1 || targets[0].Host != "127.0.0.1" {
		t.Fatalf("文件目标解析/去重错误: %+v", targets)
	}
}

func TestHostnameRejectedBeforeResolution(t *testing.T) {
	policy := safe.DefaultPolicy()
	// 主机名无法直接做网段授权判断，必须先解析为 IP，防止 DNS rebinding 绕过白名单
	_, err := Enumerate(context.Background(), Spec{
		Extras: []string{"localhost:50051"},
	}, policy)
	if err == nil {
		t.Fatal("未解析的主机名目标必须被拒绝")
	}
}

func TestMaxEndpointsCap(t *testing.T) {
	policy := safe.DefaultPolicy()
	policy.MaxEndpoints = 3
	policy.AllowCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	_, err := Enumerate(context.Background(), Spec{
		CIDRs: []string{"127.0.0.0/29"}, // 6 个可用地址
		Ports: []int{80, 81},
	}, policy)
	if err == nil {
		t.Fatal("超过 MaxEndpoints 必须报错中止")
	}
}

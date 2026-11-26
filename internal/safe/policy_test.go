package safe

import (
	"net/netip"
	"testing"

	"github.com/internal/rpcrecon/internal/model"
)

func TestPolicyCheckTarget(t *testing.T) {
	allow := mustPrefixes(t, "10.0.0.0/8")
	deny := mustPrefixes(t, "10.1.0.0/16")

	p := DefaultPolicy()
	p.AllowCIDRs = allow
	p.DenyCIDRs = deny

	tests := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{"允许网段内", "10.0.0.5", 50051, false},
		{"命中拒绝网段", "10.1.2.3", 50051, true},
		{"不在白名单", "192.168.1.1", 50051, true},
		{"非法端口", "10.0.0.5", 0, true},
		{"非法端口上限", "10.0.0.5", 70000, true},
		{"主机名拒绝直接校验", "db.internal", 50051, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.CheckTarget(tt.host, tt.port)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckTarget(%s,%d) err=%v, wantErr=%v", tt.host, tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestPolicyCheckIP(t *testing.T) {
	p := DefaultPolicy()
	p.DenyCIDRs = mustPrefixes(t, "169.254.0.0/16") // 链路本地/元数据服务网段
	ip := netip.MustParseAddr("169.254.169.254")
	if err := p.CheckIP(ip); err == nil {
		t.Fatal("云元数据地址应被拒绝")
	}
}

func TestMalformedPayloadIsUndecodable(t *testing.T) {
	// 0xFF 单独一个字节不可能是合法 protobuf：varint 首字节声称还有 9 个续接字节
	if len(MalformedPayload) != 1 || MalformedPayload[0] != 0xFF {
		t.Fatalf("非法载荷被改动: %v", MalformedPayload)
	}
}

func TestDecideMethod(t *testing.T) {
	p := DefaultPolicy() // 最保守默认

	t.Run("流式方法默认跳过", func(t *testing.T) {
		m := &model.MethodInfo{IsStreaming: true}
		d := p.DecideMethod(m)
		if d.Allowed || d.PayloadKind != "none" {
			t.Fatalf("流式方法应跳过，得到 %+v", d)
		}
	})

	t.Run("一元方法只发非法载荷", func(t *testing.T) {
		m := &model.MethodInfo{IsStreaming: false}
		d := p.DecideMethod(m)
		if !d.Allowed || d.PayloadKind != "malformed-wire" {
			t.Fatalf("一元方法应使用非法载荷，得到 %+v", d)
		}
	})

	t.Run("开启空消息后变异方法仍强制非法载荷", func(t *testing.T) {
		relaxed := p
		relaxed.AllowEmptyPayload = true
		m := &model.MethodInfo{
			IsStreaming: false,
			Sensitive:   &model.SensitiveMatch{Kind: model.KindCache},
		}
		d := relaxed.DecideMethod(m)
		if !d.Allowed || d.PayloadKind != "malformed-wire" {
			t.Fatalf("变异类方法必须保持非法载荷，得到 %+v", d)
		}
	})
}

func TestHTTPAllowedPath(t *testing.T) {
	p := DefaultPolicy()
	if err := p.HTTPAllowedPath("/metrics"); err != nil {
		t.Fatalf("只读路径应允许: %v", err)
	}
	if err := p.HTTPAllowedPath("/admin/flushall"); err == nil {
		t.Fatal("动作型路径必须拒绝")
	}
	p2 := p
	p2.ProbeHTTPAdmin = false
	if err := p2.HTTPAllowedPath("/metrics"); err == nil {
		t.Fatal("关闭开关后应全部拒绝")
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

package grpcx_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/internal/rpcrecon/internal/grpcx"
	"github.com/internal/rpcrecon/internal/safe"
	"github.com/internal/rpcrecon/internal/testutil/harness"
)

func TestInvokeRawMalformedPayload(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpcx.Dial(ctx, h.GRPCAddr, false, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 1. 对真实存在但无鉴权的管理方法发非法载荷：应越过鉴权、在解码阶段失败
	_, code, _, msg, err := grpcx.InvokeRaw(ctx, conn,
		"/testcorp.v1.AdminService/FlushAll", safe.MalformedPayload, nil)
	if err == nil {
		t.Fatal("非法载荷必须返回错误，不能成功")
	}
	if code != "Internal" {
		t.Fatalf("期望 Internal（解码失败），得到 %s: %s", code, msg)
	}
	if !strings.Contains(msg, "wire-format") && !strings.Contains(msg, "unmarshal") {
		t.Fatalf("错误消息应表明 proto 解码失败，得到 %q", msg)
	}

	// 2. 关键安全断言：解码失败保证业务体没跑
	if got := h.FlushCount.Load(); got != 0 {
		t.Fatalf("FlushAll 被实际执行 %d 次，零副作用保证失效", got)
	}

	// 3. 受保护的业务方法应返回 Unauthenticated（拦截器先于解码执行）
	_, code2, _, _, _ := grpcx.InvokeRaw(ctx, conn,
		"/testcorp.v1.BizService/GetData", safe.MalformedPayload, nil)
	if code2 != "Unauthenticated" {
		t.Fatalf("期望 Unauthenticated，得到 %s", code2)
	}

	// 4. 不存在的方法返回 Unimplemented，作为基线
	_, code3, _, _, _ := grpcx.InvokeRaw(ctx, conn,
		"/__rpcrecon__/BaselineProbe", safe.MalformedPayload, nil)
	if code3 != "Unimplemented" {
		t.Fatalf("基线方法应返回 Unimplemented，得到 %s", code3)
	}
}

func TestFingerprintPlaintext(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport, tlsEnabled, conn, err := grpcx.Fingerprint(ctx, h.GRPCAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if transport != "grpc" || tlsEnabled {
		t.Fatalf("明文靶场应识别为 grpc/h2c，得到 %s tls=%v", transport, tlsEnabled)
	}
}

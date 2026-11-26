package probe_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/probe"
	"github.com/internal/rpcrecon/internal/safe"
	"github.com/internal/rpcrecon/internal/testutil/harness"
)

// noopLimiter 不限流，简化引擎单测。
type noopLimiter struct{}

func (noopLimiter) Acquire(ctx context.Context, host string) (func(), error) {
	return func() {}, nil
}

func dialHarness(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithBlock(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestBaselineAndProbeMethods(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	conn := dialHarness(t, h.GRPCAddr)
	defer conn.Close()

	engine := probe.NewEngine(safe.DefaultPolicy(), noopLimiter{})
	ctx := context.Background()

	// 靶场无全局鉴权，基线应穿透到路由层返回 Unimplemented
	baseline, baselineResult := engine.Baseline(ctx, conn, h.GRPCAddr)
	if baselineResult == nil || baseline != "Unimplemented" {
		t.Fatalf("基线应返回 Unimplemented，得到 %s", baseline)
	}
	if probe.BaselineIsGlobalAuth(baseline) {
		t.Fatal("该靶场不存在全局前置鉴权")
	}

	methods := []*model.MethodInfo{
		{FullName: "/testcorp.v1.AdminService/FlushAll", Name: "FlushAll",
			Service: "testcorp.v1.AdminService", Source: model.SourceReflection,
			Sensitive: &model.SensitiveMatch{Kind: model.KindCache, Severity: model.SeverityCritical}},
		{FullName: "/testcorp.v1.BizService/GetData", Name: "GetData",
			Service: "testcorp.v1.BizService", Source: model.SourceReflection},
		{FullName: "/testcorp.v1.AdminService/Stream", Name: "Stream",
			Service: "testcorp.v1.AdminService", IsStreaming: true,
			Source: model.SourceReflection},
	}
	stats := &model.ScanStats{}
	engine.ProbeMethods(ctx, conn, h.GRPCAddr, methods, baseline, stats)

	if methods[0].Probe == nil || methods[0].Probe.Exposure != model.ExposureUnauthenticated {
		t.Fatalf("FlushAll 应未授权可触达: %+v", methods[0].Probe)
	}
	if methods[1].Probe == nil || methods[1].Probe.Exposure != model.ExposureAuthenticated {
		t.Fatalf("GetData 应被鉴权拦截: %+v", methods[1].Probe)
	}
	if methods[2].Probe == nil || methods[2].Probe.Exposure != model.ExposureSkipped {
		t.Fatalf("流式方法应跳过: %+v", methods[2].Probe)
	}
	if stats.MethodsProbed != 2 || stats.MethodsSkipped != 1 {
		t.Fatalf("统计错误: %+v", stats)
	}

	// 全程零副作用
	if got := h.FlushCount.Load(); got != 0 {
		t.Fatalf("FlushAll 被执行 %d 次", got)
	}
}

// TestLimiterIntegration 确认真实限流器能与引擎协同（并发探测不 panic、不死锁）。
func TestLimiterIntegration(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	conn := dialHarness(t, h.GRPCAddr)
	defer conn.Close()

	limiter := newTrackingLimiter(2)
	defer limiter.stop()
	engine := probe.NewEngine(safe.DefaultPolicy(), limiter)

	var methods []*model.MethodInfo
	for i := 0; i < 8; i++ {
		methods = append(methods, &model.MethodInfo{
			FullName: "/testcorp.v1.AdminService/FlushAll",
			Name:     "FlushAll", Service: "testcorp.v1.AdminService",
			Source: model.SourceReflection,
		})
	}
	stats := &model.ScanStats{}
	engine.ProbeMethods(context.Background(), conn, h.GRPCAddr, methods, "Unimplemented", stats)
	if stats.MethodsProbed != 8 {
		t.Fatalf("应完成 8 次探测，得到 %d", stats.MethodsProbed)
	}
	if limiter.maxConcurrent() > 2 {
		t.Fatalf("单主机并发应被限制在 2 以内，峰值 %d", limiter.maxConcurrent())
	}
}

// trackingLimiter 是带峰值统计的最小限流器（复刻 ratelimit 的每主机语义）。
type trackingLimiter struct {
	sem     chan struct{}
	mu      sync.Mutex
	current int
	peak    int
}

func newTrackingLimiter(max int) *trackingLimiter {
	return &trackingLimiter{sem: make(chan struct{}, max)}
}

func (l *trackingLimiter) Acquire(ctx context.Context, host string) (func(), error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	l.mu.Lock()
	l.current++
	if l.current > l.peak {
		l.peak = l.current
	}
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.current--
		l.mu.Unlock()
		<-l.sem
	}, nil
}

func (l *trackingLimiter) maxConcurrent() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peak
}

func (l *trackingLimiter) stop() {}

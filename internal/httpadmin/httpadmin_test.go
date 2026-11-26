package httpadmin_test

import (
	"context"
	"testing"

	"github.com/internal/rpcrecon/internal/httpadmin"
	"github.com/internal/rpcrecon/internal/safe"
	"github.com/internal/rpcrecon/internal/testutil/harness"
)

func TestHTTPAdminProbe(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	prober := httpadmin.New(safe.DefaultPolicy())
	findings := prober.Probe(context.Background(), "http://"+h.HTTPAddr)

	exposed := map[string]bool{}
	for _, f := range findings {
		if f.Exposed {
			exposed[f.Path] = true
		}
	}
	if !exposed["/healthz"] {
		t.Fatal("/healthz 应识别为未授权暴露")
	}
	if !exposed["/metrics"] {
		t.Fatal("/metrics 应识别为未授权暴露")
	}
	if !exposed["/debug/pprof/"] {
		t.Fatal("/debug/pprof/ 应识别为未授权暴露")
	}
}

func TestHTTPAdminRespectsSwitch(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	policy := safe.DefaultPolicy()
	policy.ProbeHTTPAdmin = false
	prober := httpadmin.New(policy)
	if got := prober.Probe(context.Background(), "http://"+h.HTTPAddr); len(got) != 0 {
		t.Fatalf("关闭开关后不应有任何探测，得到 %d 条", len(got))
	}
}

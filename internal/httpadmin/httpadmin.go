// Package httpadmin 探测与 gRPC 共用端口（或同主机）的 HTTP 管理面。
//
// Go 服务常用 cmux 在同一端口同时服务 gRPC 与 HTTP，pprof / metrics /
// healthz / debug/pprof 等管理端点因此和业务方法暴露在同一攻击面上。
// 本包只发 GET 请求，且路径经过 safe.Policy 白名单校验，绝不触发动作型接口。
package httpadmin

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/safe"
)

// PathSpec 描述一个待检查的只读管理路径。
type PathSpec struct {
	Path string
	Kind model.SensitiveKind
}

// DefaultPaths 是 Go 生态常见管理端点。
var DefaultPaths = []PathSpec{
	{"/debug/pprof/", model.KindDebug},
	{"/debug/pprof/cmdline", model.KindDebug},
	{"/debug/pprof/goroutine", model.KindDebug},
	{"/debug/pprof/heap", model.KindDebug},
	{"/debug/vars", model.KindDebug},
	{"/metrics", model.KindDebug},
	{"/healthz", model.KindHealth},
	{"/readyz", model.KindHealth},
	{"/livez", model.KindHealth},
	{"/status", model.KindHealth},
	{"/admin/health", model.KindAdmin},
}

// Prober 执行 HTTP 管理面探测。
type Prober struct {
	policy safe.Policy
	client *http.Client
	paths  []PathSpec
}

// New 构造 Prober。
func New(policy safe.Policy) *Prober {
	return &Prober{
		policy: policy,
		client: &http.Client{Timeout: 5 * time.Second},
		paths:  DefaultPaths,
	}
}

// Probe 对 httpBase（如 http://10.0.0.1:9000）执行路径检查。
// 同端口 gRPC/HTTP 复用场景下，HTTP/1.1 请求会被 cmux 路由到 HTTP handler。
func (p *Prober) Probe(ctx context.Context, httpBase string) []model.HTTPPathFinding {
	var out []model.HTTPPathFinding
	for _, spec := range p.paths {
		if err := p.policy.HTTPAllowedPath(spec.Path); err != nil {
			continue
		}
		select {
		case <-ctx.Done():
			return out
		default:
		}
		finding := p.checkOne(ctx, httpBase, spec)
		if finding != nil {
			out = append(out, *finding)
		}
	}
	return out
}

func (p *Prober) checkOne(ctx context.Context, base string, spec PathSpec) *model.HTTPPathFinding {
	url := strings.TrimRight(base, "/") + spec.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	// 明确标识扫描工具，避免伪装成正常业务流量
	req.Header.Set("User-Agent", "rpcrecon/0.1 (authorized-security-scan)")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil // 端口不提供 HTTP 或连接失败，静默跳过
	}
	defer resp.Body.Close()
	// 只读探测：丢弃响应体，避免把大文件拉回（pprof profile 可能较大）
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	exposed := resp.StatusCode == http.StatusOK
	f := &model.HTTPPathFinding{
		Path:       spec.Path,
		StatusCode: resp.StatusCode,
		Exposed:    exposed,
		Kind:       spec.Kind,
	}
	switch {
	case exposed && spec.Kind == model.KindDebug:
		f.Note = "调试/指标端点未授权可读，可能泄露 goroutine、环境变量、内存数据"
	case exposed:
		f.Note = "管理端点可未授权访问"
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		f.Note = "端点存在但有鉴权"
	default:
		f.Note = "端点存在但非 200，按未暴露处理"
	}
	return f
}

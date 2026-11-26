// Package scan 编排完整探测流水线：
//
//	目标生成 → TCP 存活 → 传输指纹 → 反射枚举 / 描述文件 / 字典猜测
//	→ 敏感分类 → 基线探测 → 无害方法探测 → HTTP 管理面 → 汇总报告
package scan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/internal/rpcrecon/internal/classify"
	"github.com/internal/rpcrecon/internal/descriptors"
	"github.com/internal/rpcrecon/internal/grpcx"
	"github.com/internal/rpcrecon/internal/guess"
	"github.com/internal/rpcrecon/internal/httpadmin"
	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/probe"
	"github.com/internal/rpcrecon/internal/ratelimit"
	"github.com/internal/rpcrecon/internal/reflection"
	"github.com/internal/rpcrecon/internal/safe"
)

// Config 是扫描器配置。
type Config struct {
	Policy        safe.Policy
	Concurrency   ratelimit.Config
	DescriptorDir string // 本地 FileDescriptorSet 目录（反射关闭时使用）
	DictFile      string // 自定义猜测字典
	RulesFile     string // 自定义敏感规则
	EnableGuess   bool   // 反射与描述文件都失败时是否启用字典猜测
	MaxGuesses    int    // 每端点最大猜测数
	ScanID        string
}

// Scanner 是无状态的扫描编排器（状态都在一次 Run 内）。
type Scanner struct {
	cfg       Config
	limiter   *ratelimit.Limiter
	engine    *probe.Engine
	classer   *classify.Engine
	httpProbe *httpadmin.Prober
	dict      guess.Dictionary
	descCache []*model.ServiceInfo
}

// New 构造扫描器，预加载字典、规则、描述文件。
func New(cfg Config) (*Scanner, error) {
	limiter := ratelimit.New(cfg.Concurrency)
	engine := probe.NewEngine(cfg.Policy, limiter)

	var extraRules []classify.Rule
	if cfg.RulesFile != "" {
		rules, err := classify.LoadRules(cfg.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("加载规则文件: %w", err)
		}
		extraRules = rules
	}

	dict := guess.DefaultDictionary()
	if cfg.DictFile != "" {
		d, err := guess.LoadDictionary(cfg.DictFile)
		if err != nil {
			return nil, fmt.Errorf("加载字典文件: %w", err)
		}
		dict = d
	}

	var descServices []*model.ServiceInfo
	if cfg.DescriptorDir != "" {
		svcs, err := descriptors.LoadDir(cfg.DescriptorDir)
		if err != nil {
			return nil, fmt.Errorf("加载描述文件目录: %w", err)
		}
		descServices = svcs
	}

	if cfg.MaxGuesses <= 0 {
		cfg.MaxGuesses = 200
	}

	return &Scanner{
		cfg:       cfg,
		limiter:   limiter,
		engine:    engine,
		classer:   classify.NewEngine(extraRules),
		httpProbe: httpadmin.New(cfg.Policy),
		dict:      dict,
		descCache: descServices,
	}, nil
}

// Close 释放限流器后台协程。
func (s *Scanner) Close() { s.limiter.Stop() }

// Run 对全部目标执行扫描，返回报告。
func (s *Scanner) Run(ctx context.Context, targets []model.Target) *model.Report {
	report := &model.Report{
		ScanID:    s.cfg.ScanID,
		StartedAt: time.Now(),
		Targets:   len(targets),
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, s.cfg.Concurrency.GlobalConcurrency)
	)

	for _, t := range targets {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target model.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			ep := s.scanOne(ctx, target, &report.Stats)
			if ep == nil {
				return
			}
			mu.Lock()
			report.Endpoints = append(report.Endpoints, ep)
			report.LiveEndpoints++
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	s.buildFindings(report)
	report.FinishedAt = time.Now()
	return report
}

// scanOne 扫描单个目标，任何阶段失败都返回 nil（不可达）或部分结果。
func (s *Scanner) scanOne(ctx context.Context, target model.Target, stats *model.ScanStats) *model.Endpoint {
	addr := target.Addr()

	// 1. TCP 存活检查（快速剔除死地址，节省拨号成本）
	if !tcpAlive(ctx, addr) {
		return nil
	}
	stats.TCPProbed++

	// 2. 传输指纹 + gRPC 拨号
	transport, tlsEnabled, conn, err := grpcx.Fingerprint(ctx, addr)
	if err != nil || conn == nil {
		return nil
	}
	defer conn.Close()
	stats.GRPCIdentified++

	ep := &model.Endpoint{
		Target:    target,
		Transport: model.Transport(transport),
		IsGRPC:    true,
		ProbedAt:  time.Now(),
		Source:    target.Source,
	}
	_ = tlsEnabled

	// 3. 枚举方法：反射 → 描述文件 → 猜测
	var services []*model.ServiceInfo
	if s.cfg.Policy.EnableReflection {
		res, rerr := reflection.Enumerate(ctx, conn)
		if rerr == nil && res != nil {
			ep.Reflection = res.Status
			if res.Status.Enabled && res.Status.Unauth {
				stats.ReflectionOpen++
			}
			services = append(services, res.Services...)
		}
	}

	// 描述文件按服务名匹配（描述文件是全局的，适用于所有端点）
	if len(services) == 0 && len(s.descCache) > 0 {
		services = append(services, cloneServices(s.descCache)...)
	}

	guessed := false
	if len(services) == 0 && s.cfg.EnableGuess {
		candidates := guess.Candidates(s.dict, s.cfg.MaxGuesses)
		services = guess.MarkGuessed(candidates)
		guessed = true
		stats.MethodsGuessed += len(candidates)
	}

	// 4. 敏感分类
	allMethods := make([]*model.MethodInfo, 0)
	for _, svc := range services {
		for _, m := range svc.Methods {
			m.Sensitive = s.classer.Classify(m)
			allMethods = append(allMethods, m)
			if !guessed {
				stats.MethodsEnumerated++
			}
		}
	}
	ep.Services = services

	// 5. 基线探测
	baseline, baselineResult := s.engine.Baseline(ctx, conn, addr)
	_ = baselineResult

	// 6. 方法探测
	if probe.BaselineIsGlobalAuth(baseline) {
		// 全局前置鉴权：所有方法统一标记，省去逐方法请求
		for _, m := range allMethods {
			m.Probe = &model.ProbeResult{
				Exposure:     model.ExposureAuthenticated,
				GRPCCode:     baseline,
				BaselineCode: baseline,
				PayloadKind:  "malformed-wire",
				Confidence:   0.95,
				Notes:        []string{"基线探测证实全局前置鉴权，方法不再单独发请求"},
			}
			stats.MethodsSkipped++
		}
	} else {
		s.engine.ProbeMethods(ctx, conn, addr, allMethods, baseline, stats)
	}

	// 7. 同端口 HTTP 管理面
	if s.cfg.Policy.ProbeHTTPAdmin {
		scheme := "http"
		if tlsEnabled {
			scheme = "https"
		}
		ep.HTTPAdmin = s.httpProbe.Probe(ctx, scheme+"://"+addr)
		for _, f := range ep.HTTPAdmin {
			if f.Exposed {
				stats.HTTPAdminExposed++
			}
		}
	}

	return ep
}

func tcpAlive(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func cloneServices(in []*model.ServiceInfo) []*model.ServiceInfo {
	out := make([]*model.ServiceInfo, len(in))
	for i, svc := range in {
		dup := &model.ServiceInfo{
			Name: svc.Name, Source: svc.Source, Confidence: svc.Confidence,
		}
		for _, m := range svc.Methods {
			cp := *m
			dup.Methods = append(dup.Methods, &cp)
		}
		out[i] = dup
	}
	return out
}

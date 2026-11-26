// rpcrecon 是内网 gRPC/HTTP 服务暴露面探测工具。
//
// 安全设计见 internal/safe/policy.go：默认只发必然解码失败的非法 wire 字节，
// 业务 handler 不会执行；流式方法默认跳过；HTTP 只做只读 GET。
package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/internal/rpcrecon/internal/discover"
	"github.com/internal/rpcrecon/internal/ratelimit"
	"github.com/internal/rpcrecon/internal/report"
	"github.com/internal/rpcrecon/internal/safe"
	"github.com/internal/rpcrecon/internal/scan"
)

func main() {
	var (
		cidrs         = pflag.StringArray("cidr", nil, "授权扫描网段，可重复，如 10.0.0.0/24")
		portSpec      = pflag.String("ports", "50051,9000,9100", "端口规格，如 50051,9000-9100")
		targets       = pflag.StringArray("target", nil, "显式目标 host:port，可重复")
		targetFiles   = pflag.StringArray("target-file", nil, "目标清单文件（host:port 一行一个），可重复")
		allowCIDRs    = pflag.StringArray("allow-cidr", nil, "授权网段白名单，非空时只允许探测这些网段")
		denyCIDRs     = pflag.StringArray("deny-cidr", nil, "拒绝网段，优先级高于 allow")
		maxEndpoints  = pflag.Int("max-endpoints", 10000, "目标数量硬上限")
		concurrency   = pflag.Int("concurrency", 50, "全局并发")
		hostConc      = pflag.Int("host-concurrency", 4, "单主机并发")
		qps           = pflag.Int("qps", 200, "全局每秒请求上限，0 表示不限")
		timeout       = pflag.Duration("timeout", 3*time.Minute, "整体扫描超时")
		descriptorDir = pflag.String("descriptors", "", "本地 FileDescriptorSet 目录（反射关闭时使用）")
		dictFile      = pflag.String("dictionary", "", "自定义猜测字典 JSON")
		rulesFile     = pflag.String("rules", "", "自定义敏感规则 JSON")
		enableGuess   = pflag.Bool("guess", true, "反射与描述文件都失败时启用字典猜测")
		maxGuesses    = pflag.Int("max-guesses", 200, "每端点最大猜测方法数")
		noReflection  = pflag.Bool("no-reflection", false, "禁用 gRPC 反射枚举")
		noHTTP        = pflag.Bool("no-http-admin", false, "禁用同端口 HTTP 管理面探测")
		probeStream   = pflag.Bool("probe-streaming", false, "允许探测流式方法（默认关闭，半条流即可触发业务）")
		allowEmpty    = pflag.Bool("allow-empty-payload", false, "允许对只读方法追加一轮空合法消息探测（默认关闭）")
		dryRun        = pflag.Bool("dry-run", false, "只生成目标与探测计划，不发业务请求")
		output        = pflag.String("output", "", "JSON 报告输出路径")
		verbose       = pflag.Bool("verbose", false, "输出端点级明细")
	)
	pflag.Parse()

	ctx, cancel := signalContext()
	defer cancel()
	scanCtx, cancelScan := context.WithTimeout(ctx, *timeout)
	defer cancelScan()

	// 1. 安全策略
	policy := safe.DefaultPolicy()
	policy.MaxEndpoints = *maxEndpoints
	policy.EnableReflection = !*noReflection
	policy.ProbeHTTPAdmin = !*noHTTP
	policy.ProbeStreaming = *probeStream
	policy.AllowEmptyPayload = *allowEmpty
	policy.DryRun = *dryRun

	var err error
	if policy.AllowCIDRs, err = parsePrefixes(*allowCIDRs); err != nil {
		fatal(err)
	}
	if policy.DenyCIDRs, err = parsePrefixes(*denyCIDRs); err != nil {
		fatal(err)
	}
	if len(policy.AllowCIDRs) == 0 {
		// 没有显式白名单时，把 --cidr 参数本身作为授权范围，防止扫偏
		if policy.AllowCIDRs, err = parsePrefixes(*cidrs); err != nil {
			fatal(err)
		}
	}

	// 2. 目标生成
	ports, portRanges, err := discover.ParsePortSpec(*portSpec)
	if err != nil {
		fatal(err)
	}
	spec := discover.Spec{
		CIDRs:       *cidrs,
		Ports:       ports,
		PortRanges:  portRanges,
		TargetFiles: *targetFiles,
		Extras:      *targets,
	}
	allTargets, err := discover.Enumerate(scanCtx, spec, policy)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("生成目标 %d 个（授权网段 %d 个，拒绝网段 %d 个）\n",
		len(allTargets), len(policy.AllowCIDRs), len(policy.DenyCIDRs))

	if *dryRun {
		for _, t := range allTargets {
			fmt.Printf("[dry-run] %s (%s)\n", t.Addr(), t.Source)
		}
		fmt.Println("dry-run 模式：未建立任何连接")
		return
	}

	// 3. 扫描器
	scanner, err := scan.New(scan.Config{
		Policy:        policy,
		Concurrency:   ratelimit.Config{GlobalConcurrency: *concurrency, HostConcurrency: *hostConc, QPS: *qps},
		DescriptorDir: *descriptorDir,
		DictFile:      *dictFile,
		RulesFile:     *rulesFile,
		EnableGuess:   *enableGuess,
		MaxGuesses:    *maxGuesses,
		ScanID:        time.Now().Format("20060102-150405"),
	})
	if err != nil {
		fatal(err)
	}
	defer scanner.Close()

	// 4. 执行
	rep := scanner.Run(scanCtx, allTargets)

	// 5. 输出
	report.RenderText(os.Stdout, rep, *verbose)
	if *output != "" {
		if err := report.WriteJSON(*output, rep); err != nil {
			fatal(err)
		}
		fmt.Printf("\nJSON 报告已写入 %s\n", *output)
	}

	// 有未授权发现时以非零码退出，便于接入 CI/巡检流水线
	if rep.Stats.UnauthFindings > 0 {
		os.Exit(2)
	}
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("解析网段 %q: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}

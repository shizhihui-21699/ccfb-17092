// Package probe 实现"不触发副作用"的未授权可达性探测。
//
// 探测协议（每个端点）：
//
//  1. 基线探测：调用一个几乎不可能存在的方法 /__rpcrecon__/BaselineProbe，
//     载荷同样是非法 wire 字节 0xFF。
//     - 基线返回 Unauthenticated/PermissionDenied → 存在全局前置鉴权，
//     该端点上所有方法都会被同一层拦截，直接整体标记 authenticated。
//     - 基线返回 Unimplemented/Internal/InvalidArgument → 请求能到达路由/
//     解码层，不存在全局前置鉴权，各方法结果具备区分度。
//
//  2. 方法探测：对每个候选方法发送同样的 0xFF。
//     - Unauthenticated/PermissionDenied → 方法级鉴权生效（authenticated）
//     - Unimplemented → 方法不存在（猜测未命中，不计发现项）
//     - Internal/InvalidArgument/Unknown 等 → 越过鉴权到达解码阶段，
//     说明未授权可触达（unauthenticated），但解码失败保证 handler 不执行
//     - OK → 理论上不可能（0xFF 无法解码），标记 inconclusive 并告警
//
//  3. 流式方法默认不发任何调用（safe.Policy 裁决）。
package probe

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/internal/rpcrecon/internal/grpcx"
	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/safe"
)

// baselineMethod 是确定性的不存在方法，用于基线探测。
const baselineMethod = "/__rpcrecon__/BaselineProbe"

// Engine 执行单端点的方法探测。
type Engine struct {
	policy  safe.Policy
	limiter Limiter
	timeout time.Duration
}

// Limiter 是 ratelimit.Limiter 的最小接口（避免直接依赖具体类型）。
type Limiter interface {
	Acquire(ctx context.Context, host string) (func(), error)
}

// NewEngine 构造探测引擎。
func NewEngine(policy safe.Policy, limiter Limiter) *Engine {
	return &Engine{
		policy:  policy,
		limiter: limiter,
		timeout: 8 * time.Second,
	}
}

// Baseline 对端点执行基线探测，返回基线状态码名。
func (e *Engine) Baseline(ctx context.Context, conn *grpc.ClientConn, addr string) (string, *model.ProbeResult) {
	release, err := e.limiter.Acquire(ctx, addr)
	if err != nil {
		return "", &model.ProbeResult{Exposure: model.ExposureInconclusive, Notes: []string{err.Error()}}
	}
	defer release()

	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	_, code, _, msg, _ := grpcx.InvokeRaw(cctx, conn, baselineMethod, safe.MalformedPayload, nil)
	pr := &model.ProbeResult{
		GRPCCode:    code,
		Message:     msg,
		PayloadKind: "malformed-wire",
		Confidence:  0.95,
	}
	return code, pr
}

// ProbeMethods 对一组方法执行探测，结果直接写回 MethodInfo.Probe。
// baselineCode 为基线探测得到的状态码名。
func (e *Engine) ProbeMethods(ctx context.Context, conn *grpc.ClientConn, addr string,
	methods []*model.MethodInfo, baselineCode string, stats *model.ScanStats) {

	for _, m := range methods {
		select {
		case <-ctx.Done():
			return
		default:
		}

		decision := e.policy.DecideMethod(m)
		if !decision.Allowed {
			m.Probe = &model.ProbeResult{
				Exposure:    model.ExposureSkipped,
				PayloadKind: "none",
				Confidence:  1.0,
				Notes:       []string{decision.Reason},
			}
			stats.MethodsSkipped++
			continue
		}

		release, err := e.limiter.Acquire(ctx, addr)
		if err != nil {
			m.Probe = &model.ProbeResult{Exposure: model.ExposureInconclusive,
				Notes: []string{err.Error()}}
			continue
		}
		stats.MethodsProbed++

		cctx, cancel := context.WithTimeout(ctx, e.timeout)
		_, code, statusCode, msg, _ := grpcx.InvokeRaw(cctx, conn, m.FullName, safe.MalformedPayload, nil)
		cancel()
		release()

		pr := &model.ProbeResult{
			GRPCCode:     code,
			StatusCode:   statusCode,
			Message:      msg,
			BaselineCode: baselineCode,
			PayloadKind:  decision.PayloadKind,
		}
		pr.Exposure, pr.Confidence, pr.Notes = e.judge(code, baselineCode, m)
		m.Probe = pr
	}
}

// judge 是判定逻辑的核心，单独拆出便于单元测试。
//
// 判定矩阵（结合基线）：
//
//	方法返回码                基线 Unimplemented/Internal 类   基线 Unauth 类
//	-------------------------|------------------------------|------------------------
//	Unauthenticated/PermDen  | authenticated（方法级鉴权）     authenticated（同一全局层）
//	Unimplemented            | 方法不存在，跳过                authenticated（全局先拦）
//	Internal/InvalidArgument | unauthenticated（越过鉴权）     authenticated
//	Unknown/其它非鉴权错误     | unauthenticated(置信度稍低)     authenticated
//	OK                       | inconclusive（异常，需人工）     理论不可达
func (e *Engine) judge(code, baseline string, m *model.MethodInfo) (model.ExposureLevel, float64, []string) {
	authCodes := map[string]bool{
		"Unauthenticated":  true,
		"PermissionDenied": true,
	}
	switch {
	case authCodes[code]:
		return model.ExposureAuthenticated, 0.98, []string{
			fmt.Sprintf("方法 %s 明确返回 %s，鉴权层生效", m.FullName, code)}
	case code == "Unimplemented":
		// 反射/描述符来源的方法 schema 声称存在却路由不到，存疑人工复核；
		// 字典猜测来源的方法返回 Unimplemented 就是正常的"没猜中"。
		if m.Source == model.SourceGuess {
			return model.ExposureSkipped, 0.9, []string{"方法不存在（Unimplemented），猜测未命中"}
		}
		return model.ExposureInconclusive, 0.5, []string{
			"schema 声称存在但路由返回 Unimplemented，可能为网关裁剪，需人工确认"}
	case code == "OK":
		return model.ExposureInconclusive, 0.3, []string{
			"非法载荷返回 OK，服务可能使用自定义编解码，自动判定失效，需人工复核"}
	case code == "Internal" || code == "InvalidArgument" || code == "FailedPrecondition":
		// 请求已通过鉴权与路由，在解码/参数校验阶段失败 → 未授权可触达
		return model.ExposureUnauthenticated, 0.95, []string{
			fmt.Sprintf("请求越过鉴权到达解码阶段（%s），非法载荷保证 handler 未执行", code)}
	case code == "Unknown":
		// 部分框架把解码错误包成 Unknown，结合基线确认不是全局拦截
		if authCodes[baseline] {
			return model.ExposureAuthenticated, 0.8, []string{
				"基线显示全局鉴权存在，Unknown 视为鉴权后错误"}
		}
		return model.ExposureUnauthenticated, 0.7, []string{
			"Unknown 错误且基线可穿透，疑似解码失败被包装，按未授权可触达处理（置信度下调）"}
	case code == "Unavailable" || code == "DeadlineExceeded" || code == "Canceled":
		return model.ExposureBlocked, 0.6, []string{fmt.Sprintf("网络/网关层拦截：%s", code)}
	default:
		if authCodes[baseline] {
			return model.ExposureAuthenticated, 0.75, []string{
				fmt.Sprintf("基线为鉴权拦截，方法返回 %s，按已鉴权处理", code)}
		}
		return model.ExposureUnauthenticated, 0.6, []string{
			fmt.Sprintf("非鉴权类返回 %s，基线可穿透，按未授权可触达处理（需人工复核）", code)}
	}
}

// BaselineIsGlobalAuth 告诉调用方基线是否表明存在全局前置鉴权。
func BaselineIsGlobalAuth(baselineCode string) bool {
	return baselineCode == "Unauthenticated" || baselineCode == "PermissionDenied"
}

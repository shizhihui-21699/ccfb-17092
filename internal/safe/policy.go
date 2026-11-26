// Package safe 集中实现探测工具的安全护栏。
//
// 工具的第一设计目标是"绝不触发业务副作用"，所有可能发出的请求都必须经过
// 本包的策略检查。策略默认保守：宁可漏报，不可误触发。
package safe

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
)

// Policy 是一次扫描的安全策略。
type Policy struct {
	// AllowCIDRs 为非空时，只允许探测落在这些网段内的目标。
	AllowCIDRs []netip.Prefix
	// DenyCIDRs 始终生效，优先级高于 Allow。
	DenyCIDRs []netip.Prefix
	// MaxEndpoints 硬上限，防止配置错误扫全网。
	MaxEndpoints int
	// AllowEmptyPayload 是否允许对只读方法发送"空的合法消息"。
	// 默认 false：只发非法 wire 字节，保证连解码都过不去。
	AllowEmptyPayload bool
	// ProbeStreaming 是否探测流式方法。默认 false（半条流即可触发业务）。
	ProbeStreaming bool
	// ProbeHTTPAdmin 是否对同端口 HTTP 管理面做 GET 探测。
	ProbeHTTPAdmin bool
	// DryRun 只输出计划，不发出任何业务请求（反射枚举除外，可再关）。
	DryRun bool
	// EnableReflection 是否允许使用 gRPC 反射（只读，但会留下访问记录）。
	EnableReflection bool
}

// DefaultPolicy 返回内置的保守默认策略。
func DefaultPolicy() Policy {
	return Policy{
		MaxEndpoints:      10000,
		AllowEmptyPayload: false,
		ProbeStreaming:    false,
		ProbeHTTPAdmin:    true,
		EnableReflection:  true,
	}
}

// CheckTarget 在建立任何连接前校验目标是否被授权。
func (p Policy) CheckTarget(host string, port int) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// 主机名无法做网段判断：要求显式配置 AllowCIDRs 之外的授权来源，
		// 这里仅拒绝明显危险的写法，主机名交由 discover 层解析后再校验。
		return fmt.Errorf("主机名目标 %s 需先解析为 IP 再做授权校验", host)
	}
	for _, c := range p.DenyCIDRs {
		if c.Contains(addr) {
			return fmt.Errorf("目标 %s 命中拒绝网段 %s", host, c)
		}
	}
	if len(p.AllowCIDRs) > 0 {
		allowed := false
		for _, c := range p.AllowCIDRs {
			if c.Contains(addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("目标 %s 不在任何授权网段内", host)
		}
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("非法端口 %d", port)
	}
	return nil
}

// CheckIP 对解析后的 IP 做网段校验（供主机名目标使用）。
func (p Policy) CheckIP(addr netip.Addr) error {
	for _, c := range p.DenyCIDRs {
		if c.Contains(addr) {
			return fmt.Errorf("IP %s 命中拒绝网段 %s", addr, c)
		}
	}
	if len(p.AllowCIDRs) > 0 {
		allowed := false
		for _, c := range p.AllowCIDRs {
			if c.Contains(addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP %s 不在任何授权网段内", addr)
		}
	}
	return nil
}

// MalformedPayload 是固定的非法 protobuf wire 字节。
//
// 0xFF 作为 varint 的首字节表示"后续还有 9 个续接字节"，但本载荷只有 1
// 个字节，proto 解码器必然返回错误。任何标准 google.golang.org/protobuf
// 实现都无法把它解码成消息，业务 handler 不可能执行。
var MalformedPayload = []byte{0xFF}

// ProbeDecision 是策略对单个方法的探测裁决。
type ProbeDecision struct {
	Allowed     bool
	PayloadKind string // malformed-wire / empty-valid / none
	Reason      string
}

// DecideMethod 决定一个方法能否探测、用什么载荷探测。
//
// 规则：
//  1. 流式方法默认跳过（客户端流/双向流半条流即可触发业务；服务流同样跳过，保守）。
//  2. 普通一元方法：只发非法 wire 字节，handler 永不执行。
//  3. 空合法消息载荷需要显式开关，且只允许只读（非敏感/读类）方法。
func (p Policy) DecideMethod(m *model.MethodInfo) ProbeDecision {
	if m.IsStreaming && !p.ProbeStreaming {
		return ProbeDecision{Allowed: false, PayloadKind: "none",
			Reason: "流式方法默认跳过：半条流即可能触发业务逻辑"}
	}
	if p.AllowEmptyPayload {
		if m.Sensitive != nil && isMutatingKind(m.Sensitive.Kind) {
			// 即使开了空消息开关，变异类方法仍然只用非法载荷。
			return ProbeDecision{Allowed: true, PayloadKind: "malformed-wire",
				Reason: "变异类方法强制使用非法载荷，禁止空合法消息"}
		}
		return ProbeDecision{Allowed: true, PayloadKind: "malformed-wire",
			Reason: "默认非法载荷；空合法消息仅在只读方法且显式开启时另做一轮"}
	}
	return ProbeDecision{Allowed: true, PayloadKind: "malformed-wire",
		Reason: "发送非法 protobuf wire 字节，解码必失败，handler 不执行"}
}

// isMutatingKind 判断敏感类别是否具有写/副作用语义。
func isMutatingKind(k model.SensitiveKind) bool {
	switch k {
	case model.KindConfig, model.KindCache, model.KindAdmin,
		model.KindDataWrite, model.KindDebug, model.KindInternal:
		return true
	default:
		return false
	}
}

// HTTPAllowedPath 校验 HTTP 管理面探测路径：只允许只读 GET 路径。
func (p Policy) HTTPAllowedPath(path string) error {
	if !p.ProbeHTTPAdmin {
		return fmt.Errorf("HTTP 管理面探测已关闭")
	}
	upper := strings.ToUpper(path)
	// 路径里不允许出现明显的动作型片段，双保险（实际请求也只会用 GET）。
	for _, bad := range []string{"DELETE", "REMOVE", "RESET", "FLUSH", "SHUTDOWN", "RELOAD"} {
		if strings.Contains(upper, bad) {
			return fmt.Errorf("路径 %s 含动作型片段 %s，禁止自动探测", path, bad)
		}
	}
	return nil
}

// Package discover 负责把"动态变化的内网地址"变成一组待探测目标。
//
// 支持的来源：
//   - CIDR + 端口列表/端口范围（主动扫描模式）
//   - 目标文件（host:port 一行一个）
//   - 注册中心适配器（接口预留，见 registry.go）
package discover

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/safe"
)

// Spec 描述一次目标生成的输入。
type Spec struct {
	CIDRs       []string // 如 10.0.0.0/24
	Ports       []int    // 离散端口
	PortRanges  []PortRange
	TargetFiles []string // host:port 列表文件
	Extras      []string // 命令行直接给的 host:port
}

// PortRange 是闭区间端口段。
type PortRange struct {
	From, To int
}

// Enumerate 按 Spec 生成目标，全程经过安全策略校验。
// 返回的目标做过去重。
func Enumerate(ctx context.Context, spec Spec, policy safe.Policy) ([]model.Target, error) {
	seen := make(map[string]struct{})
	var out []model.Target

	add := func(t model.Target) error {
		key := t.Addr()
		if _, ok := seen[key]; ok {
			return nil
		}
		if err := policy.CheckTarget(t.Host, t.Port); err != nil {
			return err
		}
		if len(out) >= policy.MaxEndpoints {
			return fmt.Errorf("目标数达到硬上限 %d，拒绝继续扩展（可调高 MaxEndpoints）", policy.MaxEndpoints)
		}
		seen[key] = struct{}{}
		out = append(out, t)
		return nil
	}

	// 1. CIDR × 端口
	for _, cidr := range spec.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR %q: %w", cidr, err)
		}
		ports, err := expandPorts(spec.Ports, spec.PortRanges)
		if err != nil {
			return nil, err
		}
		if prefix.Addr().Is4() && prefix.Bits() <= 16 {
			// 防止手滑写成 /8 /16 扫全网，配合 MaxEndpoints 双保险
			return nil, fmt.Errorf("CIDR %s 过大（≤/16），请缩小扫描范围", cidr)
		}
		count := prefix.Masked()
		for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			default:
			}
			// 跳过网络地址与广播地址（IPv4）
			if addr.Is4() && (addr == count.Masked().Addr() || addr == broadcast(prefix)) {
				continue
			}
			for _, port := range ports {
				if err := add(model.Target{Host: addr.String(), Port: port, Source: "cidr:" + cidr}); err != nil {
					return out, err
				}
			}
		}
	}

	// 2. 显式 host:port
	for _, raw := range spec.Extras {
		t, err := parseHostPort(raw, "cli")
		if err != nil {
			return nil, err
		}
		if err := add(t); err != nil {
			return nil, err
		}
	}

	// 3. 文件
	for _, file := range spec.TargetFiles {
		if err := readTargetFile(ctx, file, add); err != nil {
			return nil, fmt.Errorf("读取目标文件 %s: %w", file, err)
		}
	}
	return out, nil
}

func expandPorts(ports []int, ranges []PortRange) ([]int, error) {
	seen := make(map[int]struct{})
	var out []int
	addPort := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("非法端口 %d", p)
		}
		if _, ok := seen[p]; ok {
			return nil
		}
		seen[p] = struct{}{}
		out = append(out, p)
		return nil
	}
	for _, p := range ports {
		if err := addPort(p); err != nil {
			return nil, err
		}
	}
	for _, r := range ranges {
		if r.From > r.To || r.From < 1 || r.To > 65535 {
			return nil, fmt.Errorf("非法端口段 %d-%d", r.From, r.To)
		}
		if r.To-r.From > 1024 {
			return nil, fmt.Errorf("端口段 %d-%d 超过 1024 个端口", r.From, r.To)
		}
		for p := r.From; p <= r.To; p++ {
			if err := addPort(p); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有给出任何端口")
	}
	return out, nil
}

func broadcast(p netip.Prefix) netip.Addr {
	// 仅 IPv4 调用
	addr := p.Masked().Addr().As4()
	hostBits := 32 - p.Bits()
	for i := 0; i < hostBits; i++ {
		byteIdx := 3 - i/8
		bitIdx := uint(i % 8)
		addr[byteIdx] |= 1 << bitIdx
	}
	return netip.AddrFrom4(addr)
}

func parseHostPort(raw, source string) (model.Target, error) {
	raw = strings.TrimSpace(raw)
	addrPort, err := netip.ParseAddrPort(raw)
	if err != nil {
		// 可能是 hostname:port
		idx := strings.LastIndex(raw, ":")
		if idx <= 0 {
			return model.Target{}, fmt.Errorf("非法目标 %q，应为 host:port", raw)
		}
		name := raw[:idx]
		p, err2 := strconv.Atoi(raw[idx+1:])
		if err2 != nil {
			return model.Target{}, fmt.Errorf("非法目标 %q: %w", raw, err)
		}
		return model.Target{Host: name, Port: p, Source: source}, nil
	}
	return model.Target{Host: addrPort.Addr().String(), Port: int(addrPort.Port()), Source: source}, nil
}

func readTargetFile(ctx context.Context, path string, add func(model.Target) error) error {
	f, err := openFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	lineNo := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := r.ReadString('\n')
		lineNo++
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			t, perr := parseHostPort(line, "file:"+path)
			if perr != nil {
				return fmt.Errorf("第 %d 行: %w", lineNo, perr)
			}
			if err := add(t); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ParsePortSpec 解析形如 "9000,9100-9105,50051" 的端口规格。
func ParsePortSpec(spec string) (ports []int, ranges []PortRange, err error) {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bits := strings.SplitN(part, "-", 2)
			from, e1 := strconv.Atoi(strings.TrimSpace(bits[0]))
			to, e2 := strconv.Atoi(strings.TrimSpace(bits[1]))
			if e1 != nil || e2 != nil {
				return nil, nil, fmt.Errorf("非法端口段 %q", part)
			}
			ranges = append(ranges, PortRange{From: from, To: to})
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, nil, fmt.Errorf("非法端口 %q", part)
		}
		ports = append(ports, p)
	}
	return ports, ranges, nil
}

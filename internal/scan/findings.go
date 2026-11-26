package scan

import (
	"fmt"

	"github.com/internal/rpcrecon/internal/model"
)

// buildFindings 把端点明细归并为报告级 Finding 列表，并统计未授权发现数。
func (s *Scanner) buildFindings(report *model.Report) {
	for _, ep := range report.Endpoints {
		addr := ep.Target.Addr()

		// 1. 反射开放本身是一条发现项
		if ep.Reflection.Enabled && ep.Reflection.Unauth {
			report.Findings = append(report.Findings, model.Finding{
				Endpoint:    addr,
				Transport:   ep.Transport,
				Kind:        model.KindReflection,
				Severity:    model.SeverityMedium,
				Exposure:    model.ExposureUnauthenticated,
				Confidence:  1.0,
				Description: "gRPC 反射未授权开放，任何人可枚举完整服务与方法清单",
				Evidence:    reflectionEvidence(ep),
			})
			report.Stats.UnauthFindings++
		}

		// 2. 方法级发现
		for _, svc := range ep.Services {
			for _, m := range svc.Methods {
				if m.Sensitive == nil || m.Probe == nil {
					continue
				}
				if m.Probe.Exposure != model.ExposureUnauthenticated {
					continue
				}
				report.Findings = append(report.Findings, model.Finding{
					Endpoint:    addr,
					Transport:   ep.Transport,
					Service:     m.Service,
					Method:      m.FullName,
					Kind:        m.Sensitive.Kind,
					Severity:    m.Sensitive.Severity,
					Exposure:    m.Probe.Exposure,
					Confidence:  m.Probe.Confidence,
					Source:      svc.Source,
					GRPCCode:    m.Probe.GRPCCode,
					Description: describeMethod(m),
					Evidence:    append([]string{}, m.Probe.Notes...),
				})
				report.Stats.UnauthFindings++
			}
		}

		// 3. HTTP 管理面发现
		for _, hf := range ep.HTTPAdmin {
			if !hf.Exposed {
				continue
			}
			sev := model.SeverityMedium
			if hf.Kind == model.KindDebug {
				sev = model.SeverityHigh
			}
			report.Findings = append(report.Findings, model.Finding{
				Endpoint:    addr,
				Transport:   ep.Transport,
				Method:      hf.Path,
				Kind:        hf.Kind,
				Severity:    sev,
				Exposure:    model.ExposureUnauthenticated,
				Confidence:  0.95,
				Description: hf.Note,
				Evidence:    []string{fmt.Sprintf("GET %s → HTTP %d", hf.Path, hf.StatusCode)},
			})
			report.Stats.UnauthFindings++
		}
	}

	// 稳定排序：严重程度 → 端点 → 方法
	sortFindings(report.Findings)
}

func reflectionEvidence(ep *model.Endpoint) []string {
	var ev []string
	if ep.Reflection.V1 {
		ev = append(ev, "grpc.reflection.v1.ServerReflection 可未授权调用")
	}
	if ep.Reflection.V1Alpha {
		ev = append(ev, "grpc.reflection.v1alpha.ServerReflection 可未授权调用")
	}
	count := 0
	for _, svc := range ep.Services {
		count += len(svc.Methods)
	}
	ev = append(ev, fmt.Sprintf("通过反射枚举到 %d 个服务、%d 个方法", len(ep.Services), count))
	return ev
}

func describeMethod(m *model.MethodInfo) string {
	stream := ""
	if m.IsStreaming {
		stream = "（流式方法，未实际调用，仅依据命名与元数据判定）"
	}
	return fmt.Sprintf("敏感方法 %s [%s] 未授权可触达%s；探测载荷为非法 protobuf 字节，handler 未执行",
		m.FullName, m.Sensitive.Kind, stream)
}

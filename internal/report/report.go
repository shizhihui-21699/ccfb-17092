// Package report 负责扫描结果的序列化与终端渲染。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
)

// WriteJSON 输出完整 JSON 报告。
func WriteJSON(path string, r *model.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// RenderText 把报告渲染成适合终端阅读的文本。
func RenderText(w io.Writer, r *model.Report, verbose bool) {
	fmt.Fprintf(w, "\n===== RPCRecon 扫描报告 %s =====\n", r.ScanID)
	fmt.Fprintf(w, "耗时: %s   目标: %d   存活 gRPC: %d\n",
		r.FinishedAt.Sub(r.StartedAt).Round(1e6), r.Targets, r.LiveEndpoints)
	fmt.Fprintf(w, "TCP 探测: %d   反射开放: %d   枚举方法: %d   猜测方法: %d\n",
		r.Stats.TCPProbed, r.Stats.ReflectionOpen, r.Stats.MethodsEnumerated, r.Stats.MethodsGuessed)
	fmt.Fprintf(w, "实际探测方法: %d   跳过: %d   未授权发现: %d   HTTP 管理面暴露: %d\n\n",
		r.Stats.MethodsProbed, r.Stats.MethodsSkipped, r.Stats.UnauthFindings, r.Stats.HTTPAdminExposed)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "未发现未授权敏感面。")
		return
	}

	fmt.Fprintln(w, "发现项（按严重程度排序）:")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  [%s] %s  %s %s\n",
			padRight(string(f.Severity), 8),
			padRight(string(f.Exposure), 15),
			f.Endpoint, f.Method)
		fmt.Fprintf(w, "      类别: %s | 置信度: %.2f | %s\n", f.Kind, f.Confidence, f.Description)
		for _, ev := range f.Evidence {
			fmt.Fprintf(w, "      证据: %s\n", ev)
		}
	}

	if verbose {
		fmt.Fprintln(w, "\n--- 端点明细 ---")
		for _, ep := range r.Endpoints {
			fmt.Fprintf(w, "\n%s (%s, source=%s)\n", ep.Target.Addr(), ep.Transport, ep.Source)
			fmt.Fprintf(w, "  反射: enabled=%v unauth=%v v1=%v v1alpha=%v\n",
				ep.Reflection.Enabled, ep.Reflection.Unauth, ep.Reflection.V1, ep.Reflection.V1Alpha)
			for _, svc := range ep.Services {
				fmt.Fprintf(w, "  服务 %s (source=%s, confidence=%.1f), %d 个方法\n",
					svc.Name, svc.Source, svc.Confidence, len(svc.Methods))
				for _, m := range svc.Methods {
					probeLine := "未探测"
					if m.Probe != nil {
						probeLine = fmt.Sprintf("%s (%s)", m.Probe.Exposure, m.Probe.GRPCCode)
					}
					sensLine := "-"
					if m.Sensitive != nil {
						sensLine = fmt.Sprintf("%s/%s", m.Sensitive.Kind, m.Sensitive.Severity)
					}
					fmt.Fprintf(w, "    %-45s %-28s %s\n", m.FullName, probeLine, sensLine)
				}
			}
			for _, hf := range ep.HTTPAdmin {
				fmt.Fprintf(w, "  HTTP %s -> %d exposed=%v (%s)\n",
					hf.Path, hf.StatusCode, hf.Exposed, hf.Note)
			}
		}
	}
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

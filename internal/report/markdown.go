// Package report renders a scan for people and for machines.
//
// Three formats are supported:
//
//	markdown  a human-readable inventory, leading with the exposure verdict
//	sarif     a SARIF 2.1.0 document for CI code-scanning integration
//	json      the scan's own representation, written by the store package
//
// The markdown output is deliberately explicit about confidence. An operator
// acting on this report needs to distinguish "an inert call proved this open"
// from "the server has no auth and this method lives next to a proven-open
// one", because the remediation and the risk of the claim differ.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"grpcscope/internal/model"
)

// RenderMarkdown writes the report.
func RenderMarkdown(w io.Writer, scan *model.Scan) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("# gRPC exposure scan\n\n")
	p("Scan started %s and finished %s in %s.\n\n",
		scan.Meta.StartedAt.Format("2006-01-02 15:04:05 MST"),
		scan.Meta.FinishedAt.Format("15:04:05"), humanDuration(scan.Meta.FinishedAt.Sub(scan.Meta.StartedAt)))

	p("Mode: **%s** — %s\n\n", scan.Meta.Mode, scan.Meta.ProbePolicy)
	p("Targets: %d probed at concurrency %d, %.0f req/s, %dms timeout.\n\n",
		scan.Meta.Targets, scan.Meta.Concurrency, scan.Meta.RatePerSec, scan.Meta.TimeoutMS)
	if scan.Meta.Wordlist != "" {
		p("Wordlist: %s\n\n", scan.Meta.Wordlist)
	}
	if len(scan.Meta.DescriptorSources) > 0 {
		p("Descriptors: %s\n\n", strings.Join(scan.Meta.DescriptorSources, ", "))
	}

	renderSummary(p, scan)
	renderExposed(p, scan)
	renderFindings(p, scan)
	renderInventories(p, scan)
	renderMethodTable(p, scan)
	renderProbeLegend(p)

	return nil
}

func renderSummary(p func(string, ...any), scan *model.Scan) {
	type counts struct{ total, grpc, withSensitive, withExposed, reflection, healthOpen int }
	var c counts
	for _, ep := range scan.Endpoints {
		c.total++
		if ep.Protocol != model.ProtoGRPC {
			continue
		}
		c.grpc++
		if ep.Reflection == model.ReflectionV1 || ep.Reflection == model.ReflectionV1Alpha {
			c.reflection++
		}
		if ep.Health == model.HealthOpen {
			c.healthOpen++
		}
		if len(ep.SensitiveMethods()) > 0 {
			c.withSensitive++
		}
		for _, m := range ep.SensitiveMethods() {
			if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
				c.withExposed++
				break
			}
		}
	}

	p("## Summary\n\n")
	p("| | |\n|---|---|\n")
	p("| addresses probed | %d |\n", c.total)
	p("| gRPC endpoints | %d |\n", c.grpc)
	p("| reflection exposed | %d |\n", c.reflection)
	p("| health service open | %d |\n", c.healthOpen)
	p("| endpoints with sensitive methods | %d |\n", c.withSensitive)
	p("| endpoints with exposed sensitive methods | %d |\n\n", c.withExposed)
}

func renderExposed(p func(string, ...any), scan *model.Scan) {
	var exposed []struct {
		ep *model.Endpoint
		m  *model.Method
	}
	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		if ep.Protocol != model.ProtoGRPC {
			continue
		}
		for _, m := range ep.SensitiveMethods() {
			if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
				exposed = append(exposed, struct {
					ep *model.Endpoint
					m  *model.Method
				}{ep, m})
			}
		}
	}
	if len(exposed) == 0 {
		return
	}
	sort.SliceStable(exposed, func(i, j int) bool {
		return exposed[i].ep.Addr < exposed[j].ep.Addr
	})

	p("## Sensitive methods reachable without credentials\n\n")
	p("These are the state-changing or administrative RPCs the scanner judges reachable from an unauthenticated caller.\n")
	p("Where the row says *inferred*, the method was **not called** — the tool will not invoke a state-changing method — and the conclusion rests on server-wide evidence.\n\n")
	p("| Endpoint | Method | Risk | Evidence | Confidence |\n|---|---|---|---|---|\n")
	for _, x := range exposed {
		ev := "server-wide health check"
		conf := string(x.m.Auth)
		if x.m.Auth == model.AuthProvenOpen {
			ev = "inert call succeeded"
			conf = "proven"
		}
		p("| `%s` | `%s` | %s | %s | %s |\n",
			x.ep.Addr, x.m.FullName, x.m.Risk.Level, ev, conf)
	}
	p("\n")
}

func renderFindings(p func(string, ...any), scan *model.Scan) {
	hasFindings := false
	for _, ep := range scan.Endpoints {
		if len(ep.Findings) > 0 {
			hasFindings = true
			break
		}
	}
	if !hasFindings {
		return
	}
	p("## Findings\n\n")
	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		if len(ep.Findings) == 0 {
			continue
		}
		p("### `%s`\n\n", ep.Addr)
		for _, f := range ep.Findings {
			p("- **%s** (%s, %s): %s\n", f.Kind, f.Severity, f.Confidence, f.Summary)
			for _, e := range f.Evidence {
				p("  - %s\n", e)
			}
		}
		p("\n")
	}
}

func renderInventories(p func(string, ...any), scan *model.Scan) {
	p("## Endpoint inventory\n\n")
	p("| Endpoint | Protocol | Reflection | Health | Services | Methods | Sensitive |\n")
	p("|---|---|---|---|---|---|---|\n")
	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		methods := 0
		for _, s := range ep.Services {
			methods += len(s.Methods)
		}
		p("| `%s` | %s | %s | %s | %d | %d | %d |\n",
			ep.Addr, ep.Protocol, ep.Reflection, ep.Health,
			len(ep.Services), methods, len(ep.SensitiveMethods()))
	}
	p("\n")
}

func renderMethodTable(p func(string, ...any), scan *model.Scan) {
	p("## Method inventory\n\n")
	p("| Endpoint | Method | Shape | Origin | Exists | Risk | Auth |\n")
	p("|---|---|---|---|---|---|---|\n")
	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		if ep.Protocol != model.ProtoGRPC {
			continue
		}
		for _, m := range ep.AllMethods() {
			p("| `%s` | `%s` | %s | %s | %s | %s | %s |\n",
				ep.Addr, m.FullName, m.Shape, m.Origin, yesNo(m.Exists), m.Risk.Level, m.Auth)
		}
	}
	p("\n")
}

func renderProbeLegend(p func(string, ...any)) {
	p("## How to read this report\n\n")
	p("- **Origin** — `exact` came from reflection or a supplied descriptor; `guessed` came from a wordlist and was confirmed only by the existence oracle; `proven` came from a live probe.\n")
	p("- **Exists** — `yes` means the server positively acknowledged the method's registration (by the encoding oracle, which runs no handler code).\n")
	p("- **Auth** — `proven-open` means an inert call succeeded unauthenticated; `inferred-open` means the server-wide health check succeeded and this method is adjacent to it; `unknown` means nothing safe could prove it.\n")
	p("- **Risk** — derived from the method and service names plus input field names. A `read-only` verdict is a heuristic, not a guarantee.\n")
	p("- The scanner **never sends a request body** to a method it classifies as mutating or destructive. See the probe policy for what was sent.\n")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func humanDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return d.Round(time.Millisecond).String()
}

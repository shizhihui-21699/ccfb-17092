package scan

import (
	"fmt"
	"sort"
	"time"

	"grpcscope/internal/model"
	"grpcscope/internal/wire"
)

// probeRecord converts a wire result into a model record.
func probeRecord(kind model.ProbeKind, res wire.Result) model.ProbeRecord {
	return model.ProbeRecord{
		Kind:       kind,
		Code:       res.Code.String(),
		Message:    res.Message,
		DurationMS: res.Duration.Milliseconds(),
		At:         time.Now(),
	}
}

// deriveFindings turns the endpoint's collected evidence into conclusions.
// Every finding names the evidence behind it, and every claim that is only an
// inference is labelled as one.
func (e *Engine) deriveFindings(ep *model.Endpoint) {
	if ep.Protocol != model.ProtoGRPC {
		return
	}

	sensitive := ep.SensitiveMethods()

	// The incident's central finding: an administrative or sensitive method
	// reachable without credentials.
	var exposed []*model.Method
	for _, m := range sensitive {
		switch m.Auth {
		case model.AuthProvenOpen, model.AuthInferredOpen:
			exposed = append(exposed, m)
		}
	}
	if len(exposed) > 0 {
		sev := "high"
		provenOpen := false
		for _, m := range exposed {
			if m.Auth == model.AuthProvenOpen {
				provenOpen = true
			}
			if m.Risk.Level == model.RiskDestructive || m.Risk.Adminish {
				sev = "critical"
			}
		}
		ev := []string{fmt.Sprintf("%d sensitive method(s) reachable without credentials", len(exposed))}
		if provenOpen {
			ev = append(ev, "at least one was confirmed by an inert call that succeeded")
		} else {
			ev = append(ev, "exposure inferred from the server-wide unauthenticated health check; no state-changing probe was sent")
		}
		ep.AddFinding(model.Finding{
			Kind:     "sensitive-method-exposed",
			Severity: sev,
			Summary: fmt.Sprintf("Server exposes %d state-changing or administrative method(s) that appear callable without credentials",
				len(exposed)),
			Evidence: ev,
			Confidence: func() model.Confidence {
				if provenOpen {
					return model.ConfProven
				}
				return model.ConfInferred
			}(),
		})
	}

	// Admin surface co-located with business surface on one port.
	adminSvcs, bizSvcs := 0, 0
	for i := range ep.Services {
		if ep.Services[i].Adminish {
			adminSvcs++
		} else {
			bizSvcs++
		}
	}
	if adminSvcs > 0 && bizSvcs > 0 {
		ep.AddFinding(model.Finding{
			Kind:       "admin-surface-co-located",
			Severity:   "medium",
			Summary:    "Management and business methods share one port, so a business client reaches administrative surface with the same address",
			Evidence:   []string{fmt.Sprintf("%d administrative service(s) beside %d other service(s)", adminSvcs, bizSvcs)},
			Confidence: model.ConfExact,
		})
	}

	if ep.Health == model.HealthOpen {
		ep.AddFinding(model.Finding{
			Kind:       "health-open",
			Severity:   "low",
			Summary:    "The standard health service answers without credentials, showing no global unary auth interceptor",
			Evidence:   []string{"grpc.health.v1.Health/Check returned SERVING"},
			Confidence: model.ConfProven,
		})
	}
}

// SummariseEndpointCounts is used by the CLI progress line.
func SummariseEndpointCounts(eps []model.Endpoint) (grpcCount, withSensitive, withExposed int) {
	for _, ep := range eps {
		if ep.Protocol != model.ProtoGRPC {
			continue
		}
		grpcCount++
		if len(ep.SensitiveMethods()) > 0 {
			withSensitive++
		}
		for _, m := range ep.SensitiveMethods() {
			if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
				withExposed++
				break
			}
		}
	}
	return
}

// SortEndpoints orders endpoints by risk so a report leads with what matters.
func SortEndpoints(eps []model.Endpoint) {
	sevRank := func(ep model.Endpoint) int {
		r := 0
		for _, f := range ep.Findings {
			switch f.Severity {
			case "critical":
				r = max(r, 5)
			case "high":
				r = max(r, 4)
			case "medium":
				r = max(r, 3)
			case "low":
				r = max(r, 2)
			case "info":
				r = max(r, 1)
			}
		}
		return r
	}
	sort.SliceStable(eps, func(i, j int) bool {
		ri, rj := sevRank(eps[i]), sevRank(eps[j])
		if ri != rj {
			return ri > rj
		}
		return eps[i].Addr < eps[j].Addr
	})
}

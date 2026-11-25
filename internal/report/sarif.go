package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"grpcscope/internal/model"
)

// sarifLog is the subset of SARIF 2.1.0 that code-scanning ingestion needs.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

var ruleDefs = []sarifRule{
	{
		ID:                   "grpcscope/sensitive-method-exposed",
		Name:                 "Sensitive gRPC method reachable without credentials",
		ShortDescription:     sarifText{Text: "A state-changing or administrative RPC appears callable without credentials."},
		Help:                 sarifText{Text: "Restrict the management surface: separate ports, require authentication at the interceptor, or disable reflection and co-located admin services."},
		DefaultConfiguration: sarifConfig{Level: "error"},
		Properties:           map[string]any{"tags": []string{"security", "grpc"}},
	},
	{
		ID:                   "grpcscope/reflection-exposed",
		Name:                 "gRPC server reflection exposed",
		ShortDescription:     sarifText{Text: "The server lists its full method inventory to unauthenticated callers."},
		Help:                 sarifText{Text: "Do not register the reflection service on externally reachable ports, or gate it behind authentication."},
		DefaultConfiguration: sarifConfig{Level: "warning"},
		Properties:           map[string]any{"tags": []string{"security", "grpc", "information-disclosure"}},
	},
	{
		ID:                   "grpcscope/admin-surface-co-located",
		Name:                 "Administrative surface shares a port with business methods",
		ShortDescription:     sarifText{Text: "Management RPCs are registered on the same port as business RPCs."},
		Help:                 sarifText{Text: "Serve management RPCs on a separate listener that is bound to an internal interface and authenticated independently."},
		DefaultConfiguration: sarifConfig{Level: "note"},
		Properties:           map[string]any{"tags": []string{"security", "grpc", "architecture"}},
	},
	{
		ID:                   "grpcscope/health-open",
		Name:                 "Health service answers without credentials",
		ShortDescription:     sarifText{Text: "No global unary auth interceptor appears to be installed."},
		Help:                 sarifText{Text: "If authentication is expected to be server-wide, install a unary interceptor; the open health check suggests none exists."},
		DefaultConfiguration: sarifConfig{Level: "note"},
		Properties:           map[string]any{"tags": []string{"security", "grpc"}},
	},
}

// RenderSARIF writes a SARIF document. Endpoint addresses become artifact URIs
// so a CI viewer can group findings per target.
func RenderSARIF(w io.Writer, scan *model.Scan) error {
	driver := sarifDriver{
		Name:           "grpcscope",
		Version:        scan.Meta.Version,
		InformationURI: "https://example.invalid/grpcscope",
		Rules:          ruleDefs,
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}}},
	}

	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		for _, f := range ep.Findings {
			id := "grpcscope/" + f.Kind
			level := sarifLevel(f.Severity)
			if level == "" {
				continue // info-only findings are not actionable in CI
			}
			res := sarifResult{
				RuleID:  id,
				Level:   level,
				Message: sarifText{Text: f.Summary},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: ep.Addr}},
				}},
				Properties: map[string]any{
					"confidence": f.Confidence,
					"evidence":   f.Evidence,
					"severity":   f.Severity,
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, res)
		}
	}

	// Method-level exposure results, so a reviewer sees exactly which RPCs.
	for i := range scan.Endpoints {
		ep := &scan.Endpoints[i]
		for _, m := range ep.SensitiveMethods() {
			if m.Auth != model.AuthProvenOpen && m.Auth != model.AuthInferredOpen {
				continue
			}
			msg := fmt.Sprintf("%s %s appears reachable without credentials (%s)", m.Risk.Level, m.FullName, m.Auth)
			log.Runs[0].Results = append(log.Runs[0].Results, sarifResult{
				RuleID:  "grpcscope/sensitive-method-exposed",
				Level:   "error",
				Message: sarifText{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: ep.Addr}},
				}},
				Properties: map[string]any{
					"method": m.FullName,
					"risk":   m.Risk.Level,
					"auth":   m.Auth,
					"origin": m.Origin,
				},
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	}
	return ""
}

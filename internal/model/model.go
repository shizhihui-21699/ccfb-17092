// Package model defines the data model shared by every stage of a scan.
//
// The model is deliberately additive: every field records *what was observed*
// and *how it was observed*, so that a later reader can tell a fact proven by
// an inert probe apart from a guess produced by a wordlist.
package model

import (
	"fmt"
	"sort"
	"time"
)

// Transport is the protocol layer used to reach an endpoint.
type Transport string

const (
	TransportH2C Transport = "h2c" // plaintext HTTP/2 with prior knowledge
	TransportTLS Transport = "tls" // HTTP/2 over TLS (ALPN h2)
)

// Protocol is the terminal classification produced by fingerprinting.
type Protocol string

const (
	ProtoGRPC        Protocol = "grpc"         // a gRPC server answered with a grpc-status
	ProtoHTTP2Other  Protocol = "http2-other"  // HTTP/2, but not gRPC
	ProtoHTTP1       Protocol = "http1"        // HTTP/1.x only
	ProtoTCPOther    Protocol = "tcp-other"    // accepted a connection, spoke nothing recognizable
	ProtoTLSRequired Protocol = "tls-required" // plaintext dial failed, TLS worked
	ProtoTLSRejected Protocol = "tls-rejected" // TLS dial failed, plaintext worked
	ProtoClosed      Protocol = "closed"       // TCP connection refused / unresolvable
	ProtoUnknown     Protocol = "unknown"      // inconclusive
)

// ReflectionState describes the outcome of asking the server for its own
// service list over the gRPC reflection service.
type ReflectionState string

const (
	ReflectionV1      ReflectionState = "v1"      // grpc.reflection.v1 answered
	ReflectionV1Alpha ReflectionState = "v1alpha" // only the legacy v1alpha answered
	ReflectionGated   ReflectionState = "gated"   // present but requires credentials
	ReflectionAbsent  ReflectionState = "absent"  // not registered
	ReflectionError   ReflectionState = "error"   // present but unusable
)

// HealthState describes whether the standard health service answers without
// credentials. Because HealthCheck is inert by definition, it is a legitimate
// server-wide authorization signal.
type HealthState string

const (
	HealthOpen   HealthState = "open"   // answered unauthenticated
	HealthGated  HealthState = "gated"  // rejected with an auth-ish code
	HealthAbsent HealthState = "absent" // not registered
	HealthError  HealthState = "error"  // present but unusable
)

// AuthState is the per-method authorization verdict, kept honest about how
// much evidence stands behind it.
type AuthState string

const (
	AuthUnknown       AuthState = "unknown"       // nothing non-destructive can prove this
	AuthInferredOpen  AuthState = "inferred-open" // server-wide auth absent, method co-located
	AuthInferredGated AuthState = "inferred-gated"
	AuthProvenOpen    AuthState = "proven-open"  // an inert call succeeded without credentials
	AuthProvenGated   AuthState = "proven-gated" // an inert call was rejected without credentials
)

// Confidence records how much the tool trusts a conclusion.
type Confidence string

const (
	ConfExact    Confidence = "exact"    // from reflection or a supplied descriptor
	ConfProven   Confidence = "proven"   // confirmed by an inert probe
	ConfInferred Confidence = "inferred" // derived from server-wide evidence
	ConfGuessed  Confidence = "guessed"  // from a wordlist, service/method existence not corroborated
)

// Shape is the RPC cardinality of a method.
type Shape string

const (
	ShapeUnary        Shape = "unary"
	ShapeServerStream Shape = "server-stream"
	ShapeClientStream Shape = "client-stream"
	ShapeBidi         Shape = "bidi"
	ShapeUnknown      Shape = "unknown"
)

// ProbeKind names a probe shape. The names appear in reports, so they are
// stable and describe exactly what was sent.
type ProbeKind string

const (
	ProbeEncodingOracle ProbeKind = "encoding-oracle" // unknown grpc-encoding, no message
	ProbePoisonUnary    ProbeKind = "poison-unary"    // invalid wire bytes into a unary/non-client-streaming method
	ProbeEmptyReadCall  ProbeKind = "empty-read-call" // empty request into a read-only-named method (opt-in)
	ProbeHealthCheck    ProbeKind = "health-check"    // standard inert health check
	ProbeReflectionList ProbeKind = "reflection-list" // standard inert reflection list
	ProbeUserPayload    ProbeKind = "user-payload"    // payload supplied by the operator (opt-in)
)

// SideEffectRisk classifies a method by what calling it could do.
type SideEffectRisk string

const (
	RiskReadOnly    SideEffectRisk = "read-only"   // name says it only reads
	RiskMutating    SideEffectRisk = "mutating"    // name says it writes state
	RiskDestructive SideEffectRisk = "destructive" // name says it destroys state or takes the service down
	RiskUnknown     SideEffectRisk = "unknown"     // name says nothing usable
)

// FieldInfo is the slice of an input message the risk classifier cares about.
type FieldInfo struct {
	Name     string `json:"name"`
	Number   int32  `json:"number"`
	Type     string `json:"type"`
	Repeated bool   `json:"repeated,omitempty"`
}

// ProbeRecord is one observation. It never contains the payload bytes; it
// contains what class of payload was sent so an audit can reconstruct intent.
type ProbeRecord struct {
	Kind       ProbeKind `json:"kind"`
	Message    string    `json:"message,omitempty"` // status message, trimmed
	Code       string    `json:"code"`              // gRPC status code name
	DurationMS int64     `json:"duration_ms"`
	At         time.Time `json:"at"`
}

// Risk is the classifier's verdict with its reasons, so an operator can
// disagree with the tool.
type Risk struct {
	Level   SideEffectRisk `json:"level"`
	Score   int            `json:"score"`
	Reasons []string       `json:"reasons,omitempty"`
	// Adminish marks methods whose *service* name suggests management or
	// internals (Admin, Management, Ops, Debug, ...).
	Adminish bool `json:"adminish,omitempty"`
}

// Method is one RPC entry point.
type Method struct {
	FullName    string        `json:"full_name"` // /pkg.Service/Method
	Service     string        `json:"service"`
	Name        string        `json:"name"`
	Shape       Shape         `json:"shape"`
	Input       string        `json:"input,omitempty"`
	Output      string        `json:"output,omitempty"`
	InputFields []FieldInfo   `json:"input_fields,omitempty"`
	Origin      Confidence    `json:"origin"` // how the method became known
	Exists      bool          `json:"exists"` // proven present on the server
	ProvenBy    ProbeKind     `json:"proven_by,omitempty"`
	Risk        Risk          `json:"risk"`
	Auth        AuthState     `json:"auth"`
	Probes      []ProbeRecord `json:"probes,omitempty"`
}

// Service is one registered gRPC service.
type Service struct {
	Name     string     `json:"name"`
	Origin   Confidence `json:"origin"`
	Adminish bool       `json:"adminish,omitempty"`
	Methods  []Method   `json:"methods"`
}

// Endpoint is one address that was probed.
type Endpoint struct {
	Addr      string    `json:"addr"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Transport Transport `json:"transport,omitempty"`
	Protocol  Protocol  `json:"protocol"`
	// Detail is the short human explanation of the fingerprint verdict.
	Detail string `json:"detail,omitempty"`
	// ServerHeader is the "server" response header when the server named itself.
	ServerHeader string          `json:"server_header,omitempty"`
	TLSSubject   string          `json:"tls_subject,omitempty"`
	Reflection   ReflectionState `json:"reflection"`
	Health       HealthState     `json:"health"`
	// ServerWideUnaryAuth summarises the health/reflection evidence about a
	// global auth interceptor.
	ServerWideUnaryAuth AuthState `json:"server_wide_unary_auth"`
	Services            []Service `json:"services"`
	// Findings are endpoint-level issues worth calling out.
	Findings  []Finding `json:"findings,omitempty"`
	ScanMS    int64     `json:"scan_ms"`
	ScannedAt time.Time `json:"scanned_at"`
	Error     string    `json:"error,omitempty"`
}

// Finding is an endpoint-level conclusion.
type Finding struct {
	Kind       string     `json:"kind"`
	Severity   string     `json:"severity"` // info, low, medium, high, critical
	Summary    string     `json:"summary"`
	Evidence   []string   `json:"evidence,omitempty"`
	Confidence Confidence `json:"confidence"`
}

// ScanMeta describes how the scan was configured, so a report is reproducible.
type ScanMeta struct {
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Version     string    `json:"version"`
	Mode        string    `json:"mode"` // safe | standard | aggressive
	ProbePolicy string    `json:"probe_policy"`
	Targets     int       `json:"targets"`
	Concurrency int       `json:"concurrency"`
	RatePerSec  float64   `json:"rate_per_sec"`
	TimeoutMS   int       `json:"timeout_ms"`
	// Wordlist is the name of the wordlist used for guessing, if any.
	Wordlist string `json:"wordlist,omitempty"`
	// DescriptorSources lists the .proto files or descriptor sets loaded.
	DescriptorSources []string `json:"descriptor_sources,omitempty"`
}

// Scan is the unit written to the store: metadata plus all endpoints.
type Scan struct {
	Meta      ScanMeta   `json:"meta"`
	Endpoints []Endpoint `json:"endpoints"`
}

// AllMethods returns every method across all services, in stable order.
func (e *Endpoint) AllMethods() []*Method {
	var out []*Method
	for si := range e.Services {
		for mi := range e.Services[si].Methods {
			out = append(out, &e.Services[si].Methods[mi])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out
}

// SensitiveMethods returns methods whose risk is mutating or destructive.
func (e *Endpoint) SensitiveMethods() []*Method {
	var out []*Method
	for _, m := range e.AllMethods() {
		if m.Risk.Level == RiskMutating || m.Risk.Level == RiskDestructive {
			out = append(out, m)
		}
	}
	return out
}

// UnauthenticatedCandidates returns sensitive methods whose authorization is
// absent or unknown, i.e. the ones worth verifying.
func (e *Endpoint) UnauthenticatedCandidates() []*Method {
	var out []*Method
	for _, m := range e.SensitiveMethods() {
		switch m.Auth {
		case AuthProvenOpen, AuthInferredOpen, AuthUnknown:
			out = append(out, m)
		}
	}
	return out
}

// AddFinding appends a finding if the same kind is not already present.
func (e *Endpoint) AddFinding(f Finding) {
	for _, x := range e.Findings {
		if x.Kind == f.Kind {
			return
		}
	}
	e.Findings = append(e.Findings, f)
}

// String renders an endpoint compactly for logs.
func (e *Endpoint) String() string {
	return fmt.Sprintf("%s(%s,%s)", e.Addr, e.Protocol, e.Reflection)
}

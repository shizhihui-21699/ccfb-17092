// Package wire implements the existence oracle: the one probe the scanner uses
// to learn whether a service or method is registered, without any possibility
// of running server code.
//
// # How it works
//
// The probe is a raw HTTP/2 request that mimics a gRPC stream open:
//
//	:method        POST
//	content-type   application/grpc
//	te             trailers
//	grpc-encoding  <a marker name nobody registers>
//
// with no body. grpc-go's server checks the incoming grpc-encoding before it
// selects a decompressor, dispatches the method, or runs any interceptor or
// handler, and replies Unimplemented: "Decompressor is not installed for ...".
// For an unrecognised path it replies "unknown service" or "unknown method"
// instead. The three replies are distinguishable, and the marker encoding
// recurrence is proof the path is registered.
//
// # Why raw HTTP/2 rather than grpc-go's client
//
// A grpc-go client refuses to send with a compression name that is not
// registered in its own process-wide encoding registry. Registering the marker
// compressor there would make it visible to any gRPC server started in the same
// process — which does happen when the tool is exercised in-process, and would
// silently defeat the safety property. Sending with raw HTTP/2 headers has no
// such coupling: the compressor need not exist anywhere on the client side, and
// the marker name reaches the server exactly as intended.
//
// # Why not corrupt protobuf bytes
//
// The common alternative — sending deliberately invalid wire bytes — is unsafe
// for client-streaming and bidi methods. Generated client-streaming handlers
// enter user code before decoding the first message, so the handler body (and
// whatever it does before its first Recv) would run. The encoding oracle has no
// such shape dependence: verified against unary, server-streaming,
// client-streaming and bidi methods with handler-entry counters at zero.
package wire

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc/codes"
)

// OracleEncoding is the marker content-encoding. It must never be registered by
// any real server; the long random suffix makes accidental collision infeasible.
const OracleEncoding = "grpcscope-oracle-8d1f22c4"

// decompressSignal is grpc-go's message prefix for a missing decompressor. It
// is the proof-of-existence signal.
const decompressSignal = "Decompressor is not installed"

// Existence is the verdict for one method path.
type Existence int

const (
	// ExistsUnknown means the server replied in a way that proves nothing.
	ExistsUnknown Existence = iota
	// ServiceMissing means the server did not recognise the service.
	ServiceMissing
	// MethodMissing means the service exists but the method does not.
	MethodMissing
	// MethodExists means both the service and the method are registered.
	MethodExists
	// EndpointNotGRPC means the endpoint did not answer as a gRPC server.
	EndpointNotGRPC
)

func (e Existence) String() string {
	switch e {
	case ServiceMissing:
		return "service-missing"
	case MethodMissing:
		return "method-missing"
	case MethodExists:
		return "method-exists"
	case EndpointNotGRPC:
		return "not-grpc"
	}
	return "unknown"
}

// Result is the outcome of one oracle probe.
type Result struct {
	Path         string
	Existence    Existence
	Code         codes.Code
	Message      string
	HTTPStatus   int
	Duration     time.Duration
	ServerHeader string
}

// IsAbsence reports whether the server positively denied the path. That is the
// only verdict the scanner treats as authoritative for pruning the inventory.
func (r Result) IsAbsence() bool {
	return r.Existence == ServiceMissing || r.Existence == MethodMissing
}

// Transport describes how to reach the endpoint for the oracle.
type Transport struct {
	TLS            bool
	ConnectTimeout time.Duration
	Timeout        time.Duration
	// ServerName overrides the TLS SNI/authority. Empty uses the connection
	// target's host, as gRPC itself would.
	ServerName string
}

func (t Transport) applyDefaults() Transport {
	if t.ConnectTimeout <= 0 {
		t.ConnectTimeout = 1500 * time.Millisecond
	}
	if t.Timeout <= 0 {
		t.Timeout = 3 * time.Second
	}
	return t
}

// Client performs oracle probes against one endpoint, reusing an HTTP/2
// connection pool where the transport allows it.
type Client struct {
	addr  string
	tr    *http2.Transport
	http  *http.Client
	opt   Transport
	close func()
}

// NewClient builds an oracle client for addr. The caller must Close it.
func NewClient(addr string, opt Transport) *Client {
	opt = opt.applyDefaults()
	tr := &http2.Transport{
		AllowHTTP:       !opt.TLS,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}, ServerName: opt.ServerName},
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			d := net.Dialer{Timeout: opt.ConnectTimeout}
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if !opt.TLS {
				return raw, nil
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	return &Client{
		addr:  addr,
		tr:    tr,
		http:  &http.Client{Transport: tr, Timeout: opt.Timeout},
		opt:   opt,
		close: func() { tr.CloseIdleConnections() },
	}
}

// Close releases idle connections.
func (c *Client) Close() { c.close() }

// Oracle probes one method path. It sends no message, so no handler can run.
func (c *Client) Oracle(ctx context.Context, path string) Result {
	start := time.Now()
	r := Result{Path: path}

	cctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()

	scheme := "http"
	if c.opt.TLS {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, scheme+"://"+c.addr+path, bytes.NewReader(nil))
	if err != nil {
		r.Existence = ExistsUnknown
		r.Message = err.Error()
		r.Duration = time.Since(start)
		return r
	}
	// Headers a gRPC server expects on a stream open, minus any message.
	req.Header.Set("content-type", "application/grpc")
	req.Header.Set("te", "trailers")
	req.Header.Set("grpc-encoding", OracleEncoding)
	req.Header.Set("grpc-accept-encoding", "identity")
	req.Header.Set("user-agent", "grpcscope-oracle")
	req.ContentLength = 0

	resp, err := c.http.Do(req)
	if err != nil {
		r.Existence = classifyTransportErr(err)
		r.Message = trimMessage(err.Error())
		r.Duration = time.Since(start)
		return r
	}
	defer resp.Body.Close()

	// Drain the body so trailers are populated by the HTTP/2 client.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	r.HTTPStatus = resp.StatusCode
	r.ServerHeader = resp.Header.Get("server")
	gs, gm := resp.Trailer.Get("grpc-status"), resp.Trailer.Get("grpc-message")
	if gs == "" {
		gs, gm = resp.Header.Get("grpc-status"), resp.Header.Get("grpc-message")
	}
	r.Code, r.Message = parseGRPCStatus(gs, gm)
	r.Existence = classifyReply(resp.StatusCode, r.Code, r.Message)
	r.Duration = time.Since(start)
	return r
}

// parseGRPCStatus turns the wire headers into a code and message. gRPC encodes
// the message with percent-encoding, so it must be decoded before matching.
func parseGRPCStatus(statusStr, msgStr string) (codes.Code, string) {
	code := codes.Unknown
	if statusStr != "" {
		if n, err := strconv.Atoi(statusStr); err == nil {
			code = codes.Code(n)
		}
	}
	msg := decodePercent(msgStr)
	return code, trimMessage(msg)
}

// decodePercent applies the gRPC percent-encoding used for grpc-message.
func decodePercent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, err1 := strconv.ParseUint(s[i+1:i+3], 16, 8); err1 == nil {
				b.WriteByte(byte(hi))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func classifyReply(httpStatus int, code codes.Code, message string) Existence {
	switch {
	case strings.Contains(message, decompressSignal):
		return MethodExists
	case strings.Contains(message, "unknown service"):
		return ServiceMissing
	case strings.Contains(message, "unknown method"):
		return MethodMissing
	case httpStatus == http.StatusOK && code == codes.OK:
		// An empty request to a method with no required fields can complete.
		// That proves existence, though it may have run a handler; callers
		// must not treat an OK reply as proof of *nothing happening*.
		return MethodExists
	case httpStatus == http.StatusOK:
		// No status trailers at all: the server is not a gRPC server, or it
		// closed without a status. Inconclusive.
		return ExistsUnknown
	case httpStatus == http.StatusNotFound || httpStatus == http.StatusMethodNotAllowed:
		return EndpointNotGRPC
	case httpStatus >= 400 && httpStatus < 500:
		// A gRPC server answers HTTP 200 with a status trailer; anything else is
		// an HTTP-layer rejection, not a gRPC registration answer.
		return ExistsUnknown
	}
	return ExistsUnknown
}

func classifyTransportErr(err error) Existence {
	if err == nil {
		return ExistsUnknown
	}
	st := err.Error()
	switch {
	case strings.Contains(st, "http2"),
		strings.Contains(st, "connection"),
		strings.Contains(st, "dial"):
		// Transport-level: not a registration verdict.
		return EndpointNotGRPC
	}
	return ExistsUnknown
}

func trimMessage(s string) string {
	s = strings.ReplaceAll(s, " ", " ")
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// IsAuthCode reports whether a status code is an authorization decision rather
// than a server capability failure.
func IsAuthCode(c codes.Code) bool {
	return c == codes.Unauthenticated || c == codes.PermissionDenied
}

// IsAuthishMessage catches the common practice of servers returning
// codes.Unknown/Internal with an auth-looking message.
func IsAuthishMessage(msg string) bool {
	low := strings.ToLower(msg)
	for _, s := range []string{
		"unauthorized", "unauthenticated", "forbidden", "permission denied",
		"access denied", "not authorized", "missing token", "invalid token",
		"no credentials", "authentication required", "missing credentials",
	} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// ParseForTest exposes status parsing to tests without widening the API.
func ParseForTest(statusStr, msgStr string) (codes.Code, string) {
	return parseGRPCStatus(statusStr, msgStr)
}

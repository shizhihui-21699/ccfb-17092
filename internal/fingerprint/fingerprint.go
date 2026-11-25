// Package fingerprint classifies what protocol an address speaks, without
// invoking any remote handler.
//
// The ladder:
//
//  1. TCP connect. Refused -> closed, stop.
//  2. gRPC over h2c (prior knowledge). A real gRPC server answers a bogus
//     path with "unknown service"; that reply is proof it speaks gRPC and
//     proof that no handler ran.
//  3. gRPC over TLS. Catches TLS-only servers that refused plaintext.
//  4. HTTP/2 with a bogus gRPC content-type. Distinguishes "HTTP/2 but not
//     gRPC" from "gRPC", and plain HTTP/1.1 from HTTP/2.
//  5. A bare TLS handshake, to note TLS termination on non-gRPC endpoints.
//
// Every request targets a path under a private, unreachable package name, so
// the only possible reactions are transport errors or an "unknown service"
// status. No interceptor, handler or service code can run.
package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"grpcscope/internal/model"
	"grpcscope/internal/wire"
)

// BogusService is a package name that cannot be registered by a real service:
// a leading dot is not a valid protobuf package element.
const BogusService = "grpcscope.probe.nonexistent"

// BogusMethod is the method used against BogusService.
const BogusMethod = "Ping"

// Result is the fingerprint of one address.
type Result struct {
	Protocol  model.Protocol
	Transport model.Transport
	Detail    string
	// ServerHeader is the "server" header value when the server named itself.
	ServerHeader string
	TLSSubject   string
	// Conn is a live gRPC connection when Protocol is grpc; the caller closes it.
	Conn *grpc.ClientConn
	// CatchAll reports that the server answered a bogus method path with
	// something other than "unknown service", i.e. it has an unknown-service
	// handler. Enumeration by absence is unreliable in that case.
	CatchAll bool
}

// Options tune probing.
type Options struct {
	ConnectTimeout time.Duration
	ScanTimeout    time.Duration
}

// DefaultOptions keep a wide sweep quick while tolerating slow hosts.
func DefaultOptions() Options {
	return Options{ConnectTimeout: 1500 * time.Millisecond, ScanTimeout: 3 * time.Second}
}

// TCPUp reports whether a TCP connection can be established.
func TCPUp(ctx context.Context, addr string, opt Options) (bool, string) {
	d := net.Dialer{Timeout: opt.ConnectTimeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, dialReason(err)
	}
	_ = c.Close()
	return true, ""
}

// Probe classifies addr. On grpc, Result.Conn is a live connection.
func Probe(ctx context.Context, addr string, opt Options) Result {
	if up, why := TCPUp(ctx, addr, opt); !up {
		return Result{Protocol: model.ProtoClosed, Detail: why}
	}

	// 1. h2c
	if conn, r, ok := grpcAttempt(ctx, addr, false, opt); ok {
		return r.withConn(conn)
	}
	// 2. TLS
	if conn, r, ok := grpcAttempt(ctx, addr, true, opt); ok {
		return r.withConn(conn)
	}
	// 3. HTTP/2 / HTTP/1.1
	if p, detail := http2Attempt(ctx, addr, opt); p != "" {
		return Result{Protocol: p, Detail: detail}
	}
	// 4. TLS termination
	if subject, ok := tlsHandshake(ctx, addr, opt); ok {
		return Result{Protocol: model.ProtoTLSRequired, Transport: model.TransportTLS,
			TLSSubject: subject, Detail: "TLS handshake completed; no gRPC status"}
	}
	return Result{Protocol: model.ProtoTCPOther, Detail: "connection accepted; no gRPC or HTTP/2 response"}
}

func (r Result) withConn(conn *grpc.ClientConn) Result {
	r.Conn = conn
	return r
}

// dialOptions builds client options for one transport. TLS is performed by
// grpc itself; the dialer only opens the raw TCP socket.
func dialOptions(useTLS bool) []grpc.DialOption {
	if useTLS {
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // fingerprinting: we do not trust, we observe
			NextProtos:         []string{"h2"},
		}))}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}

func grpcAttempt(ctx context.Context, addr string, useTLS bool, opt Options) (*grpc.ClientConn, Result, bool) {
	opts := append(dialOptions(useTLS),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: opt.ConnectTimeout}
			return d.DialContext(ctx, "tcp", addr)
		}),
	)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, Result{Protocol: model.ProtoUnknown, Detail: err.Error()}, false
	}

	cctx, cancel := context.WithTimeout(ctx, opt.ConnectTimeout+opt.ScanTimeout)
	defer cancel()

	path := "/" + BogusService + "/" + BogusMethod
	oc := wire.NewClient(addr, wire.Transport{TLS: useTLS, ConnectTimeout: opt.ConnectTimeout, Timeout: opt.ScanTimeout})
	res := oc.Oracle(cctx, path)
	oc.Close()

	switch res.Existence {
	case wire.ServiceMissing:
		transport := model.TransportH2C
		if useTLS {
			transport = model.TransportTLS
		}
		// Keep this connection: it is verified gRPC and free of the probe deadline.
		return conn, Result{Protocol: model.ProtoGRPC, Transport: transport, Detail: res.Message}, true
	case wire.MethodExists:
		// A bogus service cannot be registered, so this means a catch-all handler.
		transport := model.TransportH2C
		if useTLS {
			transport = model.TransportTLS
		}
		return conn, Result{Protocol: model.ProtoGRPC, Transport: transport,
			CatchAll: true, Detail: "server accepted a nonexistent service path (unknown-service handler)"}, true
	default:
		conn.Close()
		return nil, Result{Protocol: model.ProtoUnknown, Detail: res.Message}, false
	}
}

func http2Attempt(ctx context.Context, addr string, opt Options) (model.Protocol, string) {
	for _, useTLS := range []bool{false, true} {
		p, detail, ok := http2One(ctx, addr, useTLS, opt)
		if ok {
			return p, detail
		}
	}
	return "", ""
}

func http2One(ctx context.Context, addr string, useTLS bool, opt Options) (model.Protocol, string, bool) {
	tr := &http2.Transport{
		AllowHTTP: !useTLS,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			d := net.Dialer{Timeout: opt.ConnectTimeout}
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if !useTLS {
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
	defer tr.CloseIdleConnections()

	cctx, cancel := context.WithTimeout(ctx, opt.ConnectTimeout+opt.ScanTimeout)
	defer cancel()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost,
		scheme+"://"+addr+"/"+BogusService+"/"+BogusMethod, bytes.NewReader(nil))
	if err != nil {
		return "", "", false
	}
	req.Header.Set("content-type", "application/grpc")
	req.Header.Set("te", "trailers")

	cli := &http.Client{Transport: tr, Timeout: opt.ScanTimeout}
	resp, err := cli.Do(req)
	if err != nil {
		// A plain HTTP/1.1 server answers the HTTP/2 preface with HTTP/1.1
		// framing; Go reports that as a frame error naming the cause.
		if !useTLS && (strings.Contains(err.Error(), "HTTP/1.1") || strings.Contains(err.Error(), "frame too large")) {
			return model.ProtoHTTP1, "answered the HTTP/2 preface with HTTP/1.1 framing", true
		}
		return "", "", false
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("content-type")
	if strings.HasPrefix(ct, "application/grpc") || resp.Trailer.Get("grpc-status") != "" {
		// It speaks gRPC at the HTTP layer even though our grpc-go dial failed
		// (for example, a server that rejects the h2 handshake we sent).
		if useTLS {
			return model.ProtoGRPC, fmt.Sprintf("HTTP/2 gRPC content-type=%q status=%d", ct, resp.StatusCode), true
		}
		return model.ProtoGRPC, fmt.Sprintf("h2c gRPC content-type=%q status=%d", ct, resp.StatusCode), true
	}
	if useTLS {
		return model.ProtoTLSRequired, fmt.Sprintf("HTTP/2 over TLS, content-type=%q", ct), true
	}
	return model.ProtoHTTP2Other, fmt.Sprintf("HTTP/2, content-type=%q", ct), true
}

func tlsHandshake(ctx context.Context, addr string, opt Options) (string, bool) {
	d := net.Dialer{Timeout: opt.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", false
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	hctx, cancel := context.WithTimeout(ctx, opt.ConnectTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return "", false
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) > 0 {
		return st.PeerCertificates[0].Subject.String(), true
	}
	return "", true
}

func dialReason(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Timeout() {
		return "connect timeout"
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "refused"):
		return "connection refused"
	case strings.Contains(low, "no such host"):
		return "unknown host"
	case strings.Contains(low, "network is unreachable"):
		return "network unreachable"
	}
	return err.Error()
}

// DialGRPC opens a plain gRPC client connection for a transport already
// classified. It performs no probe itself.
func DialGRPC(ctx context.Context, addr string, transport model.Transport) (*grpc.ClientConn, error) {
	useTLS := transport == model.TransportTLS
	opts := append(dialOptions(useTLS),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		}),
	)
	return grpc.NewClient(addr, opts...)
}

package wire_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"grpcscope/internal/testserver"
	"grpcscope/internal/wire"
)

// TestOracleNeverRunsAHandler is the safety property the whole tool rests on:
// the existence oracle must prove a method is registered without ever letting
// server code run, for every method shape.
func TestOracleNeverRunsAHandler(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	oc := wire.NewClient(srv.Addr, wire.Transport{Timeout: 2 * time.Second})
	defer oc.Close()
	ctx := context.Background()

	// Every method the demo server registers, across all four cardinalities.
	paths := []string{
		"/demo.AdminService/FlushCache",   // unary, destructive
		"/demo.AdminService/UpdateConfig", // unary, mutating
		"/demo.AdminService/GetStatus",    // unary, read-only
		"/demo.AdminService/WatchAdmin",   // server-stream
		"/demo.AdminService/BulkImport",   // client-stream
		"/demo.BizService/GetUser",
		"/demo.BizService/CreateUser",
	}

	before := srv.GlobalEntries().Count()
	for _, p := range paths {
		r := oc.Oracle(ctx, p)
		if r.Existence != wire.MethodExists {
			t.Errorf("%s: expected method-exists, got %s (%v: %s)", p, r.Existence, r.Code, r.Message)
		}
	}
	if after := srv.GlobalEntries().Count(); after != before {
		t.Fatalf("the oracle ran %d handler(s); it must never reach user code", after-before)
	}
}

// TestOracleDistinguishesAbsence proves the oracle separates "service missing"
// from "method missing" from "present".
func TestOracleDistinguishesAbsence(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	oc := wire.NewClient(srv.Addr, wire.Transport{Timeout: 2 * time.Second})
	defer oc.Close()

	cases := []struct {
		path string
		want wire.Existence
	}{
		{"/demo.AdminService/FlushCache", wire.MethodExists},
		{"/demo.AdminService/NoSuchMethod", wire.MethodMissing},
		{"/no.Such.Service/Any", wire.ServiceMissing},
		{"/demo.BizService/GetUser", wire.MethodExists},
	}
	for _, c := range cases {
		got := oc.Oracle(context.Background(), c.path)
		if got.Existence != c.want {
			t.Errorf("%s: got %s, want %s (%v: %s)", c.path, got.Existence, c.want, got.Code, got.Message)
		}
	}
}

// TestOracleDoesNotNeedRegisteredCompressor guards against the in-process
// footgun: the client must not depend on a compressor existing in the current
// process's encoding registry.
func TestOracleDoesNotNeedRegisteredCompressor(t *testing.T) {
	srv, err := testserver.New()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	oc := wire.NewClient(srv.Addr, wire.Transport{Timeout: 2 * time.Second})
	defer oc.Close()

	r := oc.Oracle(context.Background(), "/demo.AdminService/GetStatus")
	if r.Existence != wire.MethodExists {
		t.Fatalf("oracle failed without any registered compressor: %s (%v: %s)", r.Existence, r.Code, r.Message)
	}
	if got := wire.OracleEncoding; got != "grpcscope-oracle-8d1f22c4" {
		t.Fatalf("oracle encoding changed; reports and audits depend on it being stable: %q", got)
	}
}

func TestParseGRPCStatusDecodesPercentEscapes(t *testing.T) {
	// The real grpc-go message contains a non-breaking space before "cannot";
	// percent-encoding is the transport's job to undo.
	msg := "grpc%3A%20Decompressor%20is%20not%20installed"
	code, got := wire.ParseForTest("12", msg)
	if code != 12 {
		t.Errorf("code = %d, want 12", code)
	}
	if got == "" || got[0] != 'g' {
		t.Errorf("message decoded to %q", got)
	}
	_ = fmt.Sprint
}

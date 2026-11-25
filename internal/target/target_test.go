package target_test

import (
	"testing"

	"grpcscope/internal/config"
	"grpcscope/internal/target"
)

func TestExpandDedupesAndOrders(t *testing.T) {
	ts, err := target.Expand(config.Targets{
		Addresses: []string{"10.0.0.2:50051", "10.0.0.1:50051", "10.0.0.2:50051"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 {
		t.Fatalf("expected 2 unique targets, got %d: %v", len(ts), ts)
	}
	if ts[0].Host != "10.0.0.1" || ts[1].Host != "10.0.0.2" {
		t.Errorf("targets not sorted by host: %v", ts)
	}
}

func TestExpandCIDR(t *testing.T) {
	ts, err := target.Expand(config.Targets{
		CIDRs: []string{"10.1.0.0/30"},
		Ports: []int{50051},
	})
	if err != nil {
		t.Fatal(err)
	}
	// /30 has four addresses.
	if len(ts) != 4 {
		t.Fatalf("expected 4 addresses from a /30, got %d", len(ts))
	}
}

func TestExpandEmptyErrors(t *testing.T) {
	if _, err := target.Expand(config.Targets{}); err == nil {
		t.Fatal("empty target set should error")
	}
}

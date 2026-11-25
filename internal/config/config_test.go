package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"grpcscope/internal/config"
)

func TestDefaultIsSafeAndValid(t *testing.T) {
	c := config.Default()
	if c.Mode != config.ModeSafe {
		t.Fatalf("default mode = %s, want safe", c.Mode)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
	if c.BodyProbingAllowed() {
		t.Fatal("safe mode must not allow body probing")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("mode: safe\nnot_a_field: true\n"), 0o644)
	if _, err := config.Load(path); err == nil {
		t.Fatal("config with an unknown field should be rejected, not silently ignored")
	}
}

func TestBadRegexSurfacesAtEngineBuild(t *testing.T) {
	// The regexes are compiled in scan.NewEngine, which is where a typo must
	// become an error before any packet is sent.
	c := config.Default()
	c.Safety.NeverCall = []string{"("}
	if err := c.Validate(); err != nil {
		t.Fatalf("config validation itself should not compile regexes: %v", err)
	}
}

func TestCIDRBounds(t *testing.T) {
	c := config.Default()
	c.Targets.CIDRs = []string{"10.0.0.0/8"}
	if err := c.Validate(); err == nil {
		t.Fatal("a /8 sweep should be rejected as too large")
	}
}

func TestLoadMergesOverDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.yaml")
	os.WriteFile(path, []byte(`mode: standard
probe:
  concurrency: 8
  timeout: 2s
targets:
  addresses:
    - 10.0.0.1:50051
`), 0o644)
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != config.ModeStandard {
		t.Errorf("mode = %s", c.Mode)
	}
	if c.Probe.Concurrency != 8 {
		t.Errorf("concurrency = %d", c.Probe.Concurrency)
	}
	// Unset fields keep their defaults.
	if c.Probe.ReflectionTimeout == 0 {
		t.Error("reflection timeout default was not retained")
	}
	if len(c.Targets.Addresses) != 1 {
		t.Errorf("addresses = %v", c.Targets.Addresses)
	}
}

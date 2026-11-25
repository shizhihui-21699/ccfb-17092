// Package config loads and validates the scan configuration.
//
// Configuration is YAML or JSON, and every field has a safe default: running
// with only a target list performs read-only discovery, never a state-changing
// call.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode selects the maximum aggressiveness of the probe plan.
type Mode string

const (
	// ModeSafe uses only provably inert probes: reflection listing, the health
	// check, and the encoding existence oracle. It never sends a request body
	// into a handler.
	ModeSafe Mode = "safe"
	// ModeStandard additionally sends poison payloads into unary and
	// server-streaming methods (which decode before user code) to confirm
	// existence when the oracle is unavailable, and sends inert empty requests
	// into methods whose names mark them read-only. It still never calls a
	// method that looks mutating or destructive.
	ModeStandard Mode = "standard"
	// ModeAggressive additionally sends empty requests into any unary method
	// with a descriptor known and no required fields, regardless of risk name.
	// It is intended for isolated test environments with written authorization.
	ModeAggressive Mode = "aggressive"
)

// Config is the whole scan plan.
type Config struct {
	Mode        Mode          `yaml:"mode" json:"mode"`
	Targets     Targets       `yaml:"targets" json:"targets"`
	Probe       ProbeSettings `yaml:"probe" json:"probe"`
	Discovery   Discovery     `yaml:"discovery" json:"discovery"`
	Wordlists   Wordlists     `yaml:"wordlists" json:"wordlists"`
	Descriptors Descriptors   `yaml:"descriptors" json:"descriptors"`
	Safety      Safety        `yaml:"safety" json:"safety"`
	Output      Output        `yaml:"output" json:"output"`
}

// Targets says where to scan.
type Targets struct {
	// Addresses are explicit host:port entries.
	Addresses []string `yaml:"addresses" json:"addresses"`
	// Files are newline-delimited host:port lists.
	Files []string `yaml:"files" json:"files"`
	// CIDRs are networks to sweep across Ports.
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
	// Hosts are individual hosts swept across Ports.
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Ports are the ports tried for CIDRs and Hosts.
	Ports []int `yaml:"ports" json:"ports"`
}

// ProbeSettings bound the probing behaviour.
type ProbeSettings struct {
	Concurrency       int           `yaml:"concurrency" json:"concurrency"`
	RatePerSec        float64       `yaml:"rate_per_sec" json:"rate_per_sec"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	ConnectTimeout    time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	ReflectionTimeout time.Duration `yaml:"reflection_timeout" json:"reflection_timeout"`
	// MaxMethodsPerService caps enumeration so a pathological server cannot
	// make the tool spin forever.
	MaxMethodsPerService int `yaml:"max_methods_per_service" json:"max_methods_per_service"`
	// ConfirmWithOracle re-probes every method discovered from descriptors or
	// wordlists against the live server, so nothing is reported as present
	// without proof.
	ConfirmWithOracle bool `yaml:"confirm_with_oracle" json:"confirm_with_oracle"`
}

// Discovery controls how much guessing happens when reflection is absent.
type Discovery struct {
	// GuessServices tries the service wordlist against every grpc endpoint
	// that did not expose reflection.
	GuessServices bool `yaml:"guess_services" json:"guess_services"`
	// GuessMethods, for each service proven to exist, tries the method
	// wordlist against it.
	GuessMethods bool `yaml:"guess_methods" json:"guess_methods"`
	// MaxGuessServices bounds the cross product.
	MaxGuessServices int `yaml:"max_guess_services" json:"max_guess_services"`
	// MaxGuessMethodsPerService bounds per-service guessing.
	MaxGuessMethodsPerService int `yaml:"max_guess_methods_per_service" json:"max_guess_methods_per_service"`
	// ReflectionProbe asks every grpc endpoint for reflection even when the
	// fingerprint stage already saw an "unknown service" reply.
	ReflectionProbe bool `yaml:"reflection_probe" json:"reflection_probe"`
	// HealthProbe asks the standard health service for its status.
	HealthProbe bool `yaml:"health_probe" json:"health_probe"`
}

// Wordlists locate the candidate names used when reflection is absent.
type Wordlists struct {
	Services []string `yaml:"services" json:"services"`
	Methods  []string `yaml:"methods" json:"methods"`
}

// Descriptors locate .proto sources or compiled descriptor sets.
type Descriptors struct {
	Protos []string `yaml:"protos" json:"protos"` // files or dirs
	Sets   []string `yaml:"sets" json:"sets"`     // .pb descriptor set files
}

// Safety is the operator's veto list; it is enforced before any probe.
type Safety struct {
	// NeverCall lists regular expressions matched against the full method
	// name. A match means the method is never sent a request body, even an
	// empty one; only the inert existence oracle may touch it.
	NeverCall []string `yaml:"never_call" json:"never_call"`
	// NeverTouch lists regular expressions whose matches are not probed at all,
	// not even by the oracle. Use for production-critical services.
	NeverTouch []string `yaml:"never_touch" json:"never_touch"`
	// AllowedCall lists regular expressions that re-enable body probes inside
	// an otherwise forbidden area. It cannot override NeverTouch.
	AllowedCall []string `yaml:"allowed_call" json:"allowed_call"`
	// MaxTargets is the largest sweep permitted without -allow-large. It exists
	// so a mistyped CIDR cannot quietly turn into a multi-hour scan that fills a
	// log file and saturates a shared network segment.
	MaxTargets int `yaml:"max_targets" json:"max_targets"`
	// AllowLarge removes the MaxTargets cap. It is mirrored by the -allow-large
	// flag and is false by default.
	AllowLarge bool `yaml:"allow_large" json:"allow_large"`
}

// Output controls result persistence and rendering.
type Output struct {
	Dir     string   `yaml:"dir" json:"dir"`
	Formats []string `yaml:"formats" json:"formats"` // json, markdown, sarif
	// FailOnExitCode returns a non-zero exit status when findings at or above
	// this severity exist (for CI gating).
	FailOn string `yaml:"fail_on" json:"fail_on"`
}

// Default returns the plan used when no config file is given.
func Default() *Config {
	return &Config{
		Mode: ModeSafe,
		Targets: Targets{
			Ports: []int{50051, 9090, 8080, 8443, 50052, 6565, 7070, 9091},
		},
		Probe: ProbeSettings{
			Concurrency:          32,
			RatePerSec:           200,
			Timeout:              4 * time.Second,
			ConnectTimeout:       1500 * time.Millisecond,
			ReflectionTimeout:    6 * time.Second,
			MaxMethodsPerService: 2000,
			ConfirmWithOracle:    true,
		},
		Discovery: Discovery{
			GuessServices:             true,
			GuessMethods:              true,
			MaxGuessServices:          400,
			MaxGuessMethodsPerService: 120,
			ReflectionProbe:           true,
			HealthProbe:               true,
		},
		Safety: Safety{MaxTargets: 5000},
		Output: Output{
			Dir:     "results",
			Formats: []string{"json", "markdown"},
		},
	}
}

// Load reads a YAML or JSON config file and merges it over Default.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks the plan for internal contradictions before any packet is
// sent.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeSafe, ModeStandard, ModeAggressive:
	default:
		return fmt.Errorf("mode %q is not one of safe, standard, aggressive", c.Mode)
	}
	if c.Probe.Concurrency < 1 {
		c.Probe.Concurrency = 1
	}
	if c.Probe.Concurrency > 512 {
		return fmt.Errorf("concurrency %d is unreasonably high; cap at 512", c.Probe.Concurrency)
	}
	if c.Probe.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	for _, a := range c.Targets.Addresses {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("target %q must be host:port: %w", a, err)
		}
	}
	for _, cidr := range c.Targets.CIDRs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("cidr %q: %w", cidr, err)
		}
		_ = ip
		ones, _ := ipnet.Mask.Size()
		if ones < 16 {
			return fmt.Errorf("cidr %q spans more than /16; split it explicitly", cidr)
		}
	}
	for _, f := range c.Output.Formats {
		switch f {
		case "json", "markdown", "sarif":
		default:
			return fmt.Errorf("output format %q not supported (json, markdown, sarif)", f)
		}
	}
	if c.Output.FailOn != "" {
		switch c.Output.FailOn {
		case "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("fail_on must be one of info, low, medium, high, critical")
		}
	}
	if c.Mode != ModeAggressive && len(c.Safety.AllowedCall) > 0 {
		// allowed_call widens body probing, which only aggressive mode permits
		// as a blanket behaviour; in safer modes it only re-enables read-only
		// probes, which is fine, so this is informational rather than an error.
		_ = c.Safety.AllowedCall
	}
	return nil
}

// BodyProbingAllowed reports whether the plan permits sending any request body
// into user code at all.
func (c *Config) BodyProbingAllowed() bool {
	return c.Mode == ModeStandard || c.Mode == ModeAggressive
}

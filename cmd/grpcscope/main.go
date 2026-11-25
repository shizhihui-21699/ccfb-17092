// Command grpcscope discovers gRPC services on an internal network, enumerates
// their methods, and identifies administrative or state-changing methods
// reachable without authorization — without ever invoking one.
//
// Run `grpcscope help` for usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/reflect/protoregistry"

	"grpcscope/internal/config"
	"grpcscope/internal/descriptors"
	"grpcscope/internal/model"
	reportpkg "grpcscope/internal/report"
	"grpcscope/internal/scan"
	"grpcscope/internal/sched"
	"grpcscope/internal/store"
	"grpcscope/internal/target"
	"grpcscope/internal/testserver"
	"grpcscope/internal/wordlist"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "-h", "--help":
			usage()
			return
		case "version", "-v", "--version":
			fmt.Println("grpcscope", version)
			return
		case "selftest":
			if err := selftest(); err != nil {
				fmt.Fprintln(os.Stderr, "selftest failed:", err)
				os.Exit(1)
			}
			return
		case "diff":
			if err := runDiff(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "diff:", err)
				os.Exit(1)
			}
			return
		}
	}
	// os.Args[0] is the program; os.Args[1] is the subcommand. Flags begin at
	// os.Args[2]. Passing the subcommand name to the flag set would stop
	// parsing at the first non-flag argument and silently ignore every flag.
	if err := runScan(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "grpcscope:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`grpcscope — internal gRPC exposure scanner

Usage:
  grpcscope scan [flags]        discover endpoints and enumerate methods
  grpcscope diff [flags]        compare the two most recent scans
  grpcscope selftest           run the built-in load/scan self-check
  grpcscope version

Discovery:
  -config path                 YAML or JSON plan (see config.example.yaml)
  -addr host:port              repeatable; scan specific addresses
  -cidr 10.0.0.0/24            sweep a network across -ports
  -host 10.0.0.5               sweep one host across -ports
  -ports 50051,9090            ports for -cidr and -host (default 50051,9090,...)
  -file path                   file of host:port entries, one per line

Enumeration:
  -proto path                  .proto file or dir, repeatable
  -descset path                compiled FileDescriptorSet, repeatable
  -service-wordlist path       candidate service names
  -method-wordlist path        candidate method names
  -no-guess                    disable wordlist guessing

Probing:
  -mode safe|standard|aggressive   (default safe)
  -concurrency 32
  -rate 200                    requests per second across the scan
  -timeout 4s                  per-probe timeout
  -never-call 'regex'          never send a request body, repeatable
  -never-touch 'regex'         do not probe at all, repeatable
  -allowed-call 'regex'        re-enable body probes inside never-call

Output:
  -out results                 result directory
  -formats json,markdown,sarif
  -fail-on high                exit non-zero at or above this severity
`)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		cfgPath        string
		addrs          multiFlag
		cidrs          multiFlag
		hosts          multiFlag
		files          multiFlag
		protos         multiFlag
		sets           multiFlag
		svcWordlist    multiFlag
		methodWordlist multiFlag
		neverCall      multiFlag
		neverTouch     multiFlag
		allowedCall    multiFlag
		ports          string
		mode           string
		concurrency    int
		rateLimit      float64
		timeout        time.Duration
		outDir         string
		formats        string
		failOn         string
		noGuess        bool
		allowLarge     bool
		connectTimeout time.Duration
	)
	fs.Var(&addrs, "addr", "host:port to scan (repeatable)")
	fs.Var(&cidrs, "cidr", "network to sweep (repeatable)")
	fs.Var(&hosts, "host", "host to sweep across ports (repeatable)")
	fs.Var(&files, "file", "file of host:port entries (repeatable)")
	fs.Var(&protos, "proto", ".proto file or directory (repeatable)")
	fs.Var(&sets, "descset", "compiled descriptor set (repeatable)")
	fs.Var(&svcWordlist, "service-wordlist", "service name wordlist (repeatable)")
	fs.Var(&methodWordlist, "method-wordlist", "method name wordlist (repeatable)")
	fs.Var(&neverCall, "never-call", "regex: never send a body (repeatable)")
	fs.Var(&neverTouch, "never-touch", "regex: never probe (repeatable)")
	fs.Var(&allowedCall, "allowed-call", "regex: allow bodies inside never-call (repeatable)")
	fs.StringVar(&cfgPath, "config", "", "YAML or JSON plan file")
	fs.StringVar(&ports, "ports", "50051,9090,8080,8443,50052,6565,7070,9091", "ports for -cidr/-host")
	fs.StringVar(&mode, "mode", "", "safe|standard|aggressive")
	fs.IntVar(&concurrency, "concurrency", 0, "in-flight probe limit")
	fs.Float64Var(&rateLimit, "rate", 0, "requests per second (0 uses config)")
	fs.DurationVar(&timeout, "timeout", 0, "per-probe timeout")
	fs.DurationVar(&connectTimeout, "connect-timeout", 0, "TCP connect timeout")
	fs.StringVar(&outDir, "out", "", "result directory")
	fs.StringVar(&formats, "formats", "", "json,markdown,sarif")
	fs.StringVar(&failOn, "fail-on", "", "exit non-zero at or above severity")
	fs.BoolVar(&noGuess, "no-guess", false, "disable wordlist guessing")
	fs.BoolVar(&allowLarge, "allow-large", false, "permit sweeps larger than safety.max_targets")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Default()
	if cfgPath != "" {
		loaded, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		cfg = loaded
	}

	// Command-line flags override the config file.
	if mode != "" {
		cfg.Mode = config.Mode(mode)
	}
	if concurrency > 0 {
		cfg.Probe.Concurrency = concurrency
	}
	if rateLimit > 0 {
		cfg.Probe.RatePerSec = rateLimit
	}
	if timeout > 0 {
		cfg.Probe.Timeout = timeout
	}
	if connectTimeout > 0 {
		cfg.Probe.ConnectTimeout = connectTimeout
	}
	if outDir != "" {
		cfg.Output.Dir = outDir
	}
	if formats != "" {
		cfg.Output.Formats = splitList(formats)
	}
	if failOn != "" {
		cfg.Output.FailOn = failOn
	}
	if noGuess {
		cfg.Discovery.GuessServices = false
		cfg.Discovery.GuessMethods = false
	}
	if allowLarge {
		cfg.Safety.AllowLarge = true
	}
	cfg.Targets.Addresses = append(cfg.Targets.Addresses, addrs...)
	cfg.Targets.CIDRs = append(cfg.Targets.CIDRs, cidrs...)
	cfg.Targets.Hosts = append(cfg.Targets.Hosts, hosts...)
	cfg.Targets.Files = append(cfg.Targets.Files, files...)
	cfg.Descriptors.Protos = append(cfg.Descriptors.Protos, protos...)
	cfg.Descriptors.Sets = append(cfg.Descriptors.Sets, sets...)
	cfg.Safety.NeverCall = append(cfg.Safety.NeverCall, neverCall...)
	cfg.Safety.NeverTouch = append(cfg.Safety.NeverTouch, neverTouch...)
	cfg.Safety.AllowedCall = append(cfg.Safety.AllowedCall, allowedCall...)
	if len(ports) > 0 {
		p, err := parsePorts(ports)
		if err != nil {
			return err
		}
		cfg.Targets.Ports = p
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	targets, err := target.Expand(cfg.Targets)
	if err != nil {
		return err
	}
	if max := cfg.Safety.MaxTargets; max > 0 && !cfg.Safety.AllowLarge && len(targets) > max {
		return fmt.Errorf("target set expands to %d addresses, above safety.max_targets (%d); narrow the sweep or pass -allow-large", len(targets), max)
	}

	// Load wordlists: built-in defaults, then any supplied files.
	svcWords := wordlist.Union(wordlist.AdminServices, wordlist.DefaultServices)
	methodWords := wordlist.DefaultMethods
	wordlistName := "builtin"
	if len(svcWordlist) > 0 {
		extra, err := wordlist.LoadFiles(svcWordlist)
		if err != nil {
			return err
		}
		svcWords = wordlist.Union(extra, svcWords)
		wordlistName = "custom+builtin"
	}
	if len(methodWordlist) > 0 {
		extra, err := wordlist.LoadFiles(methodWordlist)
		if err != nil {
			return err
		}
		methodWords = wordlist.Union(extra, methodWords)
		wordlistName = "custom+builtin"
	}

	// Load descriptors.
	var descFiles *protoregistry.Files
	var descSources []string
	if len(cfg.Descriptors.Protos) > 0 || len(cfg.Descriptors.Sets) > 0 {
		reg, err := descriptors.Load(cfg.Descriptors.Protos, cfg.Descriptors.Sets)
		if err != nil {
			return err
		}
		descFiles = reg.Files
		descSources = reg.Sources
	}

	engine, err := scan.NewEngine(cfg, svcWords, methodWords, wordlist.Packages, descFiles)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	meta := model.ScanMeta{
		StartedAt:         time.Now(),
		Version:           version,
		Mode:              string(cfg.Mode),
		ProbePolicy:       probePolicy(cfg),
		Targets:           len(targets),
		Concurrency:       cfg.Probe.Concurrency,
		RatePerSec:        cfg.Probe.RatePerSec,
		TimeoutMS:         int(cfg.Probe.Timeout / time.Millisecond),
		Wordlist:          wordlistName,
		DescriptorSources: descSources,
	}

	sc := sched.New(cfg.Probe.Concurrency, cfg.Probe.RatePerSec)
	var endpoints []model.Endpoint
	var mu sync.Mutex
	done := make(chan struct{})
	var scanned int

	fmt.Fprintf(os.Stderr, "grpcscope: scanning %d target(s) in %s mode\n", len(targets), cfg.Mode)
	for _, t := range targets {
		t := t
		sc.Go(ctx, func() {
			ep := engine.ScanEndpoint(ctx, t.Addr)
			mu.Lock()
			endpoints = append(endpoints, ep)
			scanned++
			fmt.Fprintf(os.Stderr, "\r[%d/%d] %-40s %-12s %s",
				scanned, len(targets), ep.Addr, ep.Protocol, shortDetail(&ep))
			mu.Unlock()
		})
	}
	sc.Wait()
	close(done)
	fmt.Fprintln(os.Stderr)

	result := &model.Scan{Meta: meta, Endpoints: endpoints}
	result.Meta.FinishedAt = time.Now()

	st, err := store.New(cfg.Output.Dir)
	if err != nil {
		return err
	}
	scan.SortEndpoints(result.Endpoints)

	var written []string
	for _, f := range cfg.Output.Formats {
		switch f {
		case "json":
			path, err := st.Save(result)
			if err != nil {
				return err
			}
			written = append(written, path)
		case "markdown":
			path := filepath.Join(cfg.Output.Dir, fmt.Sprintf("report-%s.md", result.Meta.StartedAt.Format("20060102-150405")))
			if err := writeFile(path, func(w ioWriter) error { return reportpkg.RenderMarkdown(w, result) }); err != nil {
				return err
			}
			written = append(written, path)
		case "sarif":
			path := filepath.Join(cfg.Output.Dir, fmt.Sprintf("report-%s.sarif", result.Meta.StartedAt.Format("20060102-150405")))
			if err := writeFile(path, func(w ioWriter) error { return reportpkg.RenderSARIF(w, result) }); err != nil {
				return err
			}
			written = append(written, path)
		}
	}

	// Summary to stdout.
	printSummary(result)

	for _, p := range written {
		fmt.Fprintf(os.Stderr, "wrote %s\n", p)
	}

	if cfg.Output.FailOn != "" {
		worst := worstSeverity(result)
		if severityRank(worst) >= severityRank(cfg.Output.FailOn) && worst != "" {
			return fmt.Errorf("findings at severity %q meet -fail-on %q", worst, cfg.Output.FailOn)
		}
	}
	return nil
}

// ioWriter narrows the writer type so the report package's io.Writer method
// set is not needed at call sites.
type ioWriter = interface {
	Write(p []byte) (int, error)
}

func writeFile(path string, render func(ioWriter) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return render(f)
}

func printSummary(s *model.Scan) {
	var grpcN, total, sensitive, exposed, reflection, health int
	for _, ep := range s.Endpoints {
		total++
		if ep.Protocol == model.ProtoGRPC {
			grpcN++
		}
		if ep.Reflection == model.ReflectionV1 || ep.Reflection == model.ReflectionV1Alpha {
			reflection++
		}
		if ep.Health == model.HealthOpen {
			health++
		}
		if len(ep.SensitiveMethods()) > 0 {
			sensitive++
		}
		for _, m := range ep.SensitiveMethods() {
			if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
				exposed++
				break
			}
		}
	}
	fmt.Printf("\ngrpcscope: %d/%d addresses speak gRPC; %d expose reflection; %d have open health; %d carry sensitive methods; %d expose one unauthenticated\n",
		grpcN, total, reflection, health, sensitive, exposed)
}

func probePolicy(cfg *config.Config) string {
	base := "read-only discovery: reflection list, health check, and an encoding-existence oracle that runs no handler code"
	switch cfg.Mode {
	case config.ModeSafe:
		return base
	case config.ModeStandard:
		return base + "; empty requests to read-only-named methods with a known descriptor; no body is ever sent to a method classified mutating or destructive"
	case config.ModeAggressive:
		return base + "; empty requests to any unary method with a known descriptor and no required fields; state-changing methods still never called"
	}
	return base
}

func shortDetail(ep *model.Endpoint) string {
	if ep.Protocol == model.ProtoGRPC {
		n := 0
		for _, s := range ep.Services {
			n += len(s.Methods)
		}
		return fmt.Sprintf("%d svc %d m", len(ep.Services), n)
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePorts(s string) ([]int, error) {
	var out []int
	for _, p := range splitList(s) {
		var n int
		if _, err := fmt.Sscan(p, &n); err != nil {
			return nil, fmt.Errorf("port %q is not numeric", p)
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func worstSeverity(s *model.Scan) string {
	worst := ""
	for _, ep := range s.Endpoints {
		for _, f := range ep.Findings {
			if severityRank(f.Severity) > severityRank(worst) {
				worst = f.Severity
			}
		}
	}
	return worst
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// runDiff compares the two most recent scans in the result directory.
func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	outDir := fs.String("out", "results", "result directory")
	asJSON := fs.Bool("json", false, "emit changes as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.New(*outDir)
	if err != nil {
		return err
	}
	// Latest is the newest; we need the one before it too.
	files, err := listScans(*outDir)
	if err != nil {
		return err
	}
	if len(files) < 2 {
		return fmt.Errorf("diff needs at least two scans in %s; found %d", *outDir, len(files))
	}
	oldScan, err := st.Load(files[len(files)-2])
	if err != nil {
		return err
	}
	newScan, err := st.Load(files[len(files)-1])
	if err != nil {
		return err
	}
	changes := store.Diff(oldScan, newScan)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(changes)
	}
	if len(changes) == 0 {
		fmt.Println("no changes")
		return nil
	}
	for _, c := range changes {
		switch c.Kind {
		case "method-appeared", "method-disappeared", "auth-changed":
			fmt.Printf("%-8s %-20s %-16s %s -> %s %s\n", c.Severity, c.Addr, c.Kind, c.Before, c.After, c.Method)
		default:
			fmt.Printf("%-8s %-20s %-16s %s%s\n", c.Severity, c.Addr, c.Kind, c.Before, c.After)
		}
	}
	return nil
}

func listScans(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "scan-") && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// selftest starts an in-process server that reproduces the incident, scans it,
// and asserts the scanner found the exposed admin methods without calling them.
func selftest() error {
	fmt.Println("grpcscope selftest: starting a vulnerable demo server on loopback")
	srv, err := testserver.New()
	if err != nil {
		return err
	}
	defer srv.Stop()

	cfg := config.Default()
	cfg.Mode = config.ModeSafe
	cfg.Probe.Timeout = 3 * time.Second
	cfg.Probe.ReflectionTimeout = 3 * time.Second
	cfg.Discovery.GuessServices = false
	cfg.Discovery.GuessMethods = false
	cfg.Targets.Addresses = []string{srv.Addr}

	engine, err := scan.NewEngine(cfg, nil, nil, nil, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ep := engine.ScanEndpoint(ctx, srv.Addr)
	fmt.Printf("protocol=%s reflection=%s health=%s services=%d\n", ep.Protocol, ep.Reflection, ep.Health, len(ep.Services))

	var failures []string
	fail := func(format string, a ...any) { failures = append(failures, fmt.Sprintf(format, a...)) }

	if ep.Protocol != model.ProtoGRPC {
		fail("expected protocol grpc, got %s", ep.Protocol)
	}
	if ep.Reflection != model.ReflectionV1 && ep.Reflection != model.ReflectionV1Alpha {
		fail("expected reflection to be detected, got %s", ep.Reflection)
	}

	// The whole point: state-changing methods are identified as exposed but
	// never invoked.
	adminExposed := 0
	for _, m := range ep.SensitiveMethods() {
		if m.Service == "demo.AdminService" {
			switch m.Auth {
			case model.AuthProvenOpen, model.AuthInferredOpen:
				adminExposed++
			}
		}
	}
	if adminExposed < 3 {
		fail("expected at least 3 exposed admin methods, found %d", adminExposed)
	}
	for name, eff := range srv.SideEffects() {
		if eff.Count() > 0 {
			fail("handler %s ran %d time(s); the scanner must not invoke methods", name, eff.Count())
		}
	}
	if n := srv.GlobalEntries().Count(); n > 0 {
		fail("some handler ran %d time(s) during a safe-mode scan", n)
	}

	// Print the inventory for the operator to eyeball.
	for _, svc := range ep.Services {
		fmt.Printf("  %-24s %s\n", svc.Name, svc.Origin)
		for _, m := range svc.Methods {
			fmt.Printf("    %-46s %-14s %-10s %-14s %s\n", m.Name, m.Shape, m.Risk.Level, m.Auth, m.Origin)
		}
	}

	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", f)
		}
		return fmt.Errorf("%d self-check(s) failed", len(failures))
	}
	fmt.Println("selftest passed: admin methods identified as exposed, no handler was invoked")
	return nil
}

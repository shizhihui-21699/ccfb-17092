// Package scan orchestrates a scan of one endpoint: fingerprint, enumerate,
// classify, prove, and record.
//
// # The safety contract
//
// The engine maintains a single invariant: it never sends a request *body*
// that can reach user code unless the operator opted into body probing for
// that specific method, by mode and by the method's risk verdict.
//
//   - ModeSafe: the only requests sent to any endpoint carry no body at all
//     (the encoding oracle, reflection lists, and the health check, which is
//     inert by protocol definition).
//   - ModeStandard: body probes are additionally allowed for (a) poison
//     payloads into unary and server-streaming methods, where the generated
//     handler decodes before calling user code, and (b) empty requests into
//     methods the risk classifier marks read-only.
//   - ModeAggressive: empty requests into any unary method whose descriptor
//     shows no required fields.
//
// In every mode, a method the classifier marks mutating or destructive is
// never sent a body. Its existence and authorization are proven only through
// the oracle and through server-wide evidence, and the report says exactly
// that, rather than pretending a dangerous probe was run.
package scan

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"grpcscope/internal/config"
	"grpcscope/internal/fingerprint"
	"grpcscope/internal/model"
	reflectionpkg "grpcscope/internal/reflection"
	"grpcscope/internal/risk"
	"grpcscope/internal/wire"
)

// Engine holds the shared configuration for a scan run.
type Engine struct {
	Cfg *config.Config
	// Desc is the compiled descriptor registry, possibly empty.
	Desc *protoregistry.Files
	// ServiceWords, MethodWords and Packages are the resolved wordlists.
	ServiceWords []string
	MethodWords  []string
	Packages     []string

	neverCall  []*regexp.Regexp
	neverTouch []*regexp.Regexp
	allowed    []*regexp.Regexp
}

// NewEngine validates the safety regexes once, so a bad pattern fails before
// any packet is sent.
func NewEngine(cfg *config.Config, svcWords, methodWords, packages []string, desc *protoregistry.Files) (*Engine, error) {
	e := &Engine{
		Cfg:          cfg,
		Desc:         desc,
		ServiceWords: svcWords,
		MethodWords:  methodWords,
		Packages:     packages,
	}
	var err error
	if e.neverCall, err = compileAll(cfg.Safety.NeverCall); err != nil {
		return nil, fmt.Errorf("safety.never_call: %w", err)
	}
	if e.neverTouch, err = compileAll(cfg.Safety.NeverTouch); err != nil {
		return nil, fmt.Errorf("safety.never_touch: %w", err)
	}
	if e.allowed, err = compileAll(cfg.Safety.AllowedCall); err != nil {
		return nil, fmt.Errorf("safety.allowed_call: %w", err)
	}
	return e, nil
}

func compileAll(exprs []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, s := range exprs {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// forbidden reports whether the path is excluded outright by never_touch.
func (e *Engine) forbidden(path string) (bool, string) {
	for _, re := range e.neverTouch {
		if re.MatchString(path) {
			return true, "matched never_touch " + re.String()
		}
	}
	return false, ""
}

// bodyForbidden reports whether a request body is excluded. allowed_call can
// re-enable a body probe inside a never_call region (but never inside
// never_touch, which is checked before this).
func (e *Engine) bodyForbidden(path string) (bool, string) {
	for _, re := range e.allowed {
		if re.MatchString(path) {
			return false, ""
		}
	}
	for _, re := range e.neverCall {
		if re.MatchString(path) {
			return true, "matched never_call " + re.String()
		}
	}
	return false, ""
}

// ScanEndpoint probes one address end to end.
func (e *Engine) ScanEndpoint(ctx context.Context, addr string) model.Endpoint {
	start := time.Now()
	ep := model.Endpoint{Addr: addr, ScannedAt: start}
	ep.Host, ep.Port = splitAddr(addr)
	ep.Health = model.HealthAbsent
	ep.Reflection = model.ReflectionAbsent

	fp := fingerprint.Probe(ctx, addr, fingerprint.Options{
		ConnectTimeout: e.Cfg.Probe.ConnectTimeout,
		ScanTimeout:    e.Cfg.Probe.Timeout,
	})
	ep.Protocol = fp.Protocol
	ep.Transport = fp.Transport
	ep.Detail = fp.Detail
	ep.ServerHeader = fp.ServerHeader
	ep.TLSSubject = fp.TLSSubject

	if fp.Protocol != model.ProtoGRPC {
		ep.ScanMS = time.Since(start).Milliseconds()
		ep.ScannedAt = start
		e.deriveFindings(&ep)
		return ep
	}

	conn := fp.Conn
	if conn == nil {
		c, err := fingerprint.DialGRPC(ctx, addr, fp.Transport)
		if err != nil {
			ep.Error = "grpc classified but dial failed: " + err.Error()
			ep.ScanMS = time.Since(start).Milliseconds()
			ep.ScannedAt = start
			return ep
		}
		conn = c
	}
	defer conn.Close()

	if fp.CatchAll {
		ep.AddFinding(model.Finding{
			Kind:       "unknown-service-handler",
			Severity:   "info",
			Summary:    "Server accepts requests for nonexistent services, so enumeration by absence is unreliable here",
			Confidence: model.ConfProven,
		})
	}

	refRes := e.probeReflection(ctx, conn, &ep)
	e.probeHealth(ctx, conn, &ep)

	oc := wire.NewClient(addr, wire.Transport{TLS: fp.Transport == model.TransportTLS,
		ConnectTimeout: e.Cfg.Probe.ConnectTimeout, Timeout: e.Cfg.Probe.Timeout})
	defer oc.Close()

	methods, origins := e.enumerate(ctx, conn, oc, refRes, fp.CatchAll)
	ep.Services = groupByService(methods, origins)

	e.classify(&ep)
	e.judgeAuth(ctx, conn, &ep, fp.CatchAll)
	e.deriveFindings(&ep)

	ep.ScannedAt = start
	ep.ScanMS = time.Since(start).Milliseconds()
	return ep
}

// --- health ---

func (e *Engine) probeHealth(ctx context.Context, conn *grpc.ClientConn, ep *model.Endpoint) {
	if !e.Cfg.Discovery.HealthProbe {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
	defer cancel()

	cli := healthpb.NewHealthClient(conn)
	// An empty service name means "the whole server"; every registered health
	// server answers it, and the Check RPC is inert by protocol definition.
	out, err := cli.Check(cctx, &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		code, msg := grpcStatus(err)
		switch {
		case wire.IsAuthCode(codes.Code(code)) || wire.IsAuthishMessage(msg):
			ep.Health = model.HealthGated
		case codes.Code(code) == codes.Unimplemented: // health not registered
			ep.Health = model.HealthAbsent
		default:
			ep.Health = model.HealthError
		}
		return
	}
	ep.Health = model.HealthOpen
	if s := out.GetStatus(); s != healthpb.HealthCheckResponse_SERVING {
		ep.Detail = strings.TrimSpace(ep.Detail + "; health=" + s.String())
	}
}

// --- reflection ---

func (e *Engine) probeReflection(ctx context.Context, conn *grpc.ClientConn, ep *model.Endpoint) *reflectionpkg.Result {
	if !e.Cfg.Discovery.ReflectionProbe {
		return nil
	}
	res := reflectionpkg.Enumerate(ctx, conn, e.Cfg.Probe.ReflectionTimeout)
	switch {
	case res.Gated:
		ep.Reflection = model.ReflectionGated
		return &res
	case res.Absent:
		ep.Reflection = model.ReflectionAbsent
		return &res
	case res.Err != nil && len(res.Services) == 0:
		ep.Reflection = model.ReflectionError
		return &res
	}
	if res.Version == reflectionpkg.V1 {
		ep.Reflection = model.ReflectionV1
	} else {
		ep.Reflection = model.ReflectionV1Alpha
	}
	if len(res.Services) > 0 {
		ep.AddFinding(model.Finding{
			Kind:       "reflection-exposed",
			Severity:   "medium",
			Summary:    "Server reflection answers without credentials, exposing the full method inventory to anyone who can reach the port",
			Evidence:   []string{fmt.Sprintf("%d service(s) listed over reflection %s", len(res.Services), res.Version)},
			Confidence: model.ConfProven,
		})
	}
	return &res
}

// --- enumeration ---

func (e *Engine) enumerate(ctx context.Context, conn *grpc.ClientConn, oc *wire.Client, refRes *reflectionpkg.Result, catchAll bool) ([]model.Method, map[string]model.Confidence) {
	origins := map[string]model.Confidence{}
	var methods []model.Method

	recordOrigin := func(svc string, c model.Confidence) {
		if prev, ok := origins[svc]; !ok || rank(c) > rank(prev) {
			origins[svc] = c
		}
	}

	// 1. Reflection: exact.
	if refRes != nil && len(refRes.Services) > 0 {
		var sdList []protoreflect.ServiceDescriptor
		reg, err := refRes.BuildRegistry()
		if err == nil {
			sdList = reflectionpkg.ServiceDescriptors(reg)
		}
		for _, svc := range refRes.Services {
			if reflectionpkg.IsReflectionService(svc) {
				continue
			}
			recordOrigin(svc, model.ConfExact)
		}
		for _, sd := range sdList {
			ms := e.methodsFromService(sd, model.ConfExact)
			methods = append(methods, ms...)
			if len(ms) > 0 {
				recordOrigin(ms[0].Service, model.ConfExact)
			}
		}
		// Services reflection named but whose descriptors we could not link
		// still deserve oracle probing so their methods can be found.
		for _, svc := range refRes.Services {
			if reflectionpkg.IsReflectionService(svc) {
				continue
			}
			if !hasService(methods, svc) {
				methods = append(methods, model.Method{
					FullName: svc, Service: svc, Shape: model.ShapeUnknown,
					Origin: model.ConfExact, Exists: true,
					Risk: risk.Classify(svc, "", nil),
				})
			}
		}
	}

	// 2. Operator-supplied descriptors.
	if e.Desc != nil {
		for _, sd := range ServicesFromRegistry(e.Desc) {
			ms := e.methodsFromService(sd, model.ConfExact)
			methods = append(methods, ms...)
			if len(ms) > 0 {
				recordOrigin(ms[0].Service, model.ConfExact)
			}
		}
	}

	// 3. Service guessing for servers without reflection.
	if e.Cfg.Discovery.GuessServices && !catchAll {
		for _, svc := range e.guessServices(ctx, oc, origins) {
			recordOrigin(svc, model.ConfGuessed)
		}
	}

	// 4. Method guessing against services that have no exact inventory.
	if e.Cfg.Discovery.GuessMethods && !catchAll {
		for svc, origin := range origins {
			if origin == model.ConfExact && hasService(methods, svc) {
				// Already enumerated from a descriptor or reflection.
				continue
			}
			methods = append(methods, e.guessMethods(ctx, oc, svc)...)
		}
	}

	// 5. Confirm with the oracle, so nothing unproven is reported present.
	if e.Cfg.Probe.ConfirmWithOracle && !catchAll {
		methods = e.confirmMethods(ctx, oc, methods)
	}

	// De-duplicate by full name (guessing and descriptors can overlap).
	methods = dedupeMethods(methods)

	// never_touch is absolute: no method under such a pattern is reported,
	// regardless of where it came from. This is the last word, applied after
	// every source, so reflection and descriptors cannot leak a path the
	// operator vetoed.
	methods = e.filterNeverTouch(methods, origins)
	return methods, origins
}

func hasService(methods []model.Method, svc string) bool {
	for _, m := range methods {
		if m.Service == svc && m.Name != "" {
			return true
		}
	}
	return false
}

func (e *Engine) methodsFromService(sd protoreflect.ServiceDescriptor, origin model.Confidence) []model.Method {
	ms := sd.Methods()
	n := ms.Len()
	if e.Cfg.Probe.MaxMethodsPerService > 0 && n > e.Cfg.Probe.MaxMethodsPerService {
		n = e.Cfg.Probe.MaxMethodsPerService
	}
	out := make([]model.Method, 0, n)
	for i := 0; i < n; i++ {
		m := ms.Get(i)
		shape := shapeOf(m)
		v := model.Method{
			FullName: "/" + string(sd.FullName()) + "/" + string(m.Name()),
			Service:  string(sd.FullName()),
			Name:     string(m.Name()),
			Shape:    shape,
			Input:    string(m.Input().FullName()),
			Output:   string(m.Output().FullName()),
			Origin:   origin,
			Exists:   true,
		}
		v.InputFields = fieldsOf(m.Input())
		v.Risk = risk.Classify(v.Service, v.Name, v.InputFields)
		out = append(out, v)
	}
	return out
}

func shapeOf(m protoreflect.MethodDescriptor) model.Shape {
	switch cs, ss := m.IsStreamingClient(), m.IsStreamingServer(); {
	case cs && ss:
		return model.ShapeBidi
	case cs:
		return model.ShapeClientStream
	case ss:
		return model.ShapeServerStream
	default:
		return model.ShapeUnary
	}
}

func fieldsOf(md protoreflect.MessageDescriptor) []model.FieldInfo {
	if md == nil {
		return nil
	}
	fs := md.Fields()
	out := make([]model.FieldInfo, 0, fs.Len())
	for i := 0; i < fs.Len(); i++ {
		f := fs.Get(i)
		out = append(out, model.FieldInfo{
			Name:     string(f.Name()),
			Number:   int32(f.Number()),
			Type:     f.Kind().String(),
			Repeated: f.IsList() || f.IsMap(),
		})
	}
	return out
}

// guessServices probes the service wordlist across package prefixes using the
// oracle. Only a "method-missing" reply proves the service exists, and nothing
// enters the inventory unproven.
func (e *Engine) guessServices(ctx context.Context, oc *wire.Client, known map[string]model.Confidence) []string {
	candidates := e.serviceCandidates()
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.Cfg.Probe.Concurrency)
	stop := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(found) >= e.Cfg.Discovery.MaxGuessServices
	}
	for _, svc := range candidates {
		if stop() {
			break
		}
		if forbid, _ := e.forbidden("/" + svc + "/"); forbid {
			continue
		}
		svc := svc
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
			defer cancel()
			// "unknown method" for this placeholder proves the *service* is
			// registered; a nonexistent service would answer "unknown service".
			res := oc.Oracle(cctx, "/"+svc+"/"+probeMethodName)
			if res.Existence != wire.MethodMissing {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if _, ok := known[svc]; ok {
				return
			}
			if len(found) >= e.Cfg.Discovery.MaxGuessServices {
				return
			}
			found = append(found, svc)
		}()
	}
	wg.Wait()
	sort.Strings(found)
	return found
}

// probeMethodName is a method name no real service registers, used so that a
// service-existence probe cannot accidentally match a real method.
const probeMethodName = "__grpcscope_probe__"

func (e *Engine) serviceCandidates() []string {
	pkgs := e.Packages
	if len(pkgs) == 0 {
		pkgs = []string{""}
	}
	var out []string
	for _, pkg := range pkgs {
		for _, svc := range e.ServiceWords {
			if pkg == "" {
				out = append(out, svc)
			} else {
				out = append(out, pkg+"."+svc)
			}
		}
	}
	return out
}

func (e *Engine) guessMethods(ctx context.Context, oc *wire.Client, svc string) []model.Method {
	var out []model.Method
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.Cfg.Probe.Concurrency)
	for i, name := range e.MethodWords {
		if i >= e.Cfg.Discovery.MaxGuessMethodsPerService {
			break
		}
		path := "/" + svc + "/" + name
		if forbid, _ := e.forbidden(path); forbid {
			continue
		}
		name, path := name, path
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
			defer cancel()
			res := oc.Oracle(cctx, path)
			if res.Existence != wire.MethodExists {
				return
			}
			mu.Lock()
			out = append(out, model.Method{
				FullName: path,
				Service:  svc,
				Name:     name,
				Shape:    model.ShapeUnknown,
				Origin:   model.ConfGuessed,
				Exists:   true,
				ProvenBy: model.ProbeEncodingOracle,
				Risk:     risk.Classify(svc, name, nil),
				Probes:   []model.ProbeRecord{probeRecord(model.ProbeEncodingOracle, res)},
			})
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// confirmMethods re-probes descriptor-derived methods with the oracle. Methods
// the server denies are dropped; the report lists only real surface.
func (e *Engine) confirmMethods(ctx context.Context, oc *wire.Client, methods []model.Method) []model.Method {
	if len(methods) == 0 {
		return methods
	}
	out := make([]model.Method, 0, len(methods))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.Cfg.Probe.Concurrency)

	for _, m := range methods {
		m := m
		if m.Name == "" {
			// Placeholder service entry from reflection without descriptors.
			out = append(out, m)
			continue
		}
		if forbid, _ := e.forbidden(m.FullName); forbid {
			// never_touch: the path must not be probed at all, even by the
			// oracle. A method we did not touch is not reported as present, so
			// it is dropped from the inventory rather than asserted from a
			// descriptor we could not verify.
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
			defer cancel()
			res := oc.Oracle(cctx, m.FullName)
			switch res.Existence {
			case wire.MethodExists:
				m.Exists = true
				m.ProvenBy = model.ProbeEncodingOracle
				m.Probes = append(m.Probes, probeRecord(model.ProbeEncodingOracle, res))
			case wire.MethodMissing, wire.ServiceMissing:
				return // wire contradicts the descriptor; drop the entry
			default:
				// Inconclusive (catch-all handler, timeout, or an auth wrapper
				// that answers before the decoder). Keep it but unproven.
				m.Exists = false
				m.Probes = append(m.Probes, probeRecord(model.ProbeEncodingOracle, res))
			}
			mu.Lock()
			out = append(out, m)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func dedupeMethods(methods []model.Method) []model.Method {
	seen := map[string]int{}
	var out []model.Method
	for _, m := range methods {
		key := m.FullName
		if m.Name == "" {
			// placeholder keyed by service, so it never shadows a real service
			key = "svc:" + m.Service
		}
		if idx, ok := seen[key]; ok {
			// Prefer the higher-origin record, but keep proven evidence.
			if rank(m.Origin) > rank(out[idx].Origin) {
				out[idx].Origin = m.Origin
			}
			if m.Exists && len(out[idx].Probes) == 0 {
				out[idx].Probes = m.Probes
				out[idx].ProvenBy = m.ProvenBy
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, m)
	}
	return out
}

func groupByService(methods []model.Method, origins map[string]model.Confidence) []model.Service {
	byName := map[string]*model.Service{}
	for _, m := range methods {
		svc, ok := byName[m.Service]
		if !ok {
			origin := origins[m.Service]
			if origin == "" {
				origin = m.Origin
			}
			svc = &model.Service{Name: m.Service, Origin: origin}
			svc.Adminish = risk.ServiceRisk(m.Service).Adminish
			byName[m.Service] = svc
		}
		svc.Methods = append(svc.Methods, m)
	}
	out := make([]model.Service, 0, len(byName))
	for _, s := range byName {
		sort.Slice(s.Methods, func(i, j int) bool { return s.Methods[i].FullName < s.Methods[j].FullName })
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (e *Engine) classify(ep *model.Endpoint) {
	for si := range ep.Services {
		for mi := range ep.Services[si].Methods {
			m := &ep.Services[si].Methods[mi]
			if m.Risk.Level == "" || m.Risk.Level == model.RiskUnknown {
				m.Risk = risk.Classify(m.Service, m.Name, m.InputFields)
			}
		}
	}
}

func rank(c model.Confidence) int {
	switch c {
	case model.ConfExact:
		return 3
	case model.ConfProven:
		return 2
	case model.ConfInferred:
		return 1
	}
	return 0
}

func splitAddr(addr string) (string, int) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, 0
	}
	port := 0
	fmt.Sscan(addr[i+1:], &port)
	return addr[:i], port
}

func grpcStatus(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	st, ok := status.FromError(err)
	if !ok {
		return int(codes.Unknown), err.Error()
	}
	return int(st.Code()), st.Message()
}

// filterNeverTouch removes any method whose path or service matches
// never_touch, and forgets the service origin so an empty service is not
// emitted.
func (e *Engine) filterNeverTouch(methods []model.Method, origins map[string]model.Confidence) []model.Method {
	if len(e.neverTouch) == 0 {
		return methods
	}
	kept := methods[:0]
	for _, m := range methods {
		if forbid, _ := e.forbidden(m.FullName); forbid {
			continue
		}
		if forbid, _ := e.forbidden("/" + m.Service + "/"); forbid {
			continue
		}
		kept = append(kept, m)
	}
	// Drop service origins that no longer have any method, so a fully vetoed
	// service does not appear as an empty entry.
	present := map[string]bool{}
	for _, m := range kept {
		present[m.Service] = true
	}
	for svc := range origins {
		if !present[svc] {
			delete(origins, svc)
		}
	}
	return kept
}

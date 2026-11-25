package scan

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"grpcscope/internal/model"
	"grpcscope/internal/risk"
	"grpcscope/internal/wire"
)

// judgeAuth assigns an authorization verdict to every method.
//
// The evidence hierarchy, strongest first:
//
//  1. An inert call that succeeded without credentials proves that method open.
//     Only calls whose *whole purpose* is inert qualify: the health check on
//     its own service, and a read-only-named method sent an empty request in
//     modes that permit it.
//  2. An inert call rejected with an auth code proves that method, or a
//     server-wide interceptor in front of it, is gated.
//  3. The health service answering without credentials shows that no global
//     unary interceptor exists. Combined with a co-located method, that is
//     strong evidence the method is also open — labelled "inferred", not
//     "proven".
//  4. Nothing else. A method with no inert evidence gets "unknown", never a
//     guess dressed as a verdict.
//
// A mutating or destructive method is never called, so its evidence can never
// rise above "inferred".
func (e *Engine) judgeAuth(ctx context.Context, conn *grpc.ClientConn, ep *model.Endpoint, catchAll bool) {
	// The server-wide unary baseline comes from the most inert call there is:
	// a health check for the whole server.
	serverUnary := model.AuthUnknown
	switch ep.Health {
	case model.HealthOpen:
		serverUnary = model.AuthProvenOpen
	case model.HealthGated:
		serverUnary = model.AuthProvenGated
	}
	ep.ServerWideUnaryAuth = serverUnary

	for si := range ep.Services {
		for mi := range ep.Services[si].Methods {
			m := &ep.Services[si].Methods[mi]
			e.judgeOne(ctx, conn, m, serverUnary, catchAll)
		}
	}
}

func (e *Engine) judgeOne(ctx context.Context, conn *grpc.ClientConn, m *model.Method, serverUnary model.AuthState, catchAll bool) {
	// A sensitive method is never sent a body, so its verdict cannot be
	// stronger than the server-wide inference.
	//
	// BodyProbeSafe is stricter than the method's own risk verdict: it also
	// refuses when the method lives on an administrative service, whose
	// read-only-sounding verbs (WatchAdmin, GetConfig) still warrant caution.
	if !isBodySafeByRisk(m.Risk.Level) || !risk.BodyProbeSafe(m.Service, m.Name) {
		m.Auth = inferFromServer(serverUnary)
		if m.Auth == model.AuthInferredOpen {
			m.Risk.Reasons = append(m.Risk.Reasons,
				"authorization inferred from an unauthenticated health check; not called directly because it is state-changing or on an administrative service")
		}
		return
	}

	if !e.Cfg.BodyProbingAllowed() {
		m.Auth = inferFromServer(serverUnary)
		return
	}
	if forbid, _ := e.bodyForbidden(m.FullName); forbid {
		m.Auth = inferFromServer(serverUnary)
		return
	}
	if catchAll {
		// An unknown-service handler makes every path look implemented, so an OK
		// reply cannot distinguish "handler ran" from "catch-all shrugged".
		m.Auth = model.AuthUnknown
		return
	}
	// A known message shape is required to build a request valid without data.
	// Guessed names have no descriptor; the origin check keeps them out.
	if m.Origin == model.ConfGuessed || m.Shape == model.ShapeUnknown {
		m.Auth = model.AuthUnknown
		return
	}
	if e.hasRequired(m.Input) {
		m.Auth = model.AuthUnknown
		return
	}

	switch m.Shape {
	case model.ShapeUnary:
		in, out, ok := e.messagesFor(m)
		if !ok {
			m.Auth = model.AuthUnknown
			return
		}
		cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
		start := time.Now()
		err := conn.Invoke(cctx, m.FullName, in, out)
		cancel()
		m.Probes = append(m.Probes, model.ProbeRecord{
			Kind: model.ProbeEmptyReadCall, Code: codeOf(err), Message: msgOf(err),
			DurationMS: time.Since(start).Milliseconds(), At: time.Now(),
		})
		m.Auth = authFromErr(err)
	case model.ShapeServerStream:
		in, _, ok := e.messagesFor(m)
		if !ok {
			m.Auth = model.AuthUnknown
			return
		}
		cctx, cancel := context.WithTimeout(ctx, e.Cfg.Probe.Timeout)
		start := time.Now()
		err := invokeServerStream(cctx, conn, m.FullName, in)
		cancel()
		m.Probes = append(m.Probes, model.ProbeRecord{
			Kind: model.ProbeEmptyReadCall, Code: codeOf(err), Message: msgOf(err),
			DurationMS: time.Since(start).Milliseconds(), At: time.Now(),
		})
		m.Auth = authFromErr(err)
	default:
		// Client-streaming and bidi: generated handlers call user code before
		// decoding the first message, so no body is ever sent. Fall back to the
		// server-wide view.
		m.Auth = inferFromServer(serverUnary)
	}
}

func inferFromServer(serverUnary model.AuthState) model.AuthState {
	switch serverUnary {
	case model.AuthProvenOpen:
		return model.AuthInferredOpen
	case model.AuthProvenGated:
		return model.AuthInferredGated
	default:
		return model.AuthUnknown
	}
}

// isBodySafeByRisk reports whether a body may be sent to a method of this risk
// level. Only read-only names qualify, and only in modes that permit it.
func isBodySafeByRisk(r model.SideEffectRisk) bool {
	return r == model.RiskReadOnly
}

// messagesFor resolves the input and output message descriptors to dynamic
// messages.
func (e *Engine) messagesFor(m *model.Method) (in, out protoreflect.Message, ok bool) {
	if e.Desc == nil {
		return nil, nil, false
	}
	id, ok1 := findMessage(e.Desc, m.Input)
	if !ok1 {
		return nil, nil, false
	}
	od, ok2 := findMessage(e.Desc, m.Output)
	if !ok2 {
		return nil, nil, false
	}
	return dynamicpb.NewMessage(id), dynamicpb.NewMessage(od), true
}

func findMessage(files *protoregistry.Files, name string) (protoreflect.MessageDescriptor, bool) {
	if files == nil || name == "" {
		return nil, false
	}
	d, err := files.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, false
	}
	md, ok := d.(protoreflect.MessageDescriptor)
	return md, ok
}

// hasRequired reports whether the input message declares a proto2 required
// field. Proto3 has none by definition. When the descriptor cannot be read, the
// safe answer is "yes", so the caller declines to send an empty request.
func (e *Engine) hasRequired(input string) bool {
	if e.Desc == nil {
		return true
	}
	md, ok := findMessage(e.Desc, input)
	if !ok {
		return true
	}
	fs := md.Fields()
	for i := 0; i < fs.Len(); i++ {
		if fs.Get(i).Cardinality() == protoreflect.Required {
			return true
		}
	}
	return false
}

func invokeServerStream(ctx context.Context, conn *grpc.ClientConn, path string, in protoreflect.Message) error {
	sd := &grpc.StreamDesc{StreamName: path, ServerStreams: true}
	stream, err := conn.NewStream(ctx, sd, path)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(in); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	// One receive is enough: by this point the server has entered the handler,
	// which is what a read-only call is for. A stream that yields no message
	// and ends with io.EOF is a success.
	return stream.RecvMsg(dynamicEmpty())
}

func codeOf(err error) string {
	if err == nil {
		return "OK"
	}
	st, ok := status.FromError(err)
	if !ok {
		return "Unknown"
	}
	return st.Code().String()
}

func msgOf(err error) string {
	if err == nil {
		return ""
	}
	st, ok := status.FromError(err)
	if !ok {
		return err.Error()
	}
	return st.Message()
}

func authFromErr(err error) model.AuthState {
	if err == nil {
		return model.AuthProvenOpen
	}
	code, msg := codeOf(err), msgOf(err)
	if wire.IsAuthCode(codes.Code(codeFromString(code))) || wire.IsAuthishMessage(msg) {
		return model.AuthProvenGated
	}
	return model.AuthUnknown
}

func statusCode(err error) (string, string) { return codeOf(err), msgOf(err) }

func codeFromString(s string) int {
	if c, ok := codesNameToCode[s]; ok {
		return int(c)
	}
	return int(codes.Unknown)
}

var codesNameToCode = map[string]codes.Code{
	"OK": codes.OK, "Canceled": codes.Canceled, "Unknown": codes.Unknown,
	"InvalidArgument": codes.InvalidArgument, "DeadlineExceeded": codes.DeadlineExceeded,
	"NotFound": codes.NotFound, "AlreadyExists": codes.AlreadyExists,
	"PermissionDenied": codes.PermissionDenied, "ResourceExhausted": codes.ResourceExhausted,
	"FailedPrecondition": codes.FailedPrecondition, "Aborted": codes.Aborted,
	"OutOfRange": codes.OutOfRange, "Unimplemented": codes.Unimplemented,
	"Internal": codes.Internal, "Unavailable": codes.Unavailable,
	"DataLoss": codes.DataLoss, "Unauthenticated": codes.Unauthenticated,
}

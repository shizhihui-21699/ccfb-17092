// Package testserver builds in-process gRPC servers that reproduce the
// situation the scanner exists for: business and management methods on one
// port, reflection enabled, no method-level authorization, and a couple of
// variants (auth interceptor, no reflection) so tests can prove the scanner
// tells them apart.
//
// It is used by the unit tests and by `grpcscope selftest`.
package testserver

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// SideEffect is a counter of how many times a state-changing method ran. Tests
// assert it stays at zero for methods the scanner must not call.
type SideEffect struct {
	name  string
	count atomic.Int64
}

// Count returns how many times the handler ran.
func (s *SideEffect) Count() int64 { return s.count.Load() }

// Descriptor is the schema shared by the generated service and by the
// descriptor file the scanner can be given.
func Descriptor() protoreflect.FileDescriptor {
	s := func(x string) *string { return &x }
	i32 := func(x int32) *int32 { return &x }
	b := func(x bool) *bool { return &x }
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    s("demoproto/demo.proto"),
		Package: s("demo"),
		Syntax:  s("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: s("Empty")},
			{
				Name: s("KeyRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: s("key"), Number: i32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: s("key")},
				},
			},
			{
				Name: s("StatusReply"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: s("value"), Number: i32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: s("value")},
				},
			},
			{
				Name: s("FlushRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: s("force"), Number: i32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: s("force")},
				},
			},
			{
				Name: s("ConfigRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: s("key"), Number: i32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: s("key")},
					{Name: s("value"), Number: i32(2), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: s("value")},
				},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: s("AdminService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{Name: s("FlushCache"), InputType: s(".demo.FlushRequest"), OutputType: s(".demo.StatusReply")},
					{Name: s("UpdateConfig"), InputType: s(".demo.ConfigRequest"), OutputType: s(".demo.StatusReply")},
					{Name: s("GetStatus"), InputType: s(".demo.Empty"), OutputType: s(".demo.StatusReply")},
					{Name: s("GetConfig"), InputType: s(".demo.KeyRequest"), OutputType: s(".demo.StatusReply")},
					{Name: s("PurgeAll"), InputType: s(".demo.Empty"), OutputType: s(".demo.StatusReply")},
					{Name: s("WatchAdmin"), InputType: s(".demo.Empty"), OutputType: s(".demo.StatusReply"), ServerStreaming: b(true)},
					{Name: s("BulkImport"), InputType: s(".demo.ConfigRequest"), OutputType: s(".demo.StatusReply"), ClientStreaming: b(true)},
				},
			},
			{
				Name: s("BizService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{Name: s("GetUser"), InputType: s(".demo.KeyRequest"), OutputType: s(".demo.StatusReply")},
					{Name: s("ListUsers"), InputType: s(".demo.Empty"), OutputType: s(".demo.StatusReply")},
					{Name: s("CreateUser"), InputType: s(".demo.ConfigRequest"), OutputType: s(".demo.StatusReply")},
				},
			},
		},
	}
	f, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		panic(err)
	}
	// Generated protoc-gen-go code registers its file in the global registry
	// during init(). The reflection service serves descriptors from that
	// registry, so a test server that omits this step would appear to have no
	// service descriptors at all — a realistic failure mode, but not the one
	// these tests are about.
	if _, err := protoregistry.GlobalFiles.FindFileByPath(fdp.GetName()); err != nil {
		if err := protoregistry.GlobalFiles.RegisterFile(f); err != nil {
			// Concurrent registration by another test is benign.
			_ = err
		}
	}
	return f
}

// FileDescriptorProto returns the raw descriptor, as a .proto compile or a
// descriptor-set file would produce.
func FileDescriptorProto() *descriptorpb.FileDescriptorProto {
	return protodesc.ToFileDescriptorProto(Descriptor())
}

// Server is a running test server.
type Server struct {
	Addr string

	srv    *grpc.Server
	lis    net.Listener
	side   map[string]*SideEffect
	global *SideEffect // counts any handler entry, for safety assertions
}

// SideEffects returns the per-method counters.
func (s *Server) SideEffects() map[string]*SideEffect { return s.side }

// GlobalEntries returns how many times any handler ran.
func (s *Server) GlobalEntries() *SideEffect { return s.global }

// Option configures the server variant.
type Option func(*serverConfig)

type serverConfig struct {
	reflection bool
	unaryAuth  bool
	streamAuth bool
	health     bool
	authHeader string
}

// WithoutReflection turns reflection off, to exercise the guessing path.
func WithoutReflection() Option { return func(c *serverConfig) { c.reflection = false } }

// WithUnaryAuth installs a unary interceptor that requires a metadata header.
func WithUnaryAuth() Option { return func(c *serverConfig) { c.unaryAuth = true } }

// WithStreamAuth installs a stream interceptor that requires the same header.
func WithStreamAuth() Option { return func(c *serverConfig) { c.streamAuth = true } }

// WithHealth registers the standard health service.
func WithHealth() Option { return func(c *serverConfig) { c.health = true } }

// New starts a server on a loopback port.
func New(opts ...Option) (*Server, error) {
	cfg := serverConfig{reflection: true, health: true, authHeader: "authorization"}
	for _, o := range opts {
		o(&cfg)
	}

	f := Descriptor()
	svcAdmin := f.Services().ByName("AdminService")
	svcBiz := f.Services().ByName("BizService")

	s := &Server{
		side:   map[string]*SideEffect{},
		global: &SideEffect{name: "global"},
	}

	unaryHandler := func(svc protoreflect.ServiceDescriptor, method string) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
		md := svc.Methods().ByName(protoreflect.Name(method))
		effect := &SideEffect{name: string(svc.FullName()) + "/" + method}
		s.side[string(svc.FullName())+"/"+method] = effect
		return func(_ any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
			in := dynamicpb.NewMessage(md.Input())
			if err := dec(in); err != nil {
				return nil, err
			}
			call := func(ctx context.Context, _ any) (any, error) {
				s.global.count.Add(1)
				effect.count.Add(1)
				out := dynamicpb.NewMessage(md.Output())
				out.Set(md.Output().Fields().ByName("value"), protoreflect.ValueOfString("ok"))
				return out, nil
			}
			if ic == nil {
				return call(ctx, in)
			}
			return ic(ctx, in, &grpc.UnaryServerInfo{FullMethod: "/" + string(svc.FullName()) + "/" + method}, call)
		}
	}

	streamHandler := func(svc protoreflect.ServiceDescriptor, method string) func(any, grpc.ServerStream) error {
		md := svc.Methods().ByName(protoreflect.Name(method))
		effect := &SideEffect{name: string(svc.FullName()) + "/" + method}
		s.side[string(svc.FullName())+"/"+method] = effect
		return func(_ any, st grpc.ServerStream) error {
			s.global.count.Add(1)
			effect.count.Add(1)
			if md.IsStreamingServer() && !md.IsStreamingClient() {
				// Generated server-streaming handlers decode first.
				in := dynamicpb.NewMessage(md.Input())
				if err := st.RecvMsg(in); err != nil {
					return err
				}
				return st.SendMsg(dynamicpb.NewMessage(md.Output()))
			}
			// Client-streaming: generated code calls into user code first.
			in := dynamicpb.NewMessage(md.Input())
			for {
				if err := st.RecvMsg(in); err != nil {
					break
				}
			}
			return st.SendMsg(dynamicpb.NewMessage(md.Output()))
		}
	}

	adminDesc := &grpc.ServiceDesc{
		ServiceName: string(svcAdmin.FullName()),
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "FlushCache", Handler: unaryHandler(svcAdmin, "FlushCache")},
			{MethodName: "UpdateConfig", Handler: unaryHandler(svcAdmin, "UpdateConfig")},
			{MethodName: "GetStatus", Handler: unaryHandler(svcAdmin, "GetStatus")},
			{MethodName: "GetConfig", Handler: unaryHandler(svcAdmin, "GetConfig")},
			{MethodName: "PurgeAll", Handler: unaryHandler(svcAdmin, "PurgeAll")},
		},
		Streams: []grpc.StreamDesc{
			{StreamName: "WatchAdmin", ServerStreams: true, Handler: streamHandler(svcAdmin, "WatchAdmin")},
			{StreamName: "BulkImport", ClientStreams: true, Handler: streamHandler(svcAdmin, "BulkImport")},
		},
		Metadata: "demoproto/demo.proto",
	}
	bizDesc := &grpc.ServiceDesc{
		ServiceName: string(svcBiz.FullName()),
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "GetUser", Handler: unaryHandler(svcBiz, "GetUser")},
			{MethodName: "ListUsers", Handler: unaryHandler(svcBiz, "ListUsers")},
			{MethodName: "CreateUser", Handler: unaryHandler(svcBiz, "CreateUser")},
		},
		Metadata: "demoproto/demo.proto",
	}

	optsG := []grpc.ServerOption{}
	if cfg.unaryAuth {
		optsG = append(optsG, grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			if len(md.Get(cfg.authHeader)) == 0 {
				return nil, status.Error(codes.Unauthenticated, "missing credentials")
			}
			return h(ctx, req)
		}))
	}
	if cfg.streamAuth {
		optsG = append(optsG, grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			md, _ := metadata.FromIncomingContext(ss.Context())
			if len(md.Get(cfg.authHeader)) == 0 {
				return status.Error(codes.Unauthenticated, "missing credentials")
			}
			return h(srv, ss)
		}))
	}

	srv := grpc.NewServer(optsG...)
	srv.RegisterService(adminDesc, struct{}{})
	srv.RegisterService(bizDesc, struct{}{})
	if cfg.health {
		hs := health.NewServer()
		hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(srv, hs)
	}
	if cfg.reflection {
		reflection.Register(srv)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.srv = srv
	s.lis = lis
	s.Addr = lis.Addr().String()
	go srv.Serve(lis)
	time.Sleep(80 * time.Millisecond)
	return s, nil
}

// Stop shuts the server down.
func (s *Server) Stop() {
	if s.srv != nil {
		s.srv.Stop()
	}
}

// AllEffects returns a summary string for test failure messages.
func (s *Server) AllEffects() string {
	var b []byte
	b = fmt.Appendf(b, "global=%d", s.global.Count())
	for name, e := range s.side {
		b = fmt.Appendf(b, " %s=%d", name, e.Count())
	}
	return string(b)
}

// EmptyMessage returns a dynamic empty message for the schema, for tests that
// need a valid empty request.
func EmptyMessage() *dynamicpb.Message {
	f := Descriptor()
	return dynamicpb.NewMessage(f.Messages().ByName("Empty"))
}

var _ = proto.Bool

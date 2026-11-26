// Package harness 提供端到端测试用的内存靶场：在随机本地端口上启动一个
// 同时包含"裸奔管理服务 + 受保护业务服务 + 反射"的 gRPC server，
// 以及一个 HTTP 管理面。测试用它验证探测结论与零副作用保证。
package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	// PkgName 是靶场 proto 包名。
	PkgName      = "testcorp.v1"
	BizService   = PkgName + ".BizService"
	AdminService = PkgName + ".AdminService"
)

// Harness 是已启动的靶场。
type Harness struct {
	GRPCAddr   string // host:port
	HTTPAddr   string
	FlushCount *atomic.Int64
	grpcServer *grpc.Server
	httpServer *http.Server
	listener   net.Listener
}

// Start 在随机端口启动靶场，返回前服务已可接受连接。
func Start() (*Harness, error) {
	fdProto := buildFileDescriptor()
	fileDesc, err := buildFile(fdProto)
	if err != nil {
		return nil, err
	}
	msgDesc := fileDesc.Messages().ByName("Empty")

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	var flushCount atomic.Int64
	srv := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(&flushCount)))
	registerServices(srv, fileDesc, msgDesc, &flushCount)
	reflection.Register(srv)

	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)

	go func() { _ = srv.Serve(lis) }()

	httpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Stop()
		_ = lis.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	// 显式挂载 pprof 只读端点（不使用全局 DefaultServeMux，避免多实例冲突）
	mux.HandleFunc("/debug/pprof/", pprofIndex)
	mux.HandleFunc("/debug/pprof/cmdline", pprofCmdline)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "rpc_requests_total 12345")
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(httpLis) }()

	return &Harness{
		GRPCAddr:   lis.Addr().String(),
		HTTPAddr:   httpLis.Addr().String(),
		FlushCount: &flushCount,
		grpcServer: srv,
		httpServer: httpSrv,
		listener:   lis,
	}, nil
}

// Stop 关闭靶场。
func (h *Harness) Stop() {
	h.grpcServer.Stop()
	_ = h.httpServer.Shutdown(context.Background())
}

func buildFileDescriptor() *descriptorpb.FileDescriptorProto {
	empty := &descriptorpb.DescriptorProto{Name: proto.String("Empty")}
	return &descriptorpb.FileDescriptorProto{
		Name:        proto.String("testcorp/v1/test.proto"),
		Package:     proto.String(PkgName),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{empty},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("BizService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					method("GetData"),
				},
			},
			{
				Name: proto.String("AdminService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					method("FlushAll"),
					method("UpdateConfig"),
					method("Debug"),
				},
			},
		},
	}
}

func method(name string) *descriptorpb.MethodDescriptorProto {
	return &descriptorpb.MethodDescriptorProto{
		Name:       proto.String(name),
		InputType:  proto.String("." + PkgName + ".Empty"),
		OutputType: proto.String("." + PkgName + ".Empty"),
	}
}

func buildFile(fdProto *descriptorpb.FileDescriptorProto) (protoreflect.FileDescriptor, error) {
	if existing, err := protoregistry.GlobalFiles.FindFileByPath(fdProto.GetName()); err == nil {
		return existing, nil
	}
	desc, err := protodesc.NewFile(fdProto, nil)
	if err != nil {
		return nil, err
	}
	if err := protoregistry.GlobalFiles.RegisterFile(desc); err != nil {
		// 已注册可忽略，返回当前实例
		if existing, e2 := protoregistry.GlobalFiles.FindFileByPath(fdProto.GetName()); e2 == nil {
			return existing, nil
		}
		return nil, err
	}
	return desc, nil
}

func registerServices(srv *grpc.Server, fileDesc protoreflect.FileDescriptor,
	msgDesc protoreflect.MessageDescriptor, flushCount *atomic.Int64) {

	for i := 0; i < fileDesc.Services().Len(); i++ {
		sd := fileDesc.Services().Get(i)
		serviceName := string(sd.FullName())
		svcDesc := &grpc.ServiceDesc{
			ServiceName: serviceName,
			HandlerType: (*any)(nil),
		}
		for j := 0; j < sd.Methods().Len(); j++ {
			md := sd.Methods().Get(j)
			methodName := string(md.Name())
			fullMethod := "/" + serviceName + "/" + methodName
			svcDesc.Methods = append(svcDesc.Methods, grpc.MethodDesc{
				MethodName: methodName,
				Handler:    makeHandler(fullMethod, methodName, msgDesc, flushCount),
			})
		}
		srv.RegisterService(svcDesc, &dynamicHandler{})
	}
}

func makeHandler(fullMethod, methodName string, msgDesc protoreflect.MessageDescriptor,
	flushCount *atomic.Int64) grpc.MethodHandler {

	return func(srv any, ctx context.Context, dec func(any) error,
		interceptor grpc.UnaryServerInterceptor) (any, error) {

		info := &grpc.UnaryServerInfo{FullMethod: fullMethod, Server: srv}
		return interceptor(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
			in := dynamicpb.NewMessage(msgDesc)
			if err := dec(in); err != nil {
				return nil, status.Error(codes.Internal, "malformed request rejected: "+err.Error())
			}
			return businessLogic(methodName, flushCount)
		})
	}
}

func businessLogic(method string, flushCount *atomic.Int64) (any, error) {
	switch method {
	case "FlushAll":
		flushCount.Add(1)
	case "Debug":
		return nil, status.Error(codes.Unimplemented, "debug disabled")
	}
	return nil, nil
}

// authInterceptor 模拟真实问题：管理服务漏配鉴权，业务服务强制 token。
func authInterceptor(_ *atomic.Int64) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		if isAdminMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		return nil, status.Error(codes.Unauthenticated, "missing bearer token")
	}
}

func isAdminMethod(fullMethod string) bool {
	const prefix = "/" + AdminService + "/"
	return len(fullMethod) >= len(prefix) && fullMethod[:len(prefix)] == prefix
}

type dynamicHandler struct{}

func pprofIndex(w http.ResponseWriter, r *http.Request)   { pprof.Index(w, r) }
func pprofCmdline(w http.ResponseWriter, r *http.Request) { pprof.Cmdline(w, r) }

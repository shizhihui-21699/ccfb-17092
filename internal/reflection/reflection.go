// Package reflection 通过 gRPC Server Reflection 协议枚举服务与方法。
//
// 反射本身是只读操作（ListServices / FileByFilename / FileContainingSymbol），
// 不会执行业务方法，但它的开放本身就是一条发现项：任何人都能拉取完整接口清单。
package reflection

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/internal/rpcrecon/internal/model"
)

// Result 是反射枚举的产出。
type Result struct {
	Status   model.ReflectionStatus
	Services []*model.ServiceInfo
}

// Enumerate 同时尝试 reflection v1 与 v1alpha，成功其一即可。
func Enumerate(ctx context.Context, conn *grpc.ClientConn) (*Result, error) {
	res := &Result{}

	// 优先 v1（当前标准），失败再试 v1alpha
	if svcs, err := enumerateV1(ctx, conn); err == nil {
		res.Status.Enabled = true
		res.Status.V1 = true
		res.Status.Unauth = true // 能拿到结果本身就说明反射未加鉴权
		res.Services = svcs
		return res, nil
	} else if isAuthError(err) {
		res.Status.Enabled = true
		res.Status.V1 = true
		res.Status.Unauth = false
		res.Status.Error = err.Error()
		return res, nil
	} else {
		res.Status.Error = err.Error()
	}

	if svcs, err := enumerateV1Alpha(ctx, conn); err == nil {
		res.Status.Enabled = true
		res.Status.V1Alpha = true
		res.Status.Unauth = true
		res.Services = svcs
		return res, nil
	} else if isAuthError(err) {
		res.Status.Enabled = true
		res.Status.V1Alpha = true
		res.Status.Unauth = false
		res.Status.Error = err.Error()
		return res, nil
	} else {
		res.Status.Error = combineErr(res.Status.Error, err)
	}
	return res, nil
}

// ---- v1 ----

func enumerateV1(ctx context.Context, conn *grpc.ClientConn) ([]*model.ServiceInfo, error) {
	client := grpc_reflection_v1.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CloseSend()

	h := &v1Handler{stream: stream}
	return h.run(ctx)
}

type v1Handler struct {
	stream grpc_reflection_v1.ServerReflection_ServerReflectionInfoClient
}

func (h *v1Handler) roundTrip(req *grpc_reflection_v1.ServerReflectionRequest) (*grpc_reflection_v1.ServerReflectionResponse, error) {
	if err := h.stream.Send(req); err != nil {
		return nil, err
	}
	resp, err := h.stream.Recv()
	if err != nil {
		return nil, err
	}
	if er := resp.GetErrorResponse(); er != nil {
		return nil, status.Error(codes.Code(er.GetErrorCode()), er.GetErrorMessage())
	}
	return resp, nil
}

func (h *v1Handler) run(ctx context.Context) ([]*model.ServiceInfo, error) {
	listResp, err := h.roundTrip(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{ListServices: "*"},
	})
	if err != nil {
		return nil, err
	}
	ls := listResp.GetListServicesResponse()
	if ls == nil {
		return nil, errors.New("反射返回类型异常：缺少 ListServicesResponse")
	}

	fetcher := &fileFetcherV1{h: h}
	builder := newDescriptorBuilder(fetcher)
	var out []*model.ServiceInfo
	for _, svc := range ls.GetService() {
		name := svc.GetName()
		if isBuiltinReflectionService(name) {
			continue
		}
		files, err := builder.fileContainingSymbol(ctx, name)
		if err != nil {
			continue
		}
		if si := buildServiceFromFiles(name, files); si != nil {
			out = append(out, si)
		}
	}
	return out, nil
}

// ---- v1alpha（老版本服务兼容）----

func enumerateV1Alpha(ctx context.Context, conn *grpc.ClientConn) ([]*model.ServiceInfo, error) {
	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CloseSend()

	send := func(req *grpc_reflection_v1alpha.ServerReflectionRequest) (*grpc_reflection_v1alpha.ServerReflectionResponse, error) {
		if err := stream.Send(req); err != nil {
			return nil, err
		}
		resp, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if er := resp.GetErrorResponse(); er != nil {
			return nil, status.Error(codes.Code(er.GetErrorCode()), er.GetErrorMessage())
		}
		return resp, nil
	}

	listResp, err := send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{ListServices: "*"},
	})
	if err != nil {
		return nil, err
	}
	ls := listResp.GetListServicesResponse()
	if ls == nil {
		return nil, errors.New("v1alpha 反射返回类型异常")
	}

	fetcher := &fileFetcherAlpha{send: send}
	builder := newDescriptorBuilder(fetcher)
	var out []*model.ServiceInfo
	for _, svc := range ls.GetService() {
		name := svc.GetName()
		if isBuiltinReflectionService(name) {
			continue
		}
		files, err := builder.fileContainingSymbol(ctx, name)
		if err != nil {
			continue
		}
		if si := buildServiceFromFiles(name, files); si != nil {
			out = append(out, si)
		}
	}
	return out, nil
}

// ---- 文件描述符获取抽象（v1 / v1alpha 适配）----

type fileFetcher interface {
	fileByFilename(ctx context.Context, name string) ([]byte, error)
	fileContainingSymbol(ctx context.Context, symbol string) ([]byte, error)
}

type fileFetcherV1 struct{ h *v1Handler }

func (f *fileFetcherV1) fileByFilename(ctx context.Context, name string) ([]byte, error) {
	resp, err := f.h.roundTrip(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_FileByFilename{FileByFilename: name},
	})
	if err != nil {
		return nil, err
	}
	return firstFile(resp.GetFileDescriptorResponse())
}

func (f *fileFetcherV1) fileContainingSymbol(ctx context.Context, symbol string) ([]byte, error) {
	resp, err := f.h.roundTrip(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: symbol},
	})
	if err != nil {
		return nil, err
	}
	return firstFile(resp.GetFileDescriptorResponse())
}

type alphaSender func(req *grpc_reflection_v1alpha.ServerReflectionRequest) (*grpc_reflection_v1alpha.ServerReflectionResponse, error)

type fileFetcherAlpha struct{ send alphaSender }

func (f *fileFetcherAlpha) fileByFilename(ctx context.Context, name string) ([]byte, error) {
	resp, err := f.send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileByFilename{FileByFilename: name},
	})
	if err != nil {
		return nil, err
	}
	return firstAlpha(resp.GetFileDescriptorResponse())
}

func (f *fileFetcherAlpha) fileContainingSymbol(ctx context.Context, symbol string) ([]byte, error) {
	resp, err := f.send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: symbol},
	})
	if err != nil {
		return nil, err
	}
	return firstAlpha(resp.GetFileDescriptorResponse())
}

func firstFile(r *grpc_reflection_v1.FileDescriptorResponse) ([]byte, error) {
	if r == nil || len(r.GetFileDescriptorProto()) == 0 {
		return nil, errors.New("反射响应缺少文件描述符")
	}
	return r.GetFileDescriptorProto()[0], nil
}

func firstAlpha(r *grpc_reflection_v1alpha.FileDescriptorResponse) ([]byte, error) {
	if r == nil || len(r.GetFileDescriptorProto()) == 0 {
		return nil, errors.New("反射响应缺少文件描述符")
	}
	return r.GetFileDescriptorProto()[0], nil
}

// ---- 描述符递归构建 ----

type descriptorBuilder struct {
	fetcher fileFetcher
	cache   map[string]*descriptorpb.FileDescriptorProto
}

func newDescriptorBuilder(f fileFetcher) *descriptorBuilder {
	return &descriptorBuilder{fetcher: f, cache: make(map[string]*descriptorpb.FileDescriptorProto)}
}

// fileContainingSymbol 拉取符号所在文件及其全部依赖（深度优先 + 缓存）。
func (b *descriptorBuilder) fileContainingSymbol(ctx context.Context, symbol string) (map[string]*descriptorpb.FileDescriptorProto, error) {
	raw, err := b.fetcher.fileContainingSymbol(ctx, symbol)
	if err != nil {
		return nil, err
	}
	if err := b.ingest(raw); err != nil {
		return nil, err
	}
	// 递归拉依赖直到没有缺口
	for round := 0; round < 16; round++ {
		var missing []string
		for _, fd := range b.cache {
			for _, dep := range fd.GetDependency() {
				if _, ok := b.cache[dep]; !ok {
					missing = append(missing, dep)
				}
			}
		}
		if len(missing) == 0 {
			break
		}
		progressed := false
		for _, dep := range missing {
			depRaw, err := b.fetcher.fileByFilename(ctx, dep)
			if err != nil {
				continue // 依赖拉不到（well-known types 常见）：跳过
			}
			if b.ingest(depRaw) == nil {
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	out := make(map[string]*descriptorpb.FileDescriptorProto, len(b.cache))
	for name, fd := range b.cache {
		out[name] = fd
	}
	return out, nil
}

func (b *descriptorBuilder) ingest(raw []byte) error {
	fd := &descriptorpb.FileDescriptorProto{}
	if err := proto.Unmarshal(raw, fd); err != nil {
		return fmt.Errorf("解析 FileDescriptorProto 失败: %w", err)
	}
	if fd.GetName() == "" {
		return errors.New("FileDescriptorProto 缺少 name")
	}
	if _, ok := b.cache[fd.GetName()]; ok {
		return nil
	}
	b.cache[fd.GetName()] = fd
	return nil
}

func isBuiltinReflectionService(name string) bool {
	return name == "grpc.reflection.v1.ServerReflection" ||
		name == "grpc.reflection.v1alpha.ServerReflection" ||
		name == "grpc.health.v1.Health"
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	code := status.Code(err)
	return code == codes.Unauthenticated || code == codes.PermissionDenied
}

func combineErr(a string, b error) string {
	if a == "" {
		return b.Error()
	}
	if b == nil {
		return a
	}
	return fmt.Sprintf("%s; v1alpha: %s", a, b.Error())
}

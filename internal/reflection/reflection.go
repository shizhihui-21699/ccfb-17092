// Package reflection enumerates services and descriptors over the standard gRPC
// server-reflection service, using both the v1 and v1alpha protocols.
//
// Reflection is the only enumeration source that needs no cooperation beyond
// what the server already exposes, and its two request kinds
// (ListServices and FileContainingSymbol) are read-only by definition.
package reflection

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	refv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	refv1a "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Version is which reflection protocol answered.
type Version string

const (
	V1      Version = "v1"
	V1Alpha Version = "v1alpha"
)

// Result is everything reflection revealed.
type Result struct {
	Version  Version
	Services []string
	// Files holds the compiled descriptors, keyed by the file's dotted name.
	Files map[string]*descriptorpb.FileDescriptorProto
	// Gated reports that reflection was present but rejected our credentials.
	Gated bool
	// Absent reports that no reflection service is registered at all.
	Absent bool
	Err    error
}

// Enumerate tries v1 then v1alpha. Both are read-only service-listing
// requests; neither can cause a state change.
func Enumerate(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := enumerateV1(ctx, conn, timeout)
	if err == nil && len(res.Services) >= 0 {
		return res
	}
	// v1 failed; try the legacy protocol. Servers commonly register both, and a
	// few older ones register only v1alpha.
	res2, err2 := enumerateV1alpha(ctx, conn, timeout)
	if err2 == nil && len(res2.Services) >= 0 {
		res2.Version = V1Alpha
		if res.Version == "" {
			res2.Version = V1Alpha
		}
		return res2
	}
	if res.Gated || res2.Gated {
		return Result{Gated: true, Err: firstErr(res.Err, err2)}
	}
	// "unknown service" for the reflection service itself means reflection is
	// simply not registered — distinct from a reflection service that is
	// present but malfunctioning.
	if isUnknownService(res.Err) || isUnknownService(err2) {
		return Result{Absent: true, Err: firstErr(res.Err, err2)}
	}
	return Result{Err: firstErr(res.Err, err2)}
}

// isUnknownService reports whether the error is the server saying it does not
// register this service.
func isUnknownService(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.Unimplemented && strings.Contains(st.Message(), "unknown service")
	}
	return false
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func enumerateV1(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cli := refv1.NewServerReflectionClient(conn)
	stream, err := cli.ServerReflectionInfo(cctx)
	if err != nil {
		return Result{Version: V1}, err
	}
	req := &refv1.ServerReflectionRequest{
		MessageRequest: &refv1.ServerReflectionRequest_ListServices{ListServices: ""},
	}
	if err := stream.Send(req); err != nil {
		return Result{Version: V1}, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return Result{Version: V1}, err
	}

	result := Result{Version: V1, Files: map[string]*descriptorpb.FileDescriptorProto{}}
	if lr, ok := resp.MessageResponse.(*refv1.ServerReflectionResponse_ListServicesResponse); ok {
		for _, svc := range lr.ListServicesResponse.GetService() {
			result.Services = append(result.Services, svc.GetName())
		}
	} else if er, ok := resp.MessageResponse.(*refv1.ServerReflectionResponse_ErrorResponse); ok {
		return result, fmt.Errorf("reflection: %s", er.ErrorResponse.GetErrorMessage())
	}

	// Fetch descriptors for each service, one request per service on the same
	// stream, so a symbol-heavy server does not force one stream per symbol.
	for _, svc := range result.Services {
		_ = stream.Send(&refv1.ServerReflectionRequest{
			MessageRequest: &refv1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: svc},
		})
		r, err := stream.Recv()
		if err != nil {
			break
		}
		if fdr, ok := r.MessageResponse.(*refv1.ServerReflectionResponse_FileDescriptorResponse); ok {
			result.mergeFileDescriptors(fdr.FileDescriptorResponse.GetFileDescriptorProto())
		}
	}
	stream.CloseSend()
	return result, nil
}

func enumerateV1alpha(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cli := refv1a.NewServerReflectionClient(conn)
	stream, err := cli.ServerReflectionInfo(cctx)
	if err != nil {
		return Result{Version: V1Alpha}, err
	}
	req := &refv1a.ServerReflectionRequest{
		MessageRequest: &refv1a.ServerReflectionRequest_ListServices{ListServices: ""},
	}
	if err := stream.Send(req); err != nil {
		return Result{Version: V1Alpha}, err
	}
	resp, err := stream.Recv()
	if err != nil {
		return Result{Version: V1Alpha}, err
	}

	result := Result{Version: V1Alpha, Files: map[string]*descriptorpb.FileDescriptorProto{}}
	if lr, ok := resp.MessageResponse.(*refv1a.ServerReflectionResponse_ListServicesResponse); ok {
		for _, svc := range lr.ListServicesResponse.GetService() {
			result.Services = append(result.Services, svc.GetName())
		}
	} else if er, ok := resp.MessageResponse.(*refv1a.ServerReflectionResponse_ErrorResponse); ok {
		return result, fmt.Errorf("reflection: %s", er.ErrorResponse.GetErrorMessage())
	}

	for _, svc := range result.Services {
		_ = stream.Send(&refv1a.ServerReflectionRequest{
			MessageRequest: &refv1a.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: svc},
		})
		r, err := stream.Recv()
		if err != nil {
			break
		}
		if fdr, ok := r.MessageResponse.(*refv1a.ServerReflectionResponse_FileDescriptorResponse); ok {
			result.mergeFileDescriptors(fdr.FileDescriptorResponse.GetFileDescriptorProto())
		}
	}
	stream.CloseSend()
	return result, nil
}

// mergeFileDescriptors decodes raw serialized FileDescriptorProtos. Reflection
// may emit the same file repeatedly (it is included with every dependent
// symbol), so de-duplication is by file name.
func (r *Result) mergeFileDescriptors(raw [][]byte) {
	for _, b := range raw {
		fdp := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(b, fdp); err != nil {
			continue
		}
		if _, seen := r.Files[fdp.GetName()]; seen {
			continue
		}
		r.Files[fdp.GetName()] = fdp
	}
}

// BuildRegistry links the collected file descriptors into a resolver that can
// answer protoreflect lookups. Descriptors returned by reflection are complete
// for the service's own files but may omit files from dependencies that were
// never sent; those are filled from the standard imports where possible.
func (r *Result) BuildRegistry() (*protoregistry.Files, error) {
	if len(r.Files) == 0 {
		return nil, fmt.Errorf("no file descriptors collected")
	}
	reg := &protoregistry.Files{}

	// Add every file, in dependency order. NewFiles tolerates forward
	// references poorly, so retry until no progress is made.
	pending := make(map[string]*descriptorpb.FileDescriptorProto, len(r.Files))
	for k, v := range r.Files {
		pending[k] = v
	}
	for len(pending) > 0 {
		progressed := false
		for name, fdp := range pending {
			// Link the file against dependencies already resolved into reg.
			resolved, ok := r.resolveFile(fdp, reg)
			if ok {
				if err := reg.RegisterFile(resolved); err == nil {
					delete(pending, name)
					progressed = true
					continue
				}
			}
			// A file whose dependencies only exist in the process-wide registry
			// (the server's own generated code, or a standard import) can be
			// reused directly. It must still be *added* to reg, not skipped:
			// a caller enumerating reg only sees what it holds.
			if fd, err := protoregistry.GlobalFiles.FindFileByPath(name); err == nil {
				if err := reg.RegisterFile(fd); err == nil {
					delete(pending, name)
					progressed = true
					continue
				}
			}
		}
		if !progressed {
			// Reject the leftovers rather than loop forever.
			break
		}
	}
	if len(pending) > 0 {
		return reg, fmt.Errorf("could not link %d descriptor file(s)", len(pending))
	}
	return reg, nil
}

func (r *Result) resolveFile(fdp *descriptorpb.FileDescriptorProto, reg *protoregistry.Files) (protoreflect.FileDescriptor, bool) {
	var deps []protoreflect.FileDescriptor
	for _, dep := range fdp.GetDependency() {
		if fd, err := reg.FindFileByPath(dep); err == nil {
			deps = append(deps, fd)
			continue
		}
		if fd, err := protoregistry.GlobalFiles.FindFileByPath(dep); err == nil {
			deps = append(deps, fd)
			continue
		}
		// A dependency we never saw; give up on this file for now.
		return nil, false
	}
	fd, err := protodesc.NewFile(fdp, sliceResolver(deps))
	if err != nil {
		return nil, false
	}
	return fd, true
}

// sliceResolver resolves imports from a fixed list.
type sliceResolver []protoreflect.FileDescriptor

func (s sliceResolver) FindFileByPath(path string) (protoreflect.FileDescriptor, error) {
	for _, fd := range s {
		if fd.Path() == path {
			return fd, nil
		}
	}
	if fd, err := protoregistry.GlobalFiles.FindFileByPath(path); err == nil {
		return fd, nil
	}
	return nil, protoregistry.NotFound
}

func (s sliceResolver) FindDescriptorByName(name protoreflect.FullName) (protoreflect.Descriptor, error) {
	for _, fd := range s {
		if d := fd.Messages().ByName(name.Name()); d != nil && d.FullName() == name {
			return d, nil
		}
	}
	if d, err := protoregistry.GlobalFiles.FindDescriptorByName(name); err == nil {
		return d, nil
	}
	return nil, protoregistry.NotFound
}

// ServiceDescriptors returns the service descriptors among the collected
// files' top-level services, sorted by name.
func ServiceDescriptors(files *protoregistry.Files) []protoreflect.ServiceDescriptor {
	var out []protoreflect.ServiceDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			out = append(out, svcs.Get(i))
		}
		return true
	})
	return out
}

// IsReflectionService reports whether a service name is a reflection service
// itself, which should be listed but not treated as business surface.
func IsReflectionService(name string) bool {
	return strings.HasPrefix(name, "grpc.reflection.")
}

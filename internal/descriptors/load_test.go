package descriptors_test

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/internal/rpcrecon/internal/descriptors"
	"github.com/internal/rpcrecon/internal/model"
)

// buildDescriptorSet 构造一份等价于真实 protoc 产物的 FileDescriptorSet。
func buildDescriptorSet(t *testing.T) []byte {
	t.Helper()
	fdProto := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("ops/v1/admin.proto"),
		Package: proto.String("ops.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Req")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("AdminService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       proto.String("FlushAll"),
						InputType:  proto.String(".ops.v1.Req"),
						OutputType: proto.String(".ops.v1.Req"),
					},
					{
						Name:            proto.String("Watch"),
						InputType:       proto.String(".ops.v1.Req"),
						OutputType:      proto.String(".ops.v1.Req"),
						ServerStreaming: proto.Bool(true),
					},
				},
			},
		},
	}

	// 走一遍 protodesc 校验，保证描述符本身合法
	desc, err := protodesc.NewFile(fdProto, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = desc
	// 避免全局注册冲突
	_, _ = protoregistry.GlobalFiles.FindFileByPath("ops/v1/admin.proto")

	set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{fdProto}}
	raw, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseFileDescriptorSet(t *testing.T) {
	raw := buildDescriptorSet(t)
	svcs, err := descriptors.ParseFileDescriptorSet(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 {
		t.Fatalf("应解析出 1 个服务，得到 %d", len(svcs))
	}
	svc := svcs[0]
	if svc.Name != "ops.v1.AdminService" || svc.Source != model.SourceDescriptor || svc.Confidence != 1.0 {
		t.Fatalf("服务元数据错误: %+v", svc)
	}
	if len(svc.Methods) != 2 {
		t.Fatalf("应解析出 2 个方法，得到 %d", len(svc.Methods))
	}
	flush, watch := svc.Methods[0], svc.Methods[1]
	if flush.FullName != "/ops.v1.AdminService/FlushAll" || flush.IsStreaming {
		t.Fatalf("一元方法解析错误: %+v", flush)
	}
	if watch.Name != "Watch" || !watch.IsStreaming || !watch.ServerStream {
		t.Fatalf("流式方法标记错误: %+v", watch)
	}
}

func TestLoadDirSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.fds"), buildDescriptorSet(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.fds"), []byte("not-a-descriptor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	svcs, err := descriptors.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 {
		t.Fatalf("损坏文件应被跳过，仅加载 1 个服务，得到 %d", len(svcs))
	}
}

var _ protoreflect.FileDescriptor

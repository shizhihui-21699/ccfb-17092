package scan

import (
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ServicesFromRegistry returns every service defined across the registry.
func ServicesFromRegistry(files *protoregistry.Files) []protoreflect.ServiceDescriptor {
	if files == nil {
		return nil
	}
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

// dynamicEmpty returns a throwaway message used only as a receive target.
func dynamicEmpty() protoreflect.Message {
	md, _ := findMessage(nil, "")
	_ = md
	return dynamicpb.NewMessage((&emptypb.Empty{}).ProtoReflect().Descriptor())
}

package reflection

import (
	"strings"

	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/internal/rpcrecon/internal/model"
)

// buildServiceFromFiles 从已拉取的文件描述符集合中找到目标服务，
// 转换成工具内部的 ServiceInfo。
func buildServiceFromFiles(serviceName string, files map[string]*descriptorpb.FileDescriptorProto) *model.ServiceInfo {
	for _, fd := range files {
		pkg := fd.GetPackage()
		for _, sd := range fd.GetService() {
			fullName := sd.GetName()
			if pkg != "" {
				fullName = pkg + "." + sd.GetName()
			}
			if fullName != serviceName {
				continue
			}
			si := &model.ServiceInfo{
				Name:       fullName,
				Source:     model.SourceReflection,
				Confidence: 1.0,
			}
			for _, md := range sd.GetMethod() {
				mi := &model.MethodInfo{
					Service:      fullName,
					Name:         md.GetName(),
					FullName:     "/" + fullName + "/" + md.GetName(),
					IsStreaming:  md.GetClientStreaming() || md.GetServerStreaming(),
					ClientStream: md.GetClientStreaming(),
					ServerStream: md.GetServerStreaming(),
					InputType:    normalizeType(md.GetInputType()),
					OutputType:   normalizeType(md.GetOutputType()),
					Source:       model.SourceReflection,
				}
				si.Methods = append(si.Methods, mi)
			}
			return si
		}
	}
	return nil
}

// normalizeType 去掉 descriptor 里前导的点号：".pkg.Msg" -> "pkg.Msg"
func normalizeType(t string) string {
	return strings.TrimPrefix(t, ".")
}

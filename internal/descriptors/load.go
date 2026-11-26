// Package descriptors 加载本地 protobuf 描述文件（FileDescriptorSet），
// 在目标服务关闭反射时仍能获得精确的方法清单。
//
// 描述文件的常见来源：
//   - protoc --include_imports --descriptor_set_out=out.pb ./xxx.proto
//   - buf build -o image.bin
//   - 从构建产物 / 服务仓库里收集 *.pb（二进制 FileDescriptorSet）
package descriptors

import (
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/internal/rpcrecon/internal/model"
)

// LoadFile 读取一个 FileDescriptorSet 二进制文件并转换为 ServiceInfo。
func LoadFile(path string) ([]*model.ServiceInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseFileDescriptorSet(raw)
}

// ParseFileDescriptorSet 解析二进制 FileDescriptorSet。
func ParseFileDescriptorSet(raw []byte) ([]*model.ServiceInfo, error) {
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, fds); err != nil {
		return nil, err
	}
	var out []*model.ServiceInfo
	for _, fd := range fds.GetFile() {
		for _, si := range servicesFromFile(fd) {
			out = append(out, si)
		}
	}
	return out, nil
}

// servicesFromFile 与 reflection.buildServiceFromFiles 逻辑保持一致，
// 但来源标记为 descriptor（置信度 1.0，因为来自真实 schema）。
func servicesFromFile(fd *descriptorpb.FileDescriptorProto) []*model.ServiceInfo {
	pkg := fd.GetPackage()
	var out []*model.ServiceInfo
	for _, sd := range fd.GetService() {
		fullName := sd.GetName()
		if pkg != "" {
			fullName = pkg + "." + sd.GetName()
		}
		si := &model.ServiceInfo{
			Name:       fullName,
			Source:     model.SourceDescriptor,
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
				InputType:    trimDot(md.GetInputType()),
				OutputType:   trimDot(md.GetOutputType()),
				Source:       model.SourceDescriptor,
			}
			si.Methods = append(si.Methods, mi)
		}
		out = append(out, si)
	}
	return out
}

func trimDot(t string) string {
	if len(t) > 0 && t[0] == '.' {
		return t[1:]
	}
	return t
}

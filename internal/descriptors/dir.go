package descriptors

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
)

// LoadDir 加载目录下全部描述文件（.pb / .bin / .fds 后缀）。
// 不同文件里的同名服务自动去重。
func LoadDir(dir string) ([]*model.ServiceInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]*model.ServiceInfo)
	var out []*model.ServiceInfo

	// 稳定顺序，保证报告可复现
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if !isDescriptorFile(name) {
			continue
		}
		svcs, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			// 单个文件损坏不阻断整体扫描
			continue
		}
		for _, svc := range svcs {
			if existing, ok := seen[svc.Name]; ok {
				mergeMethods(existing, svc)
				continue
			}
			seen[svc.Name] = svc
			out = append(out, svc)
		}
	}
	return out, nil
}

func isDescriptorFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pb") ||
		strings.HasSuffix(lower, ".bin") ||
		strings.HasSuffix(lower, ".fds") ||
		strings.HasSuffix(lower, ".desc")
}

func mergeMethods(dst, src *model.ServiceInfo) {
	exists := make(map[string]struct{}, len(dst.Methods))
	for _, m := range dst.Methods {
		exists[m.FullName] = struct{}{}
	}
	for _, m := range src.Methods {
		if _, ok := exists[m.FullName]; !ok {
			dst.Methods = append(dst.Methods, m)
		}
	}
}

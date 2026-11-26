// Package guess 在服务关闭反射、也没有描述文件时，用字典组合候选方法名。
//
// gRPC 方法路径固定为 /<全限定服务名>/<方法名>，因此猜测空间 = 服务名字典 ×
// 方法名字典。猜测结果只作为候选（Confidence < 1），是否真实存在由无害探测
// 的返回码验证：Unimplemented 表示不存在，其它码表示方法存在。
package guess

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
)

// Dictionary 是可外部覆盖的猜测字典。
type Dictionary struct {
	// Services 为全限定服务名片段，如 "admin.ConfigService"
	Services []string `json:"services"`
	// Methods 为方法名，如 "FlushAll"
	Methods []string `json:"methods"`
	// Prefixes 为服务名前缀（包名），与 ServiceShortNames 组合
	Prefixes []string `json:"prefixes"`
	// ServiceShortNames 与 Prefixes 做笛卡尔积
	ServiceShortNames []string `json:"service_short_names"`
}

// DefaultDictionary 返回内置字典，覆盖 Go 微服务里最常见的管理/调试命名。
func DefaultDictionary() Dictionary {
	return Dictionary{
		Prefixes: []string{
			"admin", "internal", "ops", "system", "manage", "management",
			"debug", "config", "cache", "infra", "platform",
		},
		ServiceShortNames: []string{
			"AdminService", "ConfigService", "CacheService", "SystemService",
			"ManagementService", "DebugService", "OpsService", "ControlService",
			"MaintenanceService", "RuntimeService",
		},
		Services: []string{
			"grpc.health.v1.Health",
			"admin.AdminService",
			"admin.ConfigService",
			"admin.CacheService",
			"internal.AdminService",
			"ops.ControlService",
			"system.RuntimeService",
			"debug.DebugService",
			"manage.ManagementService",
		},
		Methods: []string{
			// 配置类
			"UpdateConfig", "SetConfig", "ReloadConfig", "GetConfig",
			"ResetConfig", "ApplyConfig",
			// 缓存类（事故重灾区）
			"FlushCache", "FlushAll", "ClearCache", "EvictKey", "PurgeCache",
			"InvalidateCache", "ResetCache",
			// 生命周期/流量
			"Shutdown", "GracefulShutdown", "Restart", "Drain", "SetDrain",
			"KillConnections", "Reload",
			// 调试
			"Debug", "Pprof", "ListGoroutines", "DumpState", "DumpEnv",
			"ToggleDebug", "SetLogLevel",
			// 数据/权限
			"DeleteAll", "Truncate", "DropData", "ResetData",
			"GrantRole", "RevokeRole", "SetPermission",
			// 通用 CRUD（用于存在性验证，不全部按高危处理）
			"List", "Get", "Create", "Update", "Delete",
		},
	}
}

// LoadDictionary 从 JSON 文件加载自定义字典（字段与 DefaultDictionary 一致）。
func LoadDictionary(path string) (Dictionary, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Dictionary{}, err
	}
	var d Dictionary
	if err := json.Unmarshal(raw, &d); err != nil {
		return Dictionary{}, err
	}
	return d, nil
}

// Candidates 按字典生成候选方法集合，自动去重。
// maxCandidates 限制总量，防止字典膨胀产生海量无效请求。
func Candidates(d Dictionary, maxCandidates int) []*model.MethodInfo {
	seen := make(map[string]struct{})
	var out []*model.MethodInfo

	add := func(service, method string) {
		if len(out) >= maxCandidates {
			return
		}
		full := "/" + service + "/" + method
		if _, ok := seen[full]; ok {
			return
		}
		seen[full] = struct{}{}
		out = append(out, &model.MethodInfo{
			Service:  service,
			Name:     method,
			FullName: full,
			// 猜测阶段不知道流类型，按一元方法处理；探测阶段仍受安全策略约束
			IsStreaming: false,
			Source:      model.SourceGuess,
		})
	}

	// 1. 显式服务名 × 全部方法
	for _, svc := range d.Services {
		for _, m := range d.Methods {
			add(svc, m)
		}
	}
	// 2. 前缀 × 短服务名 × 全部方法
	for _, prefix := range d.Prefixes {
		for _, short := range d.ServiceShortNames {
			svc := strings.TrimSuffix(prefix, ".") + "." + short
			for _, m := range d.Methods {
				add(svc, m)
			}
		}
	}
	return out
}

// MarkGuessed 把候选方法包装成 ServiceInfo，来源统一标记为 guess。
func MarkGuessed(methods []*model.MethodInfo) []*model.ServiceInfo {
	byService := make(map[string]*model.ServiceInfo)
	var order []string
	for _, m := range methods {
		si, ok := byService[m.Service]
		if !ok {
			si = &model.ServiceInfo{
				Name:       m.Service,
				Source:     model.SourceGuess,
				Confidence: 0.4, // 字典猜测的基础置信度，探测命中后再上调
			}
			byService[m.Service] = si
			order = append(order, m.Service)
		}
		si.Methods = append(si.Methods, m)
	}
	out := make([]*model.ServiceInfo, 0, len(order))
	for _, name := range order {
		out = append(out, byService[name])
	}
	return out
}

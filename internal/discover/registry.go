package discover

import (
	"context"

	"github.com/internal/rpcrecon/internal/model"
	"github.com/internal/rpcrecon/internal/safe"
)

// RegistryAdapter 抽象服务注册中心。
//
// 生产环境的服务地址通常动态变化，注册中心（etcd/nacos/consul/k8s）才是
// 最权威的目标来源。具体实现按需补充，扫描主流程只依赖本接口：
//
//	type EtcdAdapter struct{ ... }
//	func (a *EtcdAdapter) List(ctx) ([]model.Target, error) { ... }
type RegistryAdapter interface {
	Name() string
	// List 返回注册中心当前所有健康实例。
	List(ctx context.Context) ([]model.Target, error)
}

// FromRegistry 通过注册中心适配器生成目标，同样经过安全策略校验。
func FromRegistry(ctx context.Context, adapters []RegistryAdapter, policy safe.Policy) ([]model.Target, error) {
	seen := make(map[string]struct{})
	var out []model.Target
	for _, ad := range adapters {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		targets, err := ad.List(ctx)
		if err != nil {
			return out, &AdapterError{Adapter: ad.Name(), Err: err}
		}
		for _, t := range targets {
			key := t.Addr()
			if _, ok := seen[key]; ok {
				continue
			}
			if err := policy.CheckTarget(t.Host, t.Port); err != nil {
				// 注册中心里也可能混入不在授权网段的实例，跳过并保留来源
				continue
			}
			if t.Source == "" {
				t.Source = "registry:" + ad.Name()
			}
			seen[key] = struct{}{}
			out = append(out, t)
			if len(out) >= policy.MaxEndpoints {
				return out, nil
			}
		}
	}
	return out, nil
}

// AdapterError 包装注册中心适配器错误，保留适配器名。
type AdapterError struct {
	Adapter string
	Err     error
}

func (e *AdapterError) Error() string {
	return "注册中心适配器 " + e.Adapter + " 失败: " + e.Err.Error()
}

func (e *AdapterError) Unwrap() error { return e.Err }

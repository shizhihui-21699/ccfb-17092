// Package classify 根据可配置规则识别敏感 RPC 方法。
//
// 判定只依赖方法/服务命名（反射或猜测都能提供），不发送任何请求。
// 规则分三层：
//  1. 内置规则（关键词 + 命名约定），开箱即用
//  2. 外部 JSON 规则文件，团队可按自家命名习惯扩展
//  3. 显式覆盖列表
package classify

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/internal/rpcrecon/internal/model"
)

// Rule 是一条敏感方法匹配规则。
type Rule struct {
	// Name 规则名，会写入证据链
	Name string `json:"name"`
	// Kind 命中后的敏感类别
	Kind model.SensitiveKind `json:"kind"`
	// Severity 命中后的风险等级
	Severity model.Severity `json:"severity"`
	// MethodKeywords 方法名包含任一关键词即命中（大小写不敏感）
	MethodKeywords []string `json:"method_keywords,omitempty"`
	// ServiceKeywords 服务名包含任一关键词即命中
	ServiceKeywords []string `json:"service_keywords,omitempty"`
	// MethodRegex 方法名正则（可选）
	MethodRegex string `json:"method_regex,omitempty"`
	// FullNameRegex 全限定路径正则（可选）
	FullNameRegex string `json:"full_name_regex,omitempty"`
}

// Engine 是分类引擎。
type Engine struct {
	rules    []Rule
	compiled map[string]*regexp.Regexp
}

// BuiltinRules 返回内置规则集。
func BuiltinRules() []Rule {
	return []Rule{
		// ---- Critical：直接造成破坏/全局影响 ----
		{Name: "cache-flush", Kind: model.KindCache, Severity: model.SeverityCritical,
			MethodKeywords: []string{"flushall", "flushcache", "clearcache", "purgecache",
				"invalidatetable", "resetcache", "dropcache"}},
		{Name: "data-destructive", Kind: model.KindDataWrite, Severity: model.SeverityCritical,
			MethodKeywords: []string{"deleteall", "truncate", "dropdata", "resetdata", "wipeall", "purgeall"}},
		{Name: "lifecycle", Kind: model.KindAdmin, Severity: model.SeverityCritical,
			MethodKeywords: []string{"shutdown", "gracefulshutdown", "restart", "drain", "killconnections"}},
		{Name: "config-write", Kind: model.KindConfig, Severity: model.SeverityHigh,
			MethodKeywords: []string{"updateconfig", "setconfig", "reloadconfig", "resetconfig",
				"applyconfig", "patchconfig", "writeconfig"}},

		// ---- High：管理/权限变更 ----
		{Name: "admin-service", Kind: model.KindAdmin, Severity: model.SeverityHigh,
			ServiceKeywords: []string{"admin", "management", "control", "ops", "maintenance"}},
		{Name: "permission-change", Kind: model.KindAdmin, Severity: model.SeverityHigh,
			MethodKeywords: []string{"grantrole", "revokerole", "setpermission", "addpermission",
				"impersonate", "sudo"}},
		{Name: "cache-mgmt", Kind: model.KindCache, Severity: model.SeverityHigh,
			ServiceKeywords: []string{"cache"},
			MethodKeywords:  []string{"evict", "invalidate", "clear", "flush"}},
		{Name: "debug-primitive", Kind: model.KindDebug, Severity: model.SeverityHigh,
			MethodKeywords: []string{"pprof", "listgoroutines", "dumpstate", "dumpenv",
				"toggledebug", "setloglevel", "exec", "shell", "eval"}},

		// ---- Medium：普通写操作 ----
		{Name: "generic-write", Kind: model.KindDataWrite, Severity: model.SeverityMedium,
			MethodKeywords: []string{"create", "update", "delete", "remove", "set", "put", "write"}},

		// ---- Low：读操作 ----
		{Name: "generic-read", Kind: model.KindDataRead, Severity: model.SeverityLow,
			MethodKeywords: []string{"list", "get", "query", "describe", "fetch", "read", "search"}},
		{Name: "config-read", Kind: model.KindConfig, Severity: model.SeverityMedium,
			MethodKeywords: []string{"getconfig", "listconfig", "describefeature"}},
		{Name: "health", Kind: model.KindHealth, Severity: model.SeverityInfo,
			ServiceKeywords: []string{"health"},
			MethodKeywords:  []string{"check", "watch"}},
	}
}

// LoadRules 从 JSON 文件加载自定义规则（与内置规则合并）。
func LoadRules(path string) ([]Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// NewEngine 构造分类引擎，rules 为 nil 时只使用内置规则。
func NewEngine(extra []Rule) *Engine {
	e := &Engine{
		rules:    append(BuiltinRules(), extra...),
		compiled: make(map[string]*regexp.Regexp),
	}
	return e
}

// Classify 对单个方法做分类，返回最高严重级别的命中；无命中返回 nil。
func (e *Engine) Classify(m *model.MethodInfo) *model.SensitiveMatch {
	// 健康检查类方法单独处理，避免被通用 CRUD 关键词（如 List/Get）升级误报
	if isHealthMethod(m) {
		return &model.SensitiveMatch{
			Kind:     model.KindHealth,
			Severity: model.SeverityInfo,
			Keywords: []string{"health-check"},
		}
	}

	var best *model.SensitiveMatch
	for _, r := range e.rules {
		if !e.match(r, m) {
			continue
		}
		// 内置 health 规则已被上面的精确判断取代，跳过以免重复归类
		if r.Name == "health" {
			continue
		}
		match := &model.SensitiveMatch{
			Kind:     r.Kind,
			Severity: r.Severity,
			Keywords: []string{r.Name},
		}
		if best == nil || severityRank(match.Severity) > severityRank(best.Severity) {
			best = match
		} else if severityRank(match.Severity) == severityRank(best.Severity) {
			best.Keywords = append(best.Keywords, r.Name)
		}
	}
	return best
}

// isHealthMethod 精确识别 gRPC 健康检查与常见 HTTP 健康探针命名。
func isHealthMethod(m *model.MethodInfo) bool {
	svc := strings.ToLower(m.Service)
	name := strings.ToLower(m.Name)
	if strings.Contains(svc, "health") {
		switch name {
		case "check", "watch", "list", "get", "":
			return true
		}
	}
	return name == "healthz" || name == "readyz" || name == "livez"
}

func (e *Engine) match(r Rule, m *model.MethodInfo) bool {
	if len(r.MethodKeywords) > 0 {
		name := strings.ToLower(m.Name)
		hit := false
		for _, kw := range r.MethodKeywords {
			if strings.Contains(name, strings.ToLower(kw)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.ServiceKeywords) > 0 {
		svc := strings.ToLower(m.Service)
		hit := false
		for _, kw := range r.ServiceKeywords {
			if strings.Contains(svc, strings.ToLower(kw)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if r.MethodRegex != "" {
		re, err := e.regex(r.MethodRegex)
		if err != nil || !re.MatchString(m.Name) {
			return false
		}
	}
	if r.FullNameRegex != "" {
		re, err := e.regex(r.FullNameRegex)
		if err != nil || !re.MatchString(m.FullName) {
			return false
		}
	}
	// 规则可以只配服务名关键词（如 admin-service），此时关键词条件已在上面通过
	return len(r.MethodKeywords) > 0 || len(r.ServiceKeywords) > 0 ||
		r.MethodRegex != "" || r.FullNameRegex != ""
}

func (e *Engine) regex(pattern string) (*regexp.Regexp, error) {
	if re, ok := e.compiled[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	e.compiled[pattern] = re
	return re, nil
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

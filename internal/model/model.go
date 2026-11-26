// Package model 定义探测过程中流转的核心数据结构。
package model

import "time"

// Target 表示一个待探测的网络端点。
type Target struct {
	Host string // IP 或主机名
	Port int
	// Source 记录该目标的来源（cidr / file / registry:...），便于审计
	Source string
}

func (t Target) Addr() string {
	return joinHostPort(t.Host, t.Port)
}

// Transport 表示端点的传输层形态。
type Transport string

const (
	TransportPlaintext Transport = "grpc"
	TransportTLS       Transport = "grpcs"
	TransportUnknown   Transport = "unknown"
)

// Endpoint 是对一个存活服务的完整刻画。
type Endpoint struct {
	Target      Target
	Transport   Transport
	ALPN        string // h2 / http/1.1 ...
	IsGRPC      bool
	Reflection  ReflectionStatus
	Services    []*ServiceInfo
	HTTPAdmin   []HTTPPathFinding
	ProbedAt    time.Time
	Source      string
	Annotations map[string]string
}

// ReflectionStatus 描述 gRPC 反射的开放情况。
type ReflectionStatus struct {
	Enabled bool
	V1      bool // grpc.reflection.v1.ServerReflection
	V1Alpha bool // grpc.reflection.v1alpha.ServerReflection
	Unauth  bool // 反射本身是否无需鉴权即可使用
	Error   string
}

// ServiceInfo 是一个被枚举（或猜测）出来的 gRPC 服务。
type ServiceInfo struct {
	Name       string // 全限定服务名，如 admin.ConfigService
	Methods    []*MethodInfo
	Source     MethodSource // 该服务的来源
	Confidence float64      // 0~1，猜测场景下 <1
}

// MethodSource 标识方法清单的可信来源。
type MethodSource string

const (
	SourceReflection MethodSource = "reflection" // 服务反射，可信
	SourceDescriptor MethodSource = "descriptor" // 本地 FileDescriptorSet
	SourceGuess      MethodSource = "guess"      // 字典猜测
)

// MethodInfo 描述单个 RPC 方法。
type MethodInfo struct {
	FullName     string // /svc/Method
	Service      string
	Name         string
	IsStreaming  bool
	ClientStream bool
	ServerStream bool
	InputType    string
	OutputType   string
	// Source 标记该方法的来源（反射/描述文件/猜测）
	Source MethodSource
	// 敏感方法分类结果
	Sensitive *SensitiveMatch
	// 未授权探测结果
	Probe *ProbeResult
}

// SensitiveMatch 记录敏感方法判定依据。
type SensitiveMatch struct {
	Kind     SensitiveKind
	Severity Severity
	Keywords []string // 命中的关键词/规则名
}

// SensitiveKind 是敏感操作的大类。
type SensitiveKind string

const (
	KindConfig     SensitiveKind = "config_mgmt"
	KindCache      SensitiveKind = "cache_mgmt"
	KindAdmin      SensitiveKind = "admin"
	KindDataWrite  SensitiveKind = "data_write"
	KindDataRead   SensitiveKind = "data_read"
	KindDebug      SensitiveKind = "debug"
	KindInternal   SensitiveKind = "internal"
	KindHealth     SensitiveKind = "health"
	KindReflection SensitiveKind = "reflection"
	KindUnknown    SensitiveKind = "unknown"
)

// Severity 风险等级。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ExposureLevel 是未授权可达性的结论。
type ExposureLevel string

const (
	// ExposureUnauthenticated: 没有任何鉴权层拦截，请求已进入解码/业务阶段
	ExposureUnauthenticated ExposureLevel = "unauthenticated"
	// ExposureAuthenticated: 明确返回 Unauthenticated/PermissionDenied
	ExposureAuthenticated ExposureLevel = "authenticated"
	// ExposureBlocked: 网络层/网关拦截（Unavailable、连接重置等）
	ExposureBlocked ExposureLevel = "blocked"
	// ExposureInconclusive: 无法判断，需要人工复核
	ExposureInconclusive ExposureLevel = "inconclusive"
	// ExposureSkipped: 按安全策略跳过（如流式方法、变异方法空消息探测）
	ExposureSkipped ExposureLevel = "skipped"
)

// ProbeResult 是单个方法的无害探测结果。
type ProbeResult struct {
	Exposure     ExposureLevel
	GRPCCode     string // OK / Internal / Unauthenticated ...
	StatusCode   uint32
	Message      string
	BaselineCode string // 同端点不存在方法的基线返回码
	Confidence   float64
	// PayloadKind 说明实际发送的载荷类型
	PayloadKind string // malformed-wire / none
	Notes       []string
}

// HTTPPathFinding 是同端口 HTTP 管理面的发现。
type HTTPPathFinding struct {
	Path       string
	StatusCode int
	Exposed    bool
	Kind       SensitiveKind
	Note       string
}

// Finding 是最终报告里的一条结论。
type Finding struct {
	Endpoint    string        `json:"endpoint"`
	Transport   Transport     `json:"transport"`
	Service     string        `json:"service,omitempty"`
	Method      string        `json:"method,omitempty"`
	Kind        SensitiveKind `json:"kind"`
	Severity    Severity      `json:"severity"`
	Exposure    ExposureLevel `json:"exposure"`
	Confidence  float64       `json:"confidence"`
	Source      MethodSource  `json:"method_source,omitempty"`
	GRPCCode    string        `json:"grpc_code,omitempty"`
	Description string        `json:"description"`
	Evidence    []string      `json:"evidence,omitempty"`
}

// Report 是一次扫描的完整输出。
type Report struct {
	ScanID        string      `json:"scan_id"`
	StartedAt     time.Time   `json:"started_at"`
	FinishedAt    time.Time   `json:"finished_at"`
	Targets       int         `json:"targets"`
	LiveEndpoints int         `json:"live_endpoints"`
	Findings      []Finding   `json:"findings"`
	Endpoints     []*Endpoint `json:"endpoints,omitempty"` // 详细清单（-v）
	Stats         ScanStats   `json:"stats"`
}

// ScanStats 汇总计数。
type ScanStats struct {
	TCPProbed         int `json:"tcp_probed"`
	GRPCIdentified    int `json:"grpc_identified"`
	ReflectionOpen    int `json:"reflection_open"`
	MethodsEnumerated int `json:"methods_enumerated"`
	MethodsGuessed    int `json:"methods_guessed"`
	MethodsProbed     int `json:"methods_probed"`
	MethodsSkipped    int `json:"methods_skipped"`
	UnauthFindings    int `json:"unauth_findings"`
	HTTPAdminExposed  int `json:"http_admin_exposed"`
}

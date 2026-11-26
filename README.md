# rpcrecon — 内网 RPC 服务暴露面探测工具

面向"几百个 Go 微服务、地址端口动态变化、反射与管理接口混部"场景的**授权安全测试**工具。
自动发现 gRPC 服务、枚举方法、识别可未授权调用的敏感方法，且**保证探测本身不触发任何业务副作用**。

> 仅用于获得书面授权的内部安全评估。所有探测流量带 `rpcrecon` 标识，内置网段白名单与目标上限，防止误扫。

---

## 1. 它解决什么问题

| 现状风险 | 工具的对应能力 |
|---|---|
| 服务多、地址端口动态 | CIDR/端口规格/目标文件 + 注册中心适配器接口（`discover.RegistryAdapter`） |
| 开了反射，连上就能列方法 | 自动调用 reflection v1/v1alpha 拉全量服务与方法，反射开放本身记为一条发现 |
| 管理方法与业务方法同端口、漏配鉴权 | 逐方法做未授权可达性判定，按严重程度输出 FlushAll/UpdateConfig 等高危项 |
| 关了反射 | 先查本地 FileDescriptorSet（精确 schema），再退回字典猜测（返回码验证存在性） |
| 探测不能触发副作用 | 只发**必然解码失败的非法 protobuf 字节**，handler 业务体不可能执行（见第 3 节） |
| 同端口 HTTP 管理面（pprof/metrics） | 只读 GET 探测，动作型路径强制拒绝 |

## 2. 快速开始

```bash
# 编译
go build -o rpcrecon ./cmd/rpcrecon
go build -o rpcrecon-testserver ./cmd/testserver   # 本地靶场

# 最常见用法：扫一个授权网段的常见 gRPC 端口
./rpcrecon --cidr 10.20.0.0/22 --ports 50051,9000-9100 \
  --allow-cidr 10.20.0.0/22 --output report.json --verbose

# 扫描注册中心导出的实例清单
./rpcrecon --target-file instances.txt --allow-cidr 10.0.0.0/8

# 反射关闭时：提供描述文件目录 + 自定义猜测字典
./rpcrecon --target 10.20.1.5:50051 --allow-cidr 10.0.0.0/8 \
  --descriptors ./descriptors --dictionary configs/dictionary.example.json

# 只生成探测计划，不建立任何连接（评审探测范围时用）
./rpcrecon --cidr 10.20.0.0/24 --ports 50051 --dry-run
```

退出码：`0` 无未授权发现；`2` 发现未授权敏感面（可直接接入巡检流水线）；`1` 运行错误。

## 3. 安全模型：为什么探测不会触发副作用

这是整个工具的设计核心，机制有三层、互相独立：

### 3.1 载荷层：非法 wire 字节

每个一元方法只发送固定载荷 `0xFF`。它作为 protobuf varint 首字节声称"后面还有 9 个续接字节"，
但载荷只有 1 个字节，**任何标准 protobuf 实现都必然解码失败**。gRPC 服务端的执行顺序是：

```
传输 → 拦截器(鉴权) → 路由 → 解码请求体 → 业务 handler
                                  ↑ 0xFF 在这里报错，handler 永远拿不到请求
```

- 拦截器先返回 `Unauthenticated/PermissionDenied` → 方法有鉴权；
- 请求越过鉴权后在解码阶段返回 `Internal: cannot parse invalid wire-format data` → 方法未授权可触达，但业务体没执行。

线上内容类型仍是标准 `application/grpc`（通过 `ForceCodec(rawCodec) + CallContentSubtype("proto")` 实现），
服务端按正常 proto 流程处理，不会因为内容类型异常走别的代码路径。

### 3.2 基线层：先打一个不存在的方法

每个端点先调用 `/__rpcrecon__/BaselineProbe`（同样发 0xFF）：

- 基线返回鉴权错误 → 存在**全局前置鉴权**，所有方法直接标记 authenticated，不再逐方法发请求；
- 基线返回 `Unimplemented` → 请求能到路由层，不存在全局鉴权，逐方法结果才有区分度。

### 3.3 策略层：默认保守的硬约束（`internal/safe`）

- 流式方法**默认完全不调用**（半条客户端流就可能触发业务逻辑）；
- 空的"合法消息"探测默认关闭，即使显式开启，变异类方法仍强制只用非法载荷；
- HTTP 只允许 GET，路径含 `FLUSH/RESET/SHUTDOWN/...` 动作片段一律拒绝；
- 授权网段白名单 + 拒绝网段（deny 优先）+ 目标数硬上限 + 拒绝 `/16` 以上大网段；
- 主机名目标未解析为 IP 前拒绝（防 DNS rebinding 绕过网段策略）。

靶场测试用一个原子计数器验证：完整扫描结束后 `FlushAll` 业务体执行次数恒为 0。

## 4. 判定矩阵

| 方法返回码 | 含义 | 结论 |
|---|---|---|
| `Unauthenticated` / `PermissionDenied` | 鉴权层拦截 | `authenticated`（已防护） |
| `Internal` / `InvalidArgument` / `FailedPrecondition` | 越过鉴权，解码/校验失败 | **`unauthenticated`（发现项）** |
| `Unimplemented` | 猜测模式：方法不存在 | `skipped`（不计发现） |
| `Unimplemented`（反射/描述符声称存在） | 网关裁剪等异常 | `inconclusive`（人工复核） |
| `OK` | 非法载荷竟然成功，服务可能用自定义编解码 | `inconclusive` 低置信度，强制人工 |
| `Unavailable` / `DeadlineExceeded` | 网络/网关层阻断 | `blocked` |

## 5. 架构

```
cmd/rpcrecon            CLI（pflag）
internal/
  discover    目标生成：CIDR/端口/文件/注册中心接口，全部经过 safe 校验
  safe        安全策略：网段授权、载荷裁决、HTTP 路径白名单（无可商量的硬约束）
  ratelimit   全局并发信号量 + 每主机并发 + 全局 QPS 令牌桶
  grpcx       rawCodec 透传编解码、h2c/h2 传输指纹、无 stub 原始调用
  reflection  reflection v1/v1alpha 客户端，FileDescriptorProto 递归拉取
  descriptors 本地 FileDescriptorSet 加载（protoc/buf 产物）
  guess       服务名×方法名笛卡尔积字典，候选上限保护
  classify    关键词/正则/服务名三层敏感规则，内置 + 外部 JSON 扩展
  probe       基线探测 + 逐方法无害探测 + 判定矩阵
  httpadmin   同端口 pprof/metrics/healthz 只读 GET 探测
  scan        流水线编排、并发控制、Finding 归并排序
  report      终端文本 + JSON 报告
  model       全链路数据结构
  testutil/harness  进程内靶场（裸奔 AdminService + 受保护 BizService + 反射 + pprof）
```

## 6. 测试

```bash
go test -race ./...
```

覆盖安全策略、判定矩阵、分类规则、目标枚举边界、字典去重、描述文件解析、
反射 v1 枚举、rawCodec 线上载荷行为，以及两条完整 e2e（反射模式 / 关反射猜测模式），
e2e 内含"副作用计数器为 0"的硬性断言。

## 7. 已知边界（刻意保守带来的漏报）

1. **流式方法默认不探测**，只在报告里标记，需要人工确认后可用 `--probe-streaming` 放开（仍只发非法字节，但首帧可能触发服务端流初始化逻辑）。
2. **自定义编解码的服务**（非 proto）可能让 0xFF 不报错，工具会把 `OK` 降级为 inconclusive 而非误报。
3. **应用层内部鉴权**（拦截器放行、handler 内部自己查权限）无法从外部区分，会被判为未授权可触达——这对攻击面评估仍是正确结论（攻击者确实能进入 handler）。
4. 字典猜测的召回率取决于字典质量；生产建议把各服务仓库的 `.proto`/`buf image` 收集到 `--descriptors` 目录，优先走精确 schema。
5. 注册中心适配只定义了接口，etcd/nacos/consul/k8s 的具体实现需要按内网环境补一个适配器（实现 `List(ctx)` 即可）。

## 8. 修复建议（发现问题之后）

- 管理接口与业务接口**端口/监听器分离**，管理面绑定内网管理网段或加 mTLS；
- 拦截器做**默认拒绝**（default-deny），按方法白名单放行，而不是按服务黑名单拦截；
- 生产环境关闭 reflection，或给 reflection 本身挂鉴权拦截器；
- pprof/metrics/healthz 走独立管理端口，不与业务流量复用 listener；
- 把本工具接入发布后的巡检流水线，退出码 2 阻断高危服务上线。

// Package grpcx 封装探测工具用到的底层 gRPC 能力：
//   - rawCodec：透传字节的客户端编解码器（配合 CallContentSubtype("proto")，
//     线上内容类型仍是标准 application/grpc，服务端按 proto 解码并必然失败）
//   - 拨号与传输层指纹识别（明文 h2c / TLS h2）
//   - 不依赖任何业务 stub 的通用一元调用
package grpcx

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

// rawCodec 是一个只在客户端注册的透传编解码器。
//
// 关键：Marshal 原样返回字节、Unmarshal 原样接收字节，不做任何 proto 解析。
// 配合 grpc.CallContentSubtype("proto")，线上 Content-Type 仍是
// "application/grpc"，服务端会用自己的标准 proto 编解码器处理请求体——
// 我们发出的 0xFF 在服务端解码阶段就会报错，业务 handler 永远不会运行。
type rawCodec struct{}

func (rawCodec) Name() string { return "rpcrecon_raw" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	switch b := v.(type) {
	case []byte:
		return b, nil
	case *[]byte:
		return *b, nil
	default:
		return nil, errors.New("rawCodec 只接受 []byte 载荷")
	}
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	switch b := v.(type) {
	case *[]byte:
		*b = append((*b)[:0], data...)
		return nil
	default:
		return errors.New("rawCodec 只支持 *[]byte 输出")
	}
}

// 注册一次即可，进程内全局生效；不覆盖 "proto"，不影响反射客户端。
func init() {
	encoding.RegisterCodec(rawCodec{})
}

// Dial 建立到目标的 gRPC 连接。tlsEnabled=true 时先尝试 TLS（ALPN h2），
// 否则使用 h2c 明文。调用方负责 Close。
func Dial(ctx context.Context, addr string, tlsEnabled bool, serverName string) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}
	if tlsEnabled {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// 内网自签证书普遍存在，探测场景默认不校验证书链（只做传输指纹）
			InsecureSkipVerify: true, //nolint:gosec // 内网探测工具，仅连接不传输凭据
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS12,
		})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return grpc.DialContext(dialCtx, addr, opts...)
}

// Fingerprint 对一个 TCP 可达的地址做传输层指纹：
// 依次尝试 h2c 明文与 TLS-h2，返回识别到的形态。
// 超时控制由 ctx 负责。
func Fingerprint(ctx context.Context, addr string) (transport string, tlsEnabled bool, conn *grpc.ClientConn, err error) {
	// 先明文，失败再 TLS，适配大多数内网 Go 服务（明文占多数）
	if conn, err = Dial(ctx, addr, false, ""); err == nil {
		return "grpc", false, conn, nil
	}
	plainErr := err
	if conn, err = Dial(ctx, addr, true, serverNameFromAddr(addr)); err == nil {
		return "grpcs", true, conn, nil
	}
	return "unknown", false, nil, errors.Join(plainErr, err)
}

func serverNameFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// InvokeRaw 发起一次不依赖 stub 的一元调用，请求体原样发送。
//
// 调用选项固定 ForceCodec(rawCodec{}) + CallContentSubtype("proto")，
// 保证线上内容类型为标准 application/grpc。返回服务端的状态码与消息。
func InvokeRaw(ctx context.Context, conn *grpc.ClientConn, method string, payload []byte, headers map[string]string) (rawResp []byte, grpcStatus string, statusCode uint32, statusMsg string, err error) {
	opts := []grpc.CallOption{
		grpc.ForceCodec(rawCodec{}),
		grpc.CallContentSubtype("proto"),
		grpc.WaitForReady(false),
	}
	if md := makeMetadata(headers); len(md) > 0 {
		ctx = withOutgoingMetadata(ctx, md)
	}
	var resp []byte
	err = conn.Invoke(ctx, method, payload, &resp, opts...)
	rawResp = resp
	grpcStatus, statusCode, statusMsg = splitStatus(err)
	return
}

// 用 strings 拼一个简单的状态名，避免上层再 import codes/status
func splitStatus(err error) (string, uint32, string) {
	if err == nil {
		return "OK", 0, ""
	}
	// grpc/status.FromError 能解析标准 gRPC 错误
	return statusFromError(err)
}

// 去掉可能的 "rpc error: code = xxx desc = " 前缀，保留原始描述
func sanitize(s string) string {
	return strings.TrimSpace(s)
}

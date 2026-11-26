package grpcx

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// statusFromError 把任意错误归一化为 (状态名, 状态码, 描述)。
func statusFromError(err error) (string, uint32, string) {
	if err == nil {
		return "OK", 0, ""
	}
	st, ok := status.FromError(err)
	if !ok {
		return codes.Unknown.String(), uint32(codes.Unknown), sanitize(err.Error())
	}
	return st.Code().String(), uint32(st.Code()), sanitize(st.Message())
}

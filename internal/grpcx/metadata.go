package grpcx

import (
	"context"

	"google.golang.org/grpc/metadata"
)

func makeMetadata(headers map[string]string) metadata.MD {
	if len(headers) == 0 {
		return nil
	}
	md := metadata.MD{}
	for k, v := range headers {
		md.Set(k, v)
	}
	return md
}

func withOutgoingMetadata(ctx context.Context, md metadata.MD) context.Context {
	if len(md) == 0 {
		return ctx
	}
	// 只带工具自身的标识头，绝不携带任何凭据/令牌
	return metadata.NewOutgoingContext(ctx, md)
}

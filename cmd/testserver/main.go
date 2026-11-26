// rpcrecon-testserver 是手动联调用的靶场进程，逻辑复用 testutil/harness。
// harness 内部使用随机端口，启动后会打印实际 gRPC/HTTP 地址。
package main

import (
	"flag"
	"log"

	"github.com/internal/rpcrecon/internal/testutil/harness"
)

func main() {
	grpcPort := flag.Int("grpc-port", 50090, "文档用途：harness 实际使用随机端口")
	httpPort := flag.Int("http-port", 50091, "文档用途：harness 实际使用随机端口")
	flag.Parse()

	h, err := harness.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("靶场已启动（请求端口 grpc=%d http=%d 仅作文档标注）", *grpcPort, *httpPort)
	log.Printf("gRPC 实际地址: %s", h.GRPCAddr)
	log.Printf("HTTP 实际地址: %s", h.HTTPAddr)

	select {} // 保持进程存活，Ctrl-C 退出
}

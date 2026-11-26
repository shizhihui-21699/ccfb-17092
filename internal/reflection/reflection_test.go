package reflection_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/internal/rpcrecon/internal/reflection"
	"github.com/internal/rpcrecon/internal/testutil/harness"
)

func TestEnumerateViaReflectionV1(t *testing.T) {
	h, err := harness.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, h.GRPCAddr,
		grpc.WithBlock(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	res, err := reflection.Enumerate(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Status.Enabled || !res.Status.Unauth || !res.Status.V1 {
		t.Fatalf("反射状态错误: %+v", res.Status)
	}

	byName := map[string]*struct{ methods int }{}
	for _, svc := range res.Services {
		byName[svc.Name] = &struct{ methods int }{methods: len(svc.Methods)}
	}
	admin, ok := byName[harness.AdminService]
	if !ok {
		t.Fatalf("未枚举到 AdminService: %v", byName)
	}
	if admin.methods != 3 {
		t.Fatalf("AdminService 应有 3 个方法，得到 %d", admin.methods)
	}
	biz, ok := byName[harness.BizService]
	if !ok || biz.methods != 1 {
		t.Fatalf("BizService 枚举错误: %+v", byName)
	}

	// 方法细节校验：流标记、全限定名
	for _, svc := range res.Services {
		for _, m := range svc.Methods {
			if m.FullName != "/"+svc.Name+"/"+m.Name {
				t.Fatalf("方法全限定名格式错误: %s", m.FullName)
			}
			if m.InputType == "" || m.OutputType == "" {
				t.Fatalf("方法输入输出类型缺失: %s", m.FullName)
			}
		}
	}
}

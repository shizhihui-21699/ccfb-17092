package probe

import (
	"testing"

	"github.com/internal/rpcrecon/internal/model"
)

func newTestEngine() *Engine {
	return &Engine{}
}

func TestJudgeMatrix(t *testing.T) {
	e := newTestEngine()
	sensitive := &model.MethodInfo{
		FullName:  "/admin.AdminService/FlushAll",
		Name:      "FlushAll",
		Source:    model.SourceReflection,
		Sensitive: &model.SensitiveMatch{Kind: model.KindCache},
	}
	guessed := &model.MethodInfo{
		FullName: "/admin.AdminService/MaybeExists",
		Name:     "MaybeExists",
		Source:   model.SourceGuess,
	}

	t.Run("解码错误=未授权可触达", func(t *testing.T) {
		exposure, conf, _ := e.judge("Internal", "Unimplemented", sensitive)
		if exposure != model.ExposureUnauthenticated || conf < 0.9 {
			t.Fatalf("得到 %s/%.2f", exposure, conf)
		}
	})

	t.Run("InvalidArgument 同样判穿透", func(t *testing.T) {
		exposure, _, _ := e.judge("InvalidArgument", "Unimplemented", sensitive)
		if exposure != model.ExposureUnauthenticated {
			t.Fatalf("得到 %s", exposure)
		}
	})

	t.Run("鉴权错误=已防护", func(t *testing.T) {
		exposure, _, _ := e.judge("Unauthenticated", "Unimplemented", sensitive)
		if exposure != model.ExposureAuthenticated {
			t.Fatalf("得到 %s", exposure)
		}
		exposure, _, _ = e.judge("PermissionDenied", "Unimplemented", sensitive)
		if exposure != model.ExposureAuthenticated {
			t.Fatalf("PermissionDenied 应判已防护，得到 %s", exposure)
		}
	})

	t.Run("猜测方法返回Unimplemented=跳过且不算发现", func(t *testing.T) {
		exposure, _, _ := e.judge("Unimplemented", "Unimplemented", guessed)
		if exposure != model.ExposureSkipped {
			t.Fatalf("得到 %s", exposure)
		}
	})

	t.Run("schema方法返回Unimplemented=存疑人工复核", func(t *testing.T) {
		exposure, _, _ := e.judge("Unimplemented", "Unimplemented", sensitive)
		if exposure != model.ExposureInconclusive {
			t.Fatalf("得到 %s", exposure)
		}
	})

	t.Run("全局鉴权基线下一切判已防护", func(t *testing.T) {
		exposure, _, _ := e.judge("Unknown", "Unauthenticated", sensitive)
		if exposure != model.ExposureAuthenticated {
			t.Fatalf("基线为全局鉴权时应判已防护，得到 %s", exposure)
		}
	})

	t.Run("OK返回必须存疑并降级", func(t *testing.T) {
		exposure, conf, _ := e.judge("OK", "Unimplemented", sensitive)
		if exposure != model.ExposureInconclusive || conf > 0.5 {
			t.Fatalf("OK 必须 inconclusive 且低置信度，得到 %s/%.2f", exposure, conf)
		}
	})

	t.Run("网络错误判阻断", func(t *testing.T) {
		for _, code := range []string{"Unavailable", "DeadlineExceeded"} {
			exposure, _, _ := e.judge(code, "Unimplemented", sensitive)
			if exposure != model.ExposureBlocked {
				t.Fatalf("%s 应判 blocked，得到 %s", code, exposure)
			}
		}
	})
}

func TestBaselineIsGlobalAuth(t *testing.T) {
	if !BaselineIsGlobalAuth("Unauthenticated") || !BaselineIsGlobalAuth("PermissionDenied") {
		t.Fatal("鉴权类基线必须识别为全局鉴权")
	}
	if BaselineIsGlobalAuth("Unimplemented") || BaselineIsGlobalAuth("Internal") {
		t.Fatal("路由/解码类基线不是全局鉴权")
	}
}

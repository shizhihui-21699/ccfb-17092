package scan_test

import (
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"
	"grpcscope/internal/descriptors"
)

func loadDemoDescriptors(t *testing.T) (*protoregistry.Files, error) {
	t.Helper()
	p, err := filepath.Abs("../../testdata/demo.proto")
	if err != nil {
		return nil, err
	}
	reg, err := descriptors.Load([]string{p}, nil)
	if err != nil {
		return nil, err
	}
	return reg.Files, nil
}

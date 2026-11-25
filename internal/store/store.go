// Package store persists scan results so a scan can be compared against the
// inventory recorded on an earlier date. Dynamic addresses and ports mean the
// interesting question is often "what changed", which needs history on disk.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"grpcscope/internal/model"
)

// Dir is the directory layout for persisted scans.
type Dir struct {
	Root string
}

// New returns a store rooted at dir.
func New(dir string) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create result dir %q: %w", dir, err)
	}
	return &Dir{Root: dir}, nil
}

// Save writes the scan as JSON under the scan's start timestamp. It returns the
// path written.
func (d *Dir) Save(scan *model.Scan) (string, error) {
	stamp := scan.Meta.StartedAt.Format("20060102-150405")
	name := fmt.Sprintf("scan-%s.json", stamp)
	path := filepath.Join(d.Root, name)

	b, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode scan: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", fmt.Errorf("write scan: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("publish scan: %w", err)
	}
	return path, nil
}

// Latest returns the most recently written scan, or nil when none exists.
func (d *Dir) Latest() (*model.Scan, string, error) {
	entries, err := os.ReadDir(d.Root)
	if err != nil {
		return nil, "", err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if len(e.Name()) < 5 || e.Name()[:5] != "scan-" {
			continue
		}
		files = append(files, e.Name())
	}
	if len(files) == 0 {
		return nil, "", nil
	}
	sort.Strings(files)
	path := filepath.Join(d.Root, files[len(files)-1])
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	scan := new(model.Scan)
	if err := json.Unmarshal(b, scan); err != nil {
		return nil, "", fmt.Errorf("decode %q: %w", path, err)
	}
	return scan, path, nil
}

// Load reads a specific scan file.
func (d *Dir) Load(path string) (*model.Scan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	scan := new(model.Scan)
	if err := json.Unmarshal(b, scan); err != nil {
		return nil, fmt.Errorf("decode %q: %w", path, err)
	}
	return scan, nil
}

// Change is one difference between two scans, keyed on endpoint address and
// method full name.
type Change struct {
	Kind     string // endpoint-appeared, endpoint-disappeared, method-appeared, method-disappeared, auth-changed, protocol-changed
	Addr     string
	Method   string
	Before   string
	After    string
	Severity string
	Note     string
}

// Diff compares two scans. It is organised by address, because that is the
// stable key even when a service moves behind a new port during a rolling
// deploy.
func Diff(old, new *model.Scan) []Change {
	oldByAddr := map[string]*model.Endpoint{}
	for i := range old.Endpoints {
		oldByAddr[old.Endpoints[i].Addr] = &old.Endpoints[i]
	}
	newByAddr := map[string]*model.Endpoint{}
	for i := range new.Endpoints {
		newByAddr[new.Endpoints[i].Addr] = &new.Endpoints[i]
	}

	var out []Change
	for addr, n := range newByAddr {
		o, ok := oldByAddr[addr]
		if !ok {
			if n.Protocol == model.ProtoGRPC {
				out = append(out, Change{Kind: "endpoint-appeared", Addr: addr,
					After: string(n.Protocol), Severity: "info",
					Note: fmt.Sprintf("new gRPC endpoint with %d method(s)", countMethods(n))})
			} else {
				out = append(out, Change{Kind: "endpoint-appeared", Addr: addr,
					After: string(n.Protocol), Severity: "info"})
			}
			continue
		}
		if o.Protocol != n.Protocol {
			out = append(out, Change{Kind: "protocol-changed", Addr: addr,
				Before: string(o.Protocol), After: string(n.Protocol), Severity: "info"})
		}
		om := methodsByFullName(o)
		nm := methodsByFullName(n)
		for k, m := range nm {
			prev, ok := om[k]
			if !ok {
				sev := "info"
				if m.Risk.Level == model.RiskMutating || m.Risk.Level == model.RiskDestructive {
					sev = "medium"
				}
				out = append(out, Change{Kind: "method-appeared", Addr: addr, Method: k,
					After: string(m.Auth), Severity: sev,
					Note: "new " + string(m.Risk.Level) + " method"})
				continue
			}
			if prev.Auth != m.Auth {
				sev := "info"
				if m.Auth == model.AuthProvenOpen || m.Auth == model.AuthInferredOpen {
					sev = "high"
				}
				out = append(out, Change{Kind: "auth-changed", Addr: addr, Method: k,
					Before: string(prev.Auth), After: string(m.Auth), Severity: sev})
			}
		}
		for k := range om {
			if _, ok := nm[k]; !ok {
				out = append(out, Change{Kind: "method-disappeared", Addr: addr, Method: k, Severity: "info"})
			}
		}
	}
	for addr := range oldByAddr {
		if _, ok := newByAddr[addr]; !ok {
			out = append(out, Change{Kind: "endpoint-disappeared", Addr: addr, Severity: "info"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevOrder(out[i].Severity), sevOrder(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func countMethods(ep *model.Endpoint) int {
	n := 0
	for _, s := range ep.Services {
		n += len(s.Methods)
	}
	return n
}

func methodsByFullName(ep *model.Endpoint) map[string]*model.Method {
	out := map[string]*model.Method{}
	for si := range ep.Services {
		for mi := range ep.Services[si].Methods {
			out[ep.Services[si].Methods[mi].FullName] = &ep.Services[si].Methods[mi]
		}
	}
	return out
}

func sevOrder(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 1
}

// Now is exported so callers share one clock reading.
func Now() time.Time { return time.Now() }

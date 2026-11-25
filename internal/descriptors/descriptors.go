// Package descriptors turns .proto sources and compiled FileDescriptorSet
// files into a registry the scanner can consult when reflection is absent.
//
// This is the "描述文件" path from the operator's toolchain: a company that
// builds Go services from .proto files can feed the scanner the same sources,
// giving exact method names, shapes and input fields for every service they
// own — no guessing required.
package descriptors

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Registry is the union of everything we could compile.
type Registry struct {
	Files *protoregistry.Files
	// Sources are the inputs that contributed, for the report's provenance.
	Sources []string
}

// Empty returns a registry with no files, so callers can treat "no descriptors
// configured" uniformly.
func Empty() *Registry {
	return &Registry{Files: new(protoregistry.Files)}
}

// Load compiles proto sources and descriptor sets and merges them. Problems
// with individual sets are returned, since a malformed descriptor set is an
// operator error worth surfacing rather than silently tolerating.
func Load(protoPaths, setPaths []string) (*Registry, error) {
	reg := Empty()

	var protoFiles []string
	for _, p := range protoPaths {
		expanded, err := expandProtoPath(p)
		if err != nil {
			return nil, err
		}
		protoFiles = append(protoFiles, expanded...)
	}
	if len(protoFiles) > 0 {
		compiled, names, err := compileProtos(protoFiles)
		if err != nil {
			return nil, err
		}
		merged, err := merge(reg.Files, compiled)
		if err != nil {
			return nil, err
		}
		reg.Files = merged
		reg.Sources = append(reg.Sources, names...)
	}

	for _, sp := range setPaths {
		b, err := os.ReadFile(sp)
		if err != nil {
			return nil, fmt.Errorf("read descriptor set %q: %w", sp, err)
		}
		set := &descriptorpb.FileDescriptorSet{}
		if err := proto.Unmarshal(b, set); err != nil {
			return nil, fmt.Errorf("parse descriptor set %q: %w", sp, err)
		}
		merged, err := mergeProtos(reg.Files, set.File)
		if err != nil {
			return nil, err
		}
		reg.Files = merged
		for _, fdp := range set.File {
			reg.Sources = append(reg.Sources, fdp.GetName())
		}
	}

	return reg, nil
}

// expandProtoPath accepts a file or a directory of .proto files.
func expandProtoPath(p string) ([]string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("descriptor path %q: %w", p, err)
	}
	if !st.IsDir() {
		return []string{p}, nil
	}
	var out []string
	err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".proto") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// compileProtos walks each source's directory and ancestors down to a common
// root and hands protocompile those as import paths, which covers both flat
// single-directory trees and repo/pkg/proto layouts.
func compileProtos(files []string) (*protoregistry.Files, []string, error) {
	importPaths, rel, err := planImportPaths(files)
	if err != nil {
		return nil, nil, err
	}

	c := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: importPaths,
		}),
	}
	compiled, err := c.Compile(context.Background(), rel...)
	if err != nil {
		return nil, nil, fmt.Errorf("compile protos: %w", err)
	}

	var fds []protoreflect.FileDescriptor
	var names []string
	for _, f := range compiled {
		fds = append(fds, f)
		names = append(names, f.Path())
	}
	return mergeFiles(fds), names, nil
}

func planImportPaths(files []string) (importPaths, rel []string, err error) {
	// One import root per source directory, plus its ancestors. Extra roots are
	// harmless: protocompile pairs each file with the first root that yields a
	// non-relative path.
	seen := map[string]bool{}
	for _, f := range files {
		dir, err := filepath.Abs(filepath.Dir(f))
		if err != nil {
			return nil, nil, err
		}
		for i := 0; i < 4; i++ {
			if !seen[dir] {
				seen[dir] = true
				importPaths = append(importPaths, dir)
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			return nil, nil, err
		}
		placed := false
		for _, ip := range importPaths {
			r, err := filepath.Rel(ip, abs)
			if err != nil || strings.HasPrefix(r, "..") {
				continue
			}
			rel = append(rel, filepath.ToSlash(r))
			placed = true
			break
		}
		if !placed {
			return nil, nil, fmt.Errorf("cannot place %q on an import path", f)
		}
	}
	return importPaths, rel, nil
}

// mergeFiles registers already-linked files into a fresh registry, keeping the
// first definition of each path.
func mergeFiles(fds []protoreflect.FileDescriptor) *protoregistry.Files {
	out := new(protoregistry.Files)
	for _, fd := range fds {
		_ = out.RegisterFile(fd)
	}
	return out
}

// merge combines an existing registry with more linked files.
func merge(into *protoregistry.Files, more *protoregistry.Files) (*protoregistry.Files, error) {
	out := new(protoregistry.Files)
	first := true
	var err error
	into.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if e := out.RegisterFile(fd); e != nil && first {
			err = e
			first = false
		}
		return true
	})
	more.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		_ = out.RegisterFile(fd) // first definition wins
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mergeProtos links raw FileDescriptorProtos and merges them into a registry,
// iterating until every file whose dependencies are present has been linked.
func mergeProtos(into *protoregistry.Files, protos []*descriptorpb.FileDescriptorProto) (*protoregistry.Files, error) {
	out, err := merge(into, new(protoregistry.Files))
	if err != nil {
		return nil, err
	}

	pending := append([]*descriptorpb.FileDescriptorProto(nil), protos...)
	for len(pending) > 0 {
		var next []*descriptorpb.FileDescriptorProto
		progress := false
		for _, fdp := range pending {
			if _, err := out.FindFileByPath(fdp.GetName()); err == nil {
				progress = true
				continue
			}
			deps := new(protoregistry.Files)
			ready := true
			for _, d := range fdp.GetDependency() {
				fd, err := out.FindFileByPath(d)
				if err != nil {
					fd, err = protoregistry.GlobalFiles.FindFileByPath(d)
					if err != nil {
						ready = false
						break
					}
				}
				_ = deps.RegisterFile(fd)
			}
			if !ready {
				next = append(next, fdp)
				continue
			}
			fd, err := protodesc.NewFile(fdp, deps)
			if err != nil {
				return nil, fmt.Errorf("link %q: %w", fdp.GetName(), err)
			}
			if err := out.RegisterFile(fd); err != nil {
				// Already present or conflicting; first definition wins.
				progress = true
				continue
			}
			progress = true
		}
		if !progress {
			// Any leftovers reference files we cannot supply; report the first
			// so the operator knows which import is missing.
			for _, fdp := range next {
				for _, d := range fdp.GetDependency() {
					if _, err := out.FindFileByPath(d); err != nil {
						if _, err2 := protoregistry.GlobalFiles.FindFileByPath(d); err2 != nil {
							return nil, fmt.Errorf("%q imports %q, which is neither supplied nor a standard import", fdp.GetName(), d)
						}
					}
				}
			}
			break
		}
		pending = next
	}
	return out, nil
}

// Package target expands the configured target description into a concrete
// list of host:port addresses.
package target

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"grpcscope/internal/config"
	"grpcscope/internal/wordlist"
)

// Target is one address to probe.
type Target struct {
	Addr string
	Host string
	Port int
	// Source says how it was produced, for the report's provenance.
	Source string
}

// Expand turns the config's target section into addresses. It never sends a
// packet; resolution and CIDR walking are local operations.
func Expand(t config.Targets) ([]Target, error) {
	seen := map[string]bool{}
	var out []Target

	add := func(addr, source string) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// Bare host without port: this is a config mistake in Addresses,
			// but tolerate it by pairing with the default port list.
			return
		}
		p, err := net.LookupPort("tcp", port)
		if err != nil {
			return
		}
		key := net.JoinHostPort(host, fmt.Sprint(p))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Target{Addr: key, Host: host, Port: p, Source: source})
	}

	for _, a := range t.Addresses {
		add(strings.TrimSpace(a), "address")
	}

	for _, f := range t.Files {
		list, err := wordlist.LoadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range list {
			add(line, "file:"+f)
		}
	}

	ports := t.Ports
	if len(ports) == 0 {
		ports = []int{50051}
	}
	sort.Ints(ports)

	for _, cidr := range t.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", cidr, err)
		}
		if !prefix.IsValid() {
			return nil, fmt.Errorf("cidr %q is invalid", cidr)
		}
		// Guard against a mistyped /8 turning into 16 million probes.
		prefix = prefix.Masked()
		if bits := prefix.Bits(); bits < 16 {
			return nil, fmt.Errorf("cidr %q spans more than /16; split it explicitly", cidr)
		}
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if !addr.IsValid() {
				break
			}
			host := addr.String()
			for _, p := range ports {
				a := net.JoinHostPort(host, fmt.Sprint(p))
				if seen[a] {
					continue
				}
				seen[a] = true
				out = append(out, Target{Addr: a, Host: host, Port: p, Source: "cidr:" + cidr})
			}
		}
	}

	for _, h := range t.Hosts {
		host := strings.TrimSpace(h)
		if host == "" {
			continue
		}
		for _, p := range ports {
			a := net.JoinHostPort(host, fmt.Sprint(p))
			if seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, Target{Addr: a, Host: host, Port: p, Source: "host:" + host})
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no targets: set addresses, files, cidrs or hosts")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

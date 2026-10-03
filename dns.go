package twoblade

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

type SrvTarget struct {
	Host string
	Port int
	IP   string
}

// ResolveSrv finds the SHARP endpoint for a domain via DNS SRV records
// ponytail: caching omitted; add when facing high outbound email volume
func ResolveSrv(ctx context.Context, domain string) (*SrvTarget, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	resolver := net.DefaultResolver

	_, addrs, err := resolver.LookupSRV(ctx, "sharp", "tcp", d)
	if err == nil && len(addrs) > 0 {
		sort.Slice(addrs, func(i, j int) bool {
			if addrs[i].Priority == addrs[j].Priority {
				return addrs[i].Weight > addrs[j].Weight
			}
			return addrs[i].Priority < addrs[j].Priority
		})
		target := strings.TrimSuffix(addrs[0].Target, ".")
		ips, err := resolver.LookupHost(ctx, target)
		if err == nil && len(ips) > 0 {
			return &SrvTarget{Host: target, Port: int(addrs[0].Port), IP: ips[0]}, nil
		}
	}

	// Fallback to sharp.<domain>:DefaultSharpPort
	fallbackHost := "sharp." + d
	ips, err := resolver.LookupHost(ctx, fallbackHost)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("could not resolve SHARP endpoint for %s", domain)
	}
	return &SrvTarget{Host: fallbackHost, Port: DefaultSharpPort, IP: ips[0]}, nil
}

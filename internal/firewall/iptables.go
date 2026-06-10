package firewall

import (
	"context"
	"fmt"
)

type IPTables struct {
	Chain  string
	Runner Runner
}

func (f *IPTables) Setup(ctx context.Context) error {
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	if err := f.setupBin(ctx, "iptables"); err != nil {
		return err
	}
	_ = f.setupBin(ctx, "ip6tables")
	return nil
}

func (f *IPTables) setupBin(ctx context.Context, bin string) error {
	_ = f.Runner.Run(ctx, bin, "-t", "raw", "-N", f.Chain)
	if err := f.Runner.Run(ctx, bin, "-t", "raw", "-C", "PREROUTING", "-j", f.Chain); err != nil {
		if err := f.Runner.Run(ctx, bin, "-t", "raw", "-A", "PREROUTING", "-j", f.Chain); err != nil {
			return fmt.Errorf("%s setup failed: %w", bin, err)
		}
	}
	return nil
}

func (f *IPTables) Block(ctx context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	bin := "iptables"
	if isIPv6(ip) {
		bin = "ip6tables"
	}
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	if err := f.Runner.Run(ctx, bin, "-t", "raw", "-C", f.Chain, "-s", ip, "-j", "DROP"); err == nil {
		return nil
	}
	return f.Runner.Run(ctx, bin, "-t", "raw", "-A", f.Chain, "-s", ip, "-j", "DROP")
}

func (f *IPTables) Unblock(ctx context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	bin := "iptables"
	if isIPv6(ip) {
		bin = "ip6tables"
	}
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	for {
		if err := f.Runner.Run(ctx, bin, "-t", "raw", "-D", f.Chain, "-s", ip, "-j", "DROP"); err != nil {
			return nil
		}
	}
}

func (f *IPTables) DropConnections(ctx context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	_ = f.Runner.Run(ctx, "conntrack", "-D", "-s", ip)
	_ = f.Runner.Run(ctx, "conntrack", "-D", "-d", ip)
	return nil
}

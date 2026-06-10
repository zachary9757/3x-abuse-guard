package firewall

import (
	"context"
	"fmt"
)

type NFTables struct {
	Table  string
	Chain  string
	Runner Runner
}

const (
	nftSet4 = "blocked4"
	nftSet6 = "blocked6"
)

func (f *NFTables) Setup(ctx context.Context) error {
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	_ = f.Runner.Run(ctx, "nft", "add", "table", "inet", f.Table)
	_ = f.Runner.Run(ctx, "nft", "add", "set", "inet", f.Table, nftSet4, "{", "type", "ipv4_addr", ";", "}")
	_ = f.Runner.Run(ctx, "nft", "add", "set", "inet", f.Table, nftSet6, "{", "type", "ipv6_addr", ";", "}")
	_ = f.Runner.Run(ctx, "nft", "flush", "set", "inet", f.Table, nftSet4)
	_ = f.Runner.Run(ctx, "nft", "flush", "set", "inet", f.Table, nftSet6)
	_ = f.Runner.Run(ctx, "nft", "add", "chain", "inet", f.Table, f.Chain, "{", "type", "filter", "hook", "prerouting", "priority", "raw", ";", "policy", "accept", ";", "}")
	_ = f.Runner.Run(ctx, "nft", "flush", "chain", "inet", f.Table, f.Chain)
	if err := f.Runner.Run(ctx, "nft", "add", "rule", "inet", f.Table, f.Chain, "ip", "saddr", "@"+nftSet4, "drop"); err != nil {
		return err
	}
	if err := f.Runner.Run(ctx, "nft", "add", "rule", "inet", f.Table, f.Chain, "ip6", "saddr", "@"+nftSet6, "drop"); err != nil {
		return err
	}
	return nil
}

func (f *NFTables) Block(ctx context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	set := nftSet4
	if isIPv6(ip) {
		set = nftSet6
	}
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	if err := f.Runner.Run(ctx, "nft", "add", "element", "inet", f.Table, set, "{", ip, "}"); err != nil {
		return fmt.Errorf("nft block failed: %w", err)
	}
	return nil
}

func (f *NFTables) Unblock(ctx context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	set := nftSet4
	if isIPv6(ip) {
		set = nftSet6
	}
	if f.Runner == nil {
		f.Runner = ExecRunner{}
	}
	_ = f.Runner.Run(ctx, "nft", "delete", "element", "inet", f.Table, set, "{", ip, "}")
	return nil
}

func (f *NFTables) DropConnections(ctx context.Context, ip string) error {
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

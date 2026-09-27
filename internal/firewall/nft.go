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
	if err := f.ensureTable(ctx); err != nil {
		return err
	}
	if err := f.ensureSet(ctx, nftSet4, "ipv4_addr"); err != nil {
		return err
	}
	if err := f.ensureSet(ctx, nftSet6, "ipv6_addr"); err != nil {
		return err
	}
	if err := f.Runner.Run(ctx, "nft", "flush", "set", "inet", f.Table, nftSet4); err != nil {
		return fmt.Errorf("nft flush %s failed: %w", nftSet4, err)
	}
	if err := f.Runner.Run(ctx, "nft", "flush", "set", "inet", f.Table, nftSet6); err != nil {
		return fmt.Errorf("nft flush %s failed: %w", nftSet6, err)
	}
	if err := f.ensureChain(ctx); err != nil {
		return err
	}
	if err := f.Runner.Run(ctx, "nft", "flush", "chain", "inet", f.Table, f.Chain); err != nil {
		return fmt.Errorf("nft flush chain failed: %w", err)
	}
	if err := f.Runner.Run(ctx, "nft", "add", "rule", "inet", f.Table, f.Chain, "ip", "saddr", "@"+nftSet4, "drop"); err != nil {
		return err
	}
	if err := f.Runner.Run(ctx, "nft", "add", "rule", "inet", f.Table, f.Chain, "ip6", "saddr", "@"+nftSet6, "drop"); err != nil {
		return err
	}
	return nil
}

func (f *NFTables) ensureTable(ctx context.Context) error {
	if err := f.Runner.Run(ctx, "nft", "list", "table", "inet", f.Table); err == nil {
		return nil
	}
	if err := f.Runner.Run(ctx, "nft", "add", "table", "inet", f.Table); err != nil {
		return fmt.Errorf("nft create table failed: %w", err)
	}
	return nil
}

func (f *NFTables) ensureSet(ctx context.Context, name, addressType string) error {
	if err := f.Runner.Run(ctx, "nft", "list", "set", "inet", f.Table, name); err == nil {
		return nil
	}
	if err := f.Runner.Run(ctx, "nft", "add", "set", "inet", f.Table, name, "{", "type", addressType, ";", "}"); err != nil {
		return fmt.Errorf("nft create set %s failed: %w", name, err)
	}
	return nil
}

func (f *NFTables) ensureChain(ctx context.Context) error {
	if err := f.Runner.Run(ctx, "nft", "list", "chain", "inet", f.Table, f.Chain); err == nil {
		return nil
	}
	if err := f.Runner.Run(ctx, "nft", "add", "chain", "inet", f.Table, f.Chain, "{", "type", "filter", "hook", "prerouting", "priority", "raw", ";", "policy", "accept", ";", "}"); err != nil {
		return fmt.Errorf("nft create chain failed: %w", err)
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
	if err := f.Runner.Run(ctx, "nft", "get", "element", "inet", f.Table, set, "{", ip, "}"); err == nil {
		return nil
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
	if err := f.Runner.Run(ctx, "nft", "get", "element", "inet", f.Table, set, "{", ip, "}"); err != nil {
		return nil
	}
	if err := f.Runner.Run(ctx, "nft", "delete", "element", "inet", f.Table, set, "{", ip, "}"); err != nil {
		return fmt.Errorf("nft unblock failed: %w", err)
	}
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

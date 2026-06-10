package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
)

type Firewall interface {
	Setup(ctx context.Context) error
	Block(ctx context.Context, ip string) error
	Unblock(ctx context.Context, ip string) error
	DropConnections(ctx context.Context, ip string) error
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

func New(backend string, chain string) (Firewall, error) {
	if chain == "" {
		return nil, errors.New("firewall chain is required")
	}
	switch backend {
	case "iptables":
		return &IPTables{Chain: chain, Runner: ExecRunner{}}, nil
	case "nft":
		return &NFTables{Table: chain, Chain: chain, Runner: ExecRunner{}}, nil
	case "noop":
		return &Noop{}, nil
	default:
		return nil, fmt.Errorf("unsupported firewall backend: %s", backend)
	}
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ip: %s", ip)
	}
	return nil
}

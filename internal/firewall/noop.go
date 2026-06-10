package firewall

import "context"

type Noop struct {
	Blocked []string
}

func (n *Noop) Setup(context.Context) error { return nil }

func (n *Noop) Block(_ context.Context, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	n.Blocked = append(n.Blocked, ip)
	return nil
}

func (n *Noop) Unblock(context.Context, string) error { return nil }

func (n *Noop) DropConnections(context.Context, string) error { return nil }

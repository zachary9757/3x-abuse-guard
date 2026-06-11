package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zachary9757/3x-abuse-guard/internal/app"
	"github.com/zachary9757/3x-abuse-guard/internal/config"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		usage()
		return errors.New("missing command")
	}
	switch args[1] {
	case "run":
		return runDaemon(args[2:])
	case "doctor":
		return runDoctor(args[2:])
	case "print-xray-policy":
		fmt.Print(app.XrayPolicySnippet)
		return nil
	case "status":
		return runStatus(args[2:])
	case "unblock":
		return runUnblock(args[2:])
	case "test-event":
		return runTestEvent(args[2:])
	case "install":
		return runInstall(args[2:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command: %s", args[1])
	}
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	guard, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	defer guard.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Printf("3x-abuse-guard started")
	err = guard.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	checks := app.Doctor(context.Background(), cfg)
	ok := true
	for _, check := range checks {
		status := "OK"
		if !check.OK {
			status = "FAIL"
			ok = false
		}
		fmt.Printf("[%s] %s: %s\n", status, check.Name, check.Message)
	}
	if !ok {
		return errors.New("doctor found problems")
	}
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	cfg.Policy.TorrentDisableClientAfter = 0
	cfg.Policy.BlockedDisableClientAfter = 0
	cfg.Policy.Mode = "observe"
	guard, err := app.New(cfg, log.New(os.Stdout, "", log.LstdFlags))
	if err != nil {
		return err
	}
	defer guard.Close()

	bans, events, err := guard.Status(time.Now())
	if err != nil {
		return err
	}
	fmt.Println("active bans:")
	if len(bans) == 0 {
		fmt.Println("  none")
	}
	for _, ban := range bans {
		fmt.Printf("  %s email=%s reason=%s expires=%s\n", ban.IP, ban.Email, ban.Reason, ban.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Println("recent events:")
	if len(events) == 0 {
		fmt.Println("  none")
	}
	for _, ev := range events {
		fmt.Printf("  %s kind=%s score=%d profile=%s email=%s ip=%s target=%s reason=%s\n", ev.CreatedAt.Format(time.RFC3339), ev.Kind, ev.Score, ev.Profile, ev.Email, ev.SourceIP, ev.Target, ev.Reason)
	}
	return nil
}

func runUnblock(args []string) error {
	fs := flag.NewFlagSet("unblock", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: 3x-abuse-guard unblock [--config path] <ip>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	cfg.Policy.TorrentDisableClientAfter = 0
	cfg.Policy.BlockedDisableClientAfter = 0
	cfg.Policy.Mode = "observe"
	guard, err := app.New(cfg, log.New(os.Stdout, "", log.LstdFlags))
	if err != nil {
		return err
	}
	defer guard.Close()
	return guard.Unblock(context.Background(), fs.Arg(0))
}

func runTestEvent(args []string) error {
	fs := flag.NewFlagSet("test-event", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "config file path")
	email := fs.String("email", "", "client email")
	ip := fs.String("ip", "", "source ip")
	tag := fs.String("tag", "TORRENT", "outbound tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ip == "" {
		return errors.New("--ip is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	guard, err := app.New(cfg, log.New(os.Stdout, "", log.LstdFlags))
	if err != nil {
		return err
	}
	defer guard.Close()
	return guard.HandleTestEvent(context.Background(), *email, *ip, *tag)
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	prefix := fs.String("prefix", "/", "install prefix, mainly for package tests")
	binary := fs.String("binary", "/usr/local/bin/3x-abuse-guard", "binary path used in systemd service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := app.Install(*prefix, *binary); err != nil {
		return err
	}
	fmt.Println("installed config, env, state/log directories, and systemd unit")
	fmt.Println("edit /etc/3x-abuse-guard/env and set THREEX_ABUSE_GUARD_TOKEN or THREEX_ABUSE_GUARD_USERNAME/THREEX_ABUSE_GUARD_PASSWORD")
	fmt.Println("then run: systemctl daemon-reload && systemctl enable --now 3x-abuse-guard")
	return nil
}

func usage() {
	fmt.Print(`3x-abuse-guard

Commands:
  run                 Run the foreground daemon
  install             Install config, env file, directories, and systemd unit
  doctor              Check 3x-ui API, access log, Xray tags, and sniffing
  print-xray-policy   Print Xray snippets required in 3x-ui
  status              Show active bans and recent events
  unblock <ip>        Remove an IP from firewall and local state
  test-event          Inject a local policy event
`)
}

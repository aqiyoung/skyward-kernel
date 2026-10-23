// Command skyward runs one Skyward profile: it reads a profile, builds the
// router, and exposes a SOCKS5 listener. It exists to exercise the kernel
// without the app, and is the shape the app's own embedding will take.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aqiyoung/skyward-kernel/internal/config"
	"github.com/aqiyoung/skyward-kernel/internal/inbound"
	"github.com/aqiyoung/skyward-kernel/internal/logx"
	"github.com/aqiyoung/skyward-kernel/internal/route"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "skyward:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("c", "configs/example.yaml", "profile to run")
	socksAddr := flag.String("socks", "127.0.0.1:7890", "SOCKS5 listen address")
	level := flag.String("log", "", "log level: error, warn, info or debug (overrides the profile)")
	explain := flag.Bool("explain", false, "print what the profile resolved to, then exit")
	flag.Parse()

	cfg, warnings, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	profileLevel := cfg.LogLevel
	if *level != "" {
		profileLevel = *level
	}
	parsedLevel, err := logx.ParseLevel(profileLevel)
	if err != nil {
		return err
	}
	log := logx.New(parsedLevel, os.Stderr)

	for _, w := range warnings {
		log.Warnf("profile: %s is not read by this kernel", w)
	}

	router, err := route.New(cfg, log)
	if err != nil {
		return err
	}
	log.Infof("profile %s: mode=%s proxies=%d groups=%d rules=%d",
		*configPath, cfg.Mode, len(cfg.Proxies), len(cfg.ProxyGroups), len(cfg.Rules))

	if *explain {
		for _, line := range cfg.Rules {
			log.Infof("rule %s", line)
		}
		for _, g := range cfg.ProxyGroups {
			log.Infof("group %s (%s) -> %v", g.Name, g.Type, g.Proxies)
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	server := &inbound.Socks5{Listen: *socksAddr, Dial: router.DialContext, Log: log}
	return server.Serve(ctx)
}

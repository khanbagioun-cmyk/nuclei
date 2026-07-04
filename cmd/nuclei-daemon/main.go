package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/nuclei/v3/pkg/daemon"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19091", "listen address")
	bin := flag.String("bin", "", "path to nuclei binary (default ~/.local/bin/nuclei-dev)")
	results := flag.String("results", "", "results directory")
	maxConc := flag.Int("max", 3, "max concurrent scans")
	dbPath := flag.String("db", "", "state DB path")
	help := flag.Bool("h", false, "show help")
	flag.Parse()

	if *help {
		fmt.Print(daemon.CLIHelp())
		os.Exit(0)
	}

	cfg := daemon.DefaultConfig()
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	if *bin != "" {
		cfg.NucleiBin = *bin
	}
	if *results != "" {
		cfg.ResultsDir = *results
	}
	if *maxConc > 0 {
		cfg.MaxConcurrent = *maxConc
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}

	d := daemon.New(cfg)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[daemon] shutting down...")
		d.Stop()
		os.Exit(0)
	}()

	fmt.Printf("[daemon] listening on %s\n", cfg.ListenAddr)
	fmt.Printf("[daemon] nuclei binary: %s\n", cfg.NucleiBin)
	fmt.Printf("[daemon] results dir: %s\n", cfg.ResultsDir)
	fmt.Printf("[daemon] max concurrent: %d\n", cfg.MaxConcurrent)

	if err := d.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[daemon] error: %s\n", err)
		os.Exit(1)
	}
}

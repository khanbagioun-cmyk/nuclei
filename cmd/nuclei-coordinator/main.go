package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/nuclei/v3/pkg/distributed"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19093", "coordinator listen address")
	results := flag.String("results", "", "results directory")
	bin := flag.String("bin", "", "nuclei binary path (for work items)")
	chunk := flag.Int("chunk", 10, "work chunk size")
	help := flag.Bool("h", false, "show help")
	flag.Parse()

	if *help {
		fmt.Println(`nuclei-coordinator — Distributed scan coordinator

Usage:
  nuclei-coordinator [options]

Options:
  -addr <addr>     Listen address (default 127.0.0.1:19093)
  -results <dir>   Results directory
  -bin <path>      Default nuclei binary path for work items
  -chunk <n>       Work chunk size (targets per work item)

API Endpoints:
  GET  /health              — coordinator health
  GET  /api/work?worker=X   — get next work item
  POST /api/result           — submit work result
  POST /api/register         — register a worker
  GET  /api/heartbeat?worker=X — worker heartbeat
  GET  /api/jobs             — list all jobs
  POST /api/jobs             — submit a distributed job
  GET  /api/jobs/<id>        — get job status
  GET  /api/workers          — list registered workers
  GET  /api/merge/<id>       — merge all results for a job

Worker:
  Start workers on other machines pointing to this coordinator.
  Workers poll /api/work, execute nuclei, and POST results back.`)
		os.Exit(0)
	}

	cfg := distributed.DefaultCoordinatorConfig()
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	if *results != "" {
		cfg.ResultsDir = *results
	}
	if *bin != "" {
		cfg.NucleiBin = *bin
	}
	if *chunk > 0 {
		cfg.ChunkSize = *chunk
	}

	coord := distributed.NewCoordinator(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[coordinator] shutting down...")
		coord.Stop()
		os.Exit(0)
	}()

	fmt.Printf("[coordinator] listening on %s\n", cfg.ListenAddr)
	fmt.Printf("[coordinator] results dir: %s\n", cfg.ResultsDir)
	fmt.Printf("[coordinator] nuclei binary: %s\n", cfg.NucleiBin)
	fmt.Println("[coordinator] waiting for workers to register...")

	if err := coord.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[coordinator] error: %s\n", err)
		os.Exit(1)
	}
}

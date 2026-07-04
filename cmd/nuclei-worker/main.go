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
	coordinator := flag.String("coordinator", "127.0.0.1:19093", "coordinator address")
	workerID := flag.String("id", "", "worker ID (auto-generated if empty)")
	bin := flag.String("bin", "", "nuclei binary path")
	results := flag.String("results", "", "results directory")
	poll := flag.Duration("poll", 5_000_000_000, "poll interval for work")
	help := flag.Bool("h", false, "show help")
	flag.Parse()

	if *help {
		fmt.Println(`nuclei-worker — Distributed scan worker

Usage:
  nuclei-worker [options]

Options:
  -coordinator <addr>  Coordinator address (default 127.0.0.1:19093)
  -id <worker-id>      Worker ID (auto-generated if empty)
  -bin <path>          Nuclei binary path
  -results <dir>       Local results directory
  -poll <duration>     Poll interval (default 5s)

The worker registers with the coordinator, polls for work items,
executes nuclei scans, and reports results back.`)
		os.Exit(0)
	}

	cfg := distributed.DefaultWorkerConfig()
	if *coordinator != "" {
		cfg.CoordinatorAddr = *coordinator
	}
	if *workerID != "" {
		cfg.WorkerID = *workerID
	}
	if *bin != "" {
		cfg.NucleiBin = *bin
	}
	if *results != "" {
		cfg.ResultsDir = *results
	}
	if *poll > 0 {
		cfg.PollInterval = *poll
	}

	worker := distributed.NewWorker(cfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[worker] shutting down...")
		worker.Stop()
		os.Exit(0)
	}()

	fmt.Printf("[worker] ID: %s\n", cfg.WorkerID)
	fmt.Printf("[worker] coordinator: %s\n", cfg.CoordinatorAddr)
	fmt.Printf("[worker] nuclei binary: %s\n", cfg.NucleiBin)
	fmt.Printf("[worker] results dir: %s\n", cfg.ResultsDir)

	if err := worker.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[worker] error: %s\n", err)
		os.Exit(1)
	}
}

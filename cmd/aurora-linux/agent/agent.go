package agent

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nicholasgasior/aurora-linux/lib/consumer/sigma"
	"github.com/nicholasgasior/aurora-linux/lib/distributor"
	"github.com/nicholasgasior/aurora-linux/lib/enrichment"
	"github.com/nicholasgasior/aurora-linux/lib/logging"
	ebpfprovider "github.com/nicholasgasior/aurora-linux/lib/provider/ebpf"
	log "github.com/sirupsen/logrus"
)

// Agent orchestrates the lifecycle of the Aurora Linux EDR agent.
type Agent struct {
	params      Parameters
	listener    *ebpfprovider.Listener
	dist        *distributor.Distributor
	consumer    *sigma.SigmaConsumer
	correlator  *enrichment.Correlator
	enricher    *enrichment.EventEnricher
}

// New creates a new agent from the given parameters.
func New(params Parameters) *Agent {
	return &Agent{params: params}
}

// Run initializes all components and starts the event processing loop.
// It blocks until a SIGINT or SIGTERM is received.
func (a *Agent) Run() error {
	// Configure logging
	a.configureLogging()

	log.Info("Aurora Linux EDR Agent starting")
	log.WithFields(log.Fields{
		"rules":             a.params.RuleDirs,
		"ringbuf_pages":     a.params.RingBufSizePages,
		"correlation_cache": a.params.CorrelationCacheSize,
	}).Info("Configuration")

	// Create correlator
	var err error
	a.correlator, err = enrichment.NewCorrelator(a.params.CorrelationCacheSize)
	if err != nil {
		return fmt.Errorf("creating correlator: %w", err)
	}

	// Create enricher and register enrichments
	a.enricher = enrichment.NewEventEnricher()
	distributor.RegisterLinuxEnrichments(a.enricher, a.correlator)

	// Create distributor
	a.dist = distributor.New(a.enricher, a.correlator)

	// Create and initialize Sigma consumer
	sigmaLogger := log.StandardLogger()
	a.consumer = sigma.New(sigma.Config{
		RuleDirs:      a.params.RuleDirs,
		Logger:        sigmaLogger,
		ThrottleRate:  a.params.ThrottleRate,
		ThrottleBurst: a.params.ThrottleBurst,
	})

	if err := a.consumer.Initialize(); err != nil {
		return fmt.Errorf("initializing Sigma consumer: %w", err)
	}
	a.dist.RegisterConsumer(a.consumer)

	// Load Sigma rules if rule directories are specified
	if len(a.params.RuleDirs) > 0 {
		if err := a.consumer.InitializeWithRules(a.params.RuleDirs); err != nil {
			log.WithError(err).Warn("Failed to load Sigma rules; continuing without rules")
		}
	}

	// Create and initialize eBPF listener
	a.listener = ebpfprovider.NewListener(a.correlator)

	// Enable all sources
	a.listener.AddSource(ebpfprovider.SourceProcessExec)
	a.listener.AddSource(ebpfprovider.SourceFileCreate)
	a.listener.AddSource(ebpfprovider.SourceNetConnect)

	if err := a.listener.Initialize(); err != nil {
		return fmt.Errorf("initializing eBPF listener: %w", err)
	}

	log.Info("eBPF listener initialized, starting event collection")

	// Start stats reporting
	if a.params.StatsInterval > 0 {
		go a.reportStats()
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start event collection in a goroutine
	doneCh := make(chan struct{})
	go func() {
		a.listener.SendEvents(a.dist.HandleEvent)
		close(doneCh)
	}()

	// Wait for signal
	sig := <-sigCh
	log.WithField("signal", sig).Info("Received shutdown signal")

	// Graceful shutdown
	a.shutdown()
	<-doneCh

	log.Info("Aurora Linux EDR Agent stopped")
	return nil
}

// shutdown performs a graceful shutdown of all components.
func (a *Agent) shutdown() {
	log.Info("Shutting down...")

	if a.listener != nil {
		a.listener.Close()
	}
	if a.consumer != nil {
		a.consumer.Close()
	}

	log.WithFields(log.Fields{
		"events_processed": a.dist.Processed(),
		"sigma_matches":    a.consumer.Matches(),
		"events_lost":      a.listener.LostEvents(),
	}).Info("Final statistics")
}

// reportStats periodically logs processing statistics.
func (a *Agent) reportStats() {
	ticker := time.NewTicker(time.Duration(a.params.StatsInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		lost := a.listener.LostEvents()
		processed := a.dist.Processed()
		matches := a.consumer.Matches()

		fields := log.Fields{
			"events_processed": processed,
			"sigma_matches":    matches,
			"events_lost":      lost,
		}

		if processed > 0 && lost > 0 {
			lostPct := float64(lost) / float64(processed+lost) * 100
			fields["lost_pct"] = fmt.Sprintf("%.3f%%", lostPct)
			if lostPct > 1.0 {
				log.WithFields(fields).Warn("Event loss exceeds 1%; consider increasing --ringbuf-size")
				continue
			}
		}

		log.WithFields(fields).Info("Processing statistics")
	}
}

// configureLogging sets up the log formatter and output.
func (a *Agent) configureLogging() {
	if a.params.JSONOutput {
		log.SetFormatter(&logging.JSONFormatter{})
	} else {
		log.SetFormatter(&logging.TextFormatter{})
	}

	if a.params.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	if a.params.LogFile != "" {
		f, err := os.OpenFile(a.params.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithError(err).Warn("Failed to open log file, using stdout")
			return
		}
		log.SetOutput(f)
	}
}

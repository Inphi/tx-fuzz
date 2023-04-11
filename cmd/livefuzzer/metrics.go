package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v2"
)

var (
	ns = "tx_fuzz_default"

	registry                  *prometheus.Registry
	factory                   promauto.Factory
	DataBytes                 prometheus.Counter
	DataBytesConfirmed        prometheus.Counter
	TransactionTotal          prometheus.Counter
	TransactionConfirmedTotal prometheus.Counter

	metricsEnabledFlag = &cli.BoolFlag{
		Name:    "metrics.enabled",
		Usage:   "Enable the metrics server",
		EnvVars: []string{"METRICS_ENABLED"},
	}
	metricsListenAddrFlag = &cli.StringFlag{
		Name:    "metrics.addr",
		Usage:   "Metrics listening address",
		Value:   "0.0.0.0",
		EnvVars: []string{"METRICS_ADDR"},
	}
	metricsPortFlag = &cli.IntFlag{
		Name:    "metrics.port",
		Usage:   "Metrics listening port",
		Value:   7300,
		EnvVars: []string{"METRICS_PORT"},
	}
)

func init() {
	registry = prometheus.NewRegistry()
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	factory = promauto.With(registry)

	DataBytes = factory.NewCounter(prometheus.CounterOpts{
		Namespace: ns,
		Name:      "data_bytes",
		Help:      "Number of bytes in transaction",
	})
	DataBytesConfirmed = factory.NewCounter(prometheus.CounterOpts{
		Namespace: ns,
		Name:      "data_bytes_confirmed",
		Help:      "Number of bytes in transaction",
	})
	TransactionTotal = factory.NewCounter(prometheus.CounterOpts{
		Namespace: ns,
		Name:      "tx_total",
		Help:      "Number of transactions",
	})
	TransactionConfirmedTotal = factory.NewCounter(prometheus.CounterOpts{
		Namespace: ns,
		Name:      "tx_confirmed_total",
		Help:      "Number of transactions",
	})
}

func ListenAndServeMetrics(ctx context.Context, hostname string, port int) error {
	addr := net.JoinHostPort(hostname, strconv.Itoa(port))
	server := &http.Server{
		Addr: addr,
		Handler: promhttp.InstrumentMetricHandler(
			registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	tick := time.NewTicker(10 * time.Millisecond)
	select {
	case err := <-errCh:
		return fmt.Errorf("http server failed: %w", err)
	case <-tick.C:
		break
	}

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())

		err := ctx.Err()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

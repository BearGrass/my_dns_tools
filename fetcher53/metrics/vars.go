package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Namespace = "fetch53"
	Subsystem = "iterator"
)

var (
	RequestCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "request_count_total",
		Help:      "Counter of DNS requests.",
	})

	ResponseCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "response_count_total",
		Help:      "Counter of DNS responses.",
	})

	QPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "qps",
		Help:      "requests per second.",
	})

	CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "cache_hits_total",
		Help:      "The count of cache hits all views.",
	})
)

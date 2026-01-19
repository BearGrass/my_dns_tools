package metrics

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg      *prometheus.Registry
	qps      *Counter
	stopChan chan struct{}
}

func New() *Metrics {
	m := &Metrics{
		reg:      prometheus.NewRegistry(),
		qps:      newCounter(),
		stopChan: make(chan struct{}),
	}

	m.reg.MustRegister(RequestCount)
	m.reg.MustRegister(ResponseCount)
	m.reg.MustRegister(QPS)
	m.reg.MustRegister(CacheHits)

	go m.calculateQPS()

	return m
}

func (m *Metrics) calculateQPS() {
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-m.stopChan:
			m.stopChan <- struct{}{}
			return
		case <-timer.C:
		}
		QPS.Set(float64(m.qps.Count()))
		m.qps.Clear()
	}
}

func (m *Metrics) Stop() {
	m.stopChan <- struct{}{}
	<-m.stopChan
}

func (m *Metrics) HttpHandler() func(*gin.Context) {
	return func(ctx *gin.Context) {
		handler := promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
		handler.ServeHTTP(ctx.Writer, ctx.Request)
	}
}

func (m *Metrics) RecordQuery() {
	RequestCount.Inc()
	m.qps.Inc()
}

func (m *Metrics) RecordResponse(cacheHit bool) {
	ResponseCount.Inc()
	if cacheHit {
		CacheHits.Inc()
	}
}

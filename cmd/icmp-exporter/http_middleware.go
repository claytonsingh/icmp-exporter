package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	requestDurationHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "The latency of the HTTP requests.",
		Buckets: prometheus.DefBuckets,
	}, []string{"path", "method", "status"})
	responseSizeHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_response_size_bytes",
		Help:    "The size of the HTTP responses.",
		Buckets: prometheus.ExponentialBuckets(100, 10, 6),
	}, []string{"path", "method", "status"})
	requestsInflight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_requests_inflight",
		Help: "The number of inflight requests being handled at the same time.",
	})
	requestMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "connect": true, "options": true, "notify": true, "trace": true, "patch": true}
)

// PromtheusMiddlewareHandler returns an measuring standard http.Handler.
func PromtheusMiddlewareHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wp := &ResponseWriterProxy{
			statusCode:     http.StatusOK,
			ResponseWriter: w,
		}

		// Measure http request
		start := time.Now()
		requestsInflight.Inc()
		defer func() {
			requestsInflight.Dec()
			duration := time.Since(start)

			// If return status is 404 then dont return a path to prevent high cardinality metrics
			path := ""
			if wp.statusCode != 404 {
				path = r.URL.Path
			}

			statusCode := strconv.Itoa(wp.statusCode)

			method := strings.ToLower(r.Method)
			if _, ok := requestMethods[method]; !ok {
				method = "unknown"
			}

			requestDurationHistogram.WithLabelValues(path, method, statusCode).Observe(duration.Seconds())
			responseSizeHistogram.WithLabelValues(path, method, statusCode).Observe(float64(wp.bytesWritten))
		}()
		h.ServeHTTP(wp, r)
	})
}

// ResponseWriterProxy is a proxy of http.ResponseWriter and http.Flusher.
type ResponseWriterProxy struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *ResponseWriterProxy) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *ResponseWriterProxy) Write(p []byte) (int, error) {
	w.bytesWritten += len(p)
	return w.ResponseWriter.Write(p)
}

func (w *ResponseWriterProxy) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Validate interfaces
var (
	_ http.ResponseWriter = &ResponseWriterProxy{}
	_ http.Flusher        = &ResponseWriterProxy{}
)

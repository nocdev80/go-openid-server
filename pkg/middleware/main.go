package middleware

import (
	"log"
	"net/http"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Log is
func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()
		log.Println(r.URL)
		lrw := newLoggingResponseWriter(w)

		next.ServeHTTP(lrw, r)

		log.Printf("%s %s %s [%s] -> [%d]\n", r.RemoteAddr, r.Method, r.URL, time.Since(start).String(), lrw.statusCode)
	})
}

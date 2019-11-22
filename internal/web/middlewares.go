package web

import (
	"log"
	"net/http"
	"time"
)

func LogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		delta := time.Since(start)
		log.Printf("%s %s %s", r.Method, r.URL.String(), delta.String())
	})
}

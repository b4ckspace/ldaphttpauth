package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/b4ckspace/ldaphttpauth/internal/config"
	"github.com/b4ckspace/ldaphttpauth/internal/passwordchecker"
	"github.com/b4ckspace/ldaphttpauth/internal/web"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.ParseConfig()
	if err != nil {
		log.Fatalf("unable to load config from env: %s", err)
	}

	pc, err := passwordchecker.NewPasswordChecker(ctx, cfg)
	if err != nil {
		log.Fatalf("unable to connect ldap: %s", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", pc.HandleAuth)
	middlewared := web.LogMiddleware(mux)
	go func() { _ = http.ListenAndServe(cfg.HttpBind, middlewared) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	s := <-sig
	log.Printf("received %s, shutting down.", s)
}

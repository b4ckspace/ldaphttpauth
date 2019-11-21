package main

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/ldap.v3"
)

type (
	config struct {
		Realm           string `default:"Authentication"`
		LdapHost        string `required:"true"`
		LdapBind        string `required:"true"`
		LdapTLSHostname string
		HttpBind        string `default:":8042"`
	}
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := config{}
	err := envconfig.Process("", &c)
	if err != nil {
		log.Fatalf("unable to load config: %s", err)
	}
	if c.LdapTLSHostname == "" {
		if strings.Contains(c.LdapHost, ":") {
			c.LdapTLSHostname = c.LdapHost[:strings.Index(c.LdapHost, ":")]
		} else {
			c.LdapTLSHostname = c.LdapHost
		}
	}
	log.Printf("%+v", c)

	pc, err := NewPasswordChecker(ctx, c.LdapHost, c.LdapTLSHostname, c.HttpBind, &c)
	if err != nil {
		log.Fatalf("unable to connect ldap: %s", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", pc.handleAuth)
	middlewared := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			delta := time.Since(start)
			log.Printf("%s %s %s", r.Method, r.URL.String(), delta.String())
		})
	}(mux)
	go func() { _ = http.ListenAndServe(c.HttpBind, middlewared) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	select {
	case s := <-sig:
		log.Printf("received %s, shutting down.", s)
		return
	}

}

type PasswordChecker struct {
	ldapHost    string
	tlsHostname string
	bind        string
	config      *config
	cache       *sync.Map
	ttl         time.Duration
}

func NewPasswordChecker(ctx context.Context, ldapHost, tlsHostname, bind string, c *config) (pc *PasswordChecker, err error) {
	pc = &PasswordChecker{
		ldapHost:    ldapHost,
		tlsHostname: tlsHostname,
		bind:        bind,
		config:      c,
		cache:       &sync.Map{},
		ttl:         10 * time.Second,
	}
	conn, err := pc.dailTLS()
	if err != nil {
		return nil, err
	}
	conn.Close()

	ticker := time.NewTicker(time.Minute)
	go func() {
		for {
			select {
			case <-ctx.Done():
			case <-ticker.C:
				pc.cache.Range(func(key, value interface{}) bool {
					expireTime := value.(time.Time)
					if time.Since(expireTime) > pc.ttl {
						pc.cache.Delete(key)
					}
					return true
				})
			}
		}
	}()

	return pc, nil
}

func (pc *PasswordChecker) dailTLS() (conn *ldap.Conn, err error) {
	conn, err = ldap.Dial("tcp", pc.ldapHost)
	if err != nil {
		return nil, fmt.Errorf("error connection to LDAP: %s", err)
	}
	err = conn.StartTLS(&tls.Config{
		ServerName: pc.tlsHostname,
	})
	if err != nil {
		return nil, fmt.Errorf("error with STARTTLS: %s", err)
	}
	return conn, nil
}

func (pc *PasswordChecker) CheckPassword(username, password string) bool {
	if strings.TrimSpace(username) == "" {
		return false
	}
	if strings.TrimSpace(password) == "" {
		return false
	}
	conn, err := pc.dailTLS()
	if err != nil {
		log.Printf("unable to verify password for '%s': %s", username, err)
		return false
	}
	defer conn.Close()

	bindStr := fmt.Sprintf(pc.config.LdapBind, ldap.EscapeFilter(username))
	log.Print(bindStr)
	err = conn.Bind(bindStr, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false
		}
		if ldap.IsErrorWithCode(err, ldap.ErrorEmptyPassword) {
			return false
		}
		// This should not happen unless you have configuration errors
		log.Fatal(err)
	}
	return true
}

func (pc *PasswordChecker) handleAuth(w http.ResponseWriter, r *http.Request) {
	authHeaderValue := fmt.Sprintf("Basic real=%s", pc.config.Realm)
	w.Header().Add("WWW-Authenticate", authHeaderValue)
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "DENIED")
	}
	hash := sha512.New()
	_, _ = hash.Write([]byte(username))
	_, _ = hash.Write([]byte(password))
	cacheIdent := hash.Sum([]byte{})
	cacheKey := string(cacheIdent)

	_, ok = pc.cache.Load(cacheKey)
	if ok {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
		pc.cache.Store(cacheKey, time.Now())
		return
	}
	if pc.CheckPassword(username, password) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
		pc.cache.Store(cacheKey, time.Now())
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "DENIED")
	}
}

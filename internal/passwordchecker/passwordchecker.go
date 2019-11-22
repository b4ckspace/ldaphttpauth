package passwordchecker

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"gopkg.in/ldap.v3"

	"github.com/b4ckspace/ldaphttpauth/internal/cachemap"
	"github.com/b4ckspace/ldaphttpauth/internal/config"
)

type PasswordChecker struct {
	config *config.Config
	cache  *cachemap.CacheMap
	ttl    time.Duration
}

func NewPasswordChecker(ctx context.Context, cfg *config.Config) (pc *PasswordChecker, err error) {
	cache := cachemap.NewCacheMap(ctx, 10*time.Minute, time.Minute)
	pc = &PasswordChecker{
		config: cfg,
		cache:  cache,
		ttl:    10 * time.Second,
	}
	conn, err := pc.dailTLS()
	if err != nil {
		return nil, err
	}
	conn.Close()

	return pc, nil
}

func (pc *PasswordChecker) dailTLS() (conn *ldap.Conn, err error) {
	conn, err = ldap.Dial("tcp", pc.config.LdapHost)
	if err != nil {
		return nil, fmt.Errorf("error connection to LDAP: %s", err)
	}
	err = conn.StartTLS(&tls.Config{
		ServerName: pc.config.LdapTLSHostname,
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

func (pc *PasswordChecker) HandleAuth(w http.ResponseWriter, r *http.Request) {
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

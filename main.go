package main

import (
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/ldap.v3"
)

func main() {
	realm, found := os.LookupEnv("REALM")
	if !found {
		realm = "Authentication"
	}
	ldapHost, found := os.LookupEnv("LDAP_HOST")
	if !found {
		log.Fatal("LDAP_HOST environment variable must be specified.")
	}
	tlsHostname, found := os.LookupEnv("LDAP_TLS_HOSTNAME")
	if !found {
		if strings.Contains(ldapHost, ":") {
			tlsHostname = ldapHost[:strings.Index(ldapHost, ":")]
		} else {
			tlsHostname = ldapHost
		}
	}
	ldapBind, found := os.LookupEnv("LDAP_BIND")
	if !found {
		log.Fatal("LDAP_BIND environment variable must be specified.")
	}
	httpBind, found := os.LookupEnv("HTTP_BIND")
	if !found {
		httpBind = ":8042"
	}
	pc := &PasswordChecker{
		ldapHost:    ldapHost,
		tlsHostname: tlsHostname,
		bind:        ldapBind,
	}
	cache := new(sync.Map)
	maxLifetime := 10 * time.Minute
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authHeaderValue := fmt.Sprintf("Basic real=%s", realm)
		w.Header().Add("WWW-Authenticate", authHeaderValue)
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "DENIED")
		}
		var cacheKey [128]byte
		userHash := sha512.Sum512([]byte(username))
		pwHash := sha512.Sum512([]byte(password))
		copy(cacheKey[0:64], userHash[:])
		copy(cacheKey[64:128], pwHash[:])
		cacheValue, ok := cache.Load(cacheKey)
		if ok {
			expireTime := cacheValue.(time.Time)
			if time.Since(expireTime) <= maxLifetime {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "OK")
				cache.Store(cacheKey, time.Now())
				return
			}
		}
		if pc.checkPassword(username, password) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")
			cache.Store(cacheKey, time.Now())
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "DENIED")
		}
	})
	ticker := time.NewTicker(time.Minute)
	done := make(chan bool)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				cache.Range(func(key, value interface{}) bool {
					expireTime := value.(time.Time)
					if time.Since(expireTime) > maxLifetime {
						cache.Delete(key)
						keyArr := key.([128]byte)
						for i := 0; i < len(keyArr); i++ {
							keyArr[i] = 0
						}
					}
					return true
				})
			}
		}
	}()
	log.Fatal(http.ListenAndServe(httpBind, nil))
	done <- true
}

type PasswordChecker struct {
	ldapHost    string
	tlsHostname string
	bind        string
}

func (pc *PasswordChecker) checkPassword(username, password string) bool {
	if strings.TrimSpace(username) == "" {
		return false
	}
	if strings.TrimSpace(password) == "" {
		return false
	}
	conn, err := ldap.Dial("tcp", pc.ldapHost)
	defer conn.Close()
	if err != nil {
		log.Println(fmt.Sprintf("Error connection to LDAP: %s", err))
		return false
	}
	err = conn.StartTLS(&tls.Config{
		ServerName: pc.tlsHostname,
	})
	if err != nil {
		log.Println(fmt.Sprintf("Error with STARTTLS: %s", err))
		return false
	}
	bindStr := fmt.Sprintf(pc.bind, ldap.EscapeFilter(username))
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

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authHeaderValue := fmt.Sprintf("Basic real=%s", realm)
		w.Header().Add("WWW-Authenticate", authHeaderValue)
		username, password, ok := r.BasicAuth()
		if !ok || !pc.checkPassword(username, password) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "DENIED")
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")
		}
	})
	log.Fatal(http.ListenAndServe(httpBind, nil))
}

type PasswordChecker struct {
	ldapHost    string
	tlsHostname string
	bind        string
}

func (pc *PasswordChecker) checkPassword(username, password string) bool {
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

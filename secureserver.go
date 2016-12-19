package secureserver

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// CipherSuites without known attacks or extreme CPU usage
var CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

	// Go 1.8 only
	// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// Best disabled, as they don't provide Forward Secrecy,
	// but might be necessary for some clients
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,

	// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// Curves without known attacks or extreme CPU usage
var Curves = []tls.CurveID{
	// tls.CurveP521,
	// tls.CurveP384
	// Only use curves which have assembly implementations
	tls.CurveP256,
	// tls.X25519, // Go 1.8 only
}

// TLSConfig for including autocert manager
func TLSConfig(domain string) *tls.Config {
	certManager := GetCertificate(domain)

	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		GetCertificate:           certManager.GetCertificate,
		CurvePreferences:         Curves,
		CipherSuites:             CipherSuites,
	}
}

// GetCertificate using autocert
func GetCertificate(domain string) autocert.Manager {
	return autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
	}
}

// GetHTTPSServer fully secured
func GetHTTPSServer(domain string) (s *http.Server) {

	s = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		// IdleTimeout:  120 * time.Second, // go 1.8

		Addr:      ":443",
		TLSConfig: TLSConfig(domain),

		// Disable HTTP 2.0
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	return s
}

// RunHTTPRedirectServer to send all HTTP traffic to HTTPS
func RunHTTPRedirectServer() (s *http.Server) {
	s = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Connection", "close")
			url := "https://" + req.Host + req.URL.String()
			http.Redirect(w, req, url, http.StatusMovedPermanently)
		}),
	}
	go func() { log.Fatal(s.ListenAndServe()) }()
	return s
}

// RunDemoHTTPSServer to demo a working example
func RunDemoHTTPSServer(domain string) (s *http.Server) {
	s = GetHTTPSServer(domain)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("This is an example server on " + domain + ".\n"))
	})

	s.Handler = mux

	log.Fatal(s.ListenAndServeTLS("", ""))
	return
}

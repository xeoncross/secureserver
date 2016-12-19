## Go secureserver

Out-of-the-box, Go is a fully capable HTTP/HTTPS server. However, it is not
configured correctly to avoid malicious clients, timeouts, or even simple SSL
auto setup with [LetsEncrypt.org](https://letsencrypt.org/).

This repository exists to help go developers launch a secure, simple HTTPS server.

This configuration blocks major attacks like:

- BEAST attack
- POODLE (SSLv3)
- POODLE (TLS)
- Heartbleed
- CRIME
- FUBAR
- OpenSSL CCS vulnerability (CVE-2014-0224)
- OpenSSL Padding Oracle vulnerability

Achieving forward secrecy and low server load are a focus.

## Reading

- https://blog.bracebin.com/achieving-perfect-ssl-labs-score-with-go
- https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
- https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
- https://cipherli.st/
- https://wiki.mozilla.org/Security/Server_Side_TLS

## Install

    go get github.com/xeoncross/secureserver


## Usage

    package main

    import (
      "github.com/xeoncross/secureserver"
    )

    func main() {
      domain := "example.com"
      secureserver.RunHTTPRedirectServer()
      s := secureserver.GetHTTPSServer(domain)

      mux := http.NewServeMux()
      mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Write([]byte("This is an example server on " + domain + ".\n"))
      })

      s.Handler = mux

      log.Fatal(s.ListenAndServeTLS("", ""))
    }


## Demo Server

You can quickly run a test HTTP/HTTPS server like so:

    package main

    import (
      "github.com/xeoncross/secureserver"
    )

    func main() {
      domain := "example.com"
      secureserver.RunHTTPRedirectServer()
      secureserver.RunDemoHTTPSServer(domain) // blocks
    }


## Contributions Required

To serve a source of information about current Go best-practices; pull requests,
issues, and documentation are welcome.

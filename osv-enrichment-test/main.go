package main

/*
OSV Enrichment Test App

PURPOSE:
  Proves that REACHABLE can enrich Grype CVE output with OSV data,
  specifically confirming go_vuln_id (GO-XXXX-XXXX) is populated.

EXPECTED FINDINGS after scan:
  1. golang.org/x/crypto v0.26.0
     - CVE-2024-45337 (GHSA-v778-237x-gjrc)
     - go_vuln_id:  GO-2024-3321
     - epss_score:  populated
     - is_kev:      false (not in CISA KEV)
     - reachability: REACHABLE (sshServer is called from main)

  2. golang.org/x/net v0.23.0
     - CVE-2023-44487 (GHSA-qppj-fm56-g4cc) → GO-2023-2102
     - CVE-2024-45338 (GHSA-w32m-9786-jp63) → GO-2024-3333
     - epss_score:  populated (CVE-2023-44487 is high EPSS, KEV listed)
     - reachability: REACHABLE (httpServer is called from main)

REACHABILITY:
  sshServer()  → golang.org/x/crypto/ssh  (REACHABLE — called from main)
  httpServer() → golang.org/x/net/http2   (REACHABLE — called from main)
  deadCode()   → never called             (NOT_REACHABLE)
*/

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	// Both entrypoints are reachable from main
	go sshServer()
	httpServer()
}

// =============================================================================
// REACHABLE: golang.org/x/crypto v0.26.0
// CVE-2024-45337 / GO-2024-3321
// Misuse of ServerConfig.PublicKeyCallback causes authorization bypass
// =============================================================================
func sshServer() {
	config := &ssh.ServerConfig{
		// CVE-2024-45337: PublicKeyCallback without NoClientAuth allows bypass
		// when combined with keyboard-interactive auth
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Vulnerable pattern: accepts any key without checking NoClientAuth
			return &ssh.Permissions{}, nil
		},
	}

	privateBytes, err := os.ReadFile("host_key")
	if err != nil {
		fmt.Println("no host key, skipping ssh server")
		return
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSSHConn(conn, config)
	}
}

func handleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	// Vulnerable: triggers CVE-2024-45337 when PublicKeyCallback is set
	ssh.NewServerConn(conn, config) //nolint
}

// =============================================================================
// REACHABLE: golang.org/x/net v0.23.0
// CVE-2023-44487 / GO-2023-2102 (HTTP/2 Rapid Reset — high EPSS, in KEV)
// CVE-2024-45338 / GO-2024-3333 (non-linear HTML parsing DoS)
// =============================================================================
func httpServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})

	// CVE-2023-44487: HTTP/2 Rapid Reset — server accepts unbounded HEADERS+RST_STREAM
	h2s := &http2.Server{}
	handler := h2c.NewHandler(mux, h2s)

	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}
	server.ListenAndServe() //nolint
}

// =============================================================================
// NOT_REACHABLE: dead code — never called from main or any reachable path
// =============================================================================
func deadCode() {
	// Uses both packages but is never called — should appear as NOT_REACHABLE
	_ = ssh.Marshal(nil)
	resp, _ := http.Get("http://example.com")
	if resp != nil {
		resp.Body.Close()
	}
}

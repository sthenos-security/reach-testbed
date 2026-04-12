// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// REACHABLE TEST FILE — SECRET FALSE POSITIVE: LOCALHOST-ONLY TLS KEY
//
// This file contains a self-signed TLS key+cert pair hardcoded in source.
// This is a known FP pattern: the key is intentionally compromised by being
// in source, but acceptable because the listener binds ONLY to 127.0.0.1
// for local IPC (osquery <-> orbit on the same host).
//
// Expected: UNKNOWN (code_file_secret hint — Enzo reasons about context)
// With /secret-tests/ in customer's [hint].dirs → UNKNOWN + dev_code_path
// ============================================================================
package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

// localhostCert is the certificate for localhost-only IPC proxy.
// Binds only to 127.0.0.1 — never accessible remotely.
const localhostCert = `-----BEGIN CERTIFICATE-----
MIIBqTCCAU6gAwIBAgIUCvG0XCIQmOo/16H+G4pE3tgIlg0wCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNaHR0cHNpZy1wcm94eTAeFw0yNTA2MjQwMzQzMTFaFw00ODAx
MjUwMzQzMTFaMBgxFjAUBgNVBAMMDWh0dHBzaWctcHJveHkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARJk0Q6QQYCSJamw8DUxDO8o60uU2TLa4JMJ7AEZSMX3Lc4
hwBR9WJ8bpAnvTqnF1shU01oGIOgOaH0xh84pcO+
-----END CERTIFICATE-----
`

// localhostKey is the corresponding private key.
// Intentionally compromised by being in source — acceptable for localhost IPC only.
const localhostKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3ETz2yDl69ThBQ/o
XDL5o0YINWELb+ZJ0d5laq1ECdahRANCAARJk0Q6QQYCSJamw8DUxDO8o60uU2TL
a4JMJ7AEZSMX3Lc4hwBR9WJ8bpAnvTqnF1shU01oGIOgOaH0xh84pcO+
-----END PRIVATE KEY-----
`

// NewLocalhostProxy creates a TLS listener bound ONLY to 127.0.0.1.
// The compromised key is acceptable for this localhost-only use.
func NewLocalhostProxy() (net.Listener, error) {
	cert, err := tls.X509KeyPair([]byte(localhostCert), []byte(localhostKey))
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	// ONLY 127.0.0.1 — not 0.0.0.0, not accessible remotely
	return tls.Listen("tcp", "127.0.0.1:0", cfg)
}

func main() {
	l, err := NewLocalhostProxy()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer l.Close()
	fmt.Println("listening on:", l.Addr())
}

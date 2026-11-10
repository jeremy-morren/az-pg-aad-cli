package pg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnStringOverridesEnvironment(t *testing.T) {
	t.Setenv("PGSSLROOTCERT", "/nonexistent/root.crt")
	t.Setenv("PGSSLCERT", "/nonexistent/client.crt")
	t.Setenv("PGSSLMODE", "disable")
	l := NewLive(ConnConfig{Host: "h", Port: 5432, User: "u", Password: "p", SSLMode: "verify-full"})
	cc, err := l.ParseConfig("db")
	if err != nil {
		t.Fatalf("environment leaked into config: %v", err)
	}
	if cc.TLSConfig == nil || cc.TLSConfig.ServerName != "h" {
		t.Fatalf("PGSSLMODE overrode --sslmode: %+v", cc.TLSConfig)
	}
}

func TestTLSConfigPerMode(t *testing.T) {
	caPEM, _, _ := newCA(t, "test CA")
	cases := []struct {
		mode, pem                   string
		tls, skipVerify, verifyFunc bool
		roots                       bool
	}{
		// system trust store: RootCAs must stay nil so Go uses the platform verifier
		// (Windows CryptoAPI incl. AutoRoot, macOS Security framework).
		{mode: "verify-full", tls: true},
		{mode: "verify-ca", tls: true, skipVerify: true, verifyFunc: true},
		{mode: "require", tls: true, skipVerify: true},
		{mode: "prefer", tls: true, skipVerify: true},
		{mode: "disable"},
		// custom CA file: exactly those certificates
		{mode: "verify-full", pem: caPEM, tls: true, roots: true},
		{mode: "verify-ca", pem: caPEM, tls: true, skipVerify: true, verifyFunc: true, roots: true},
		{mode: "require", pem: caPEM, tls: true, skipVerify: true, verifyFunc: true, roots: true}, // libpq: require+root = verify-ca
	}
	for _, c := range cases {
		name := c.mode
		if c.pem != "" {
			name += "+pem"
		}
		t.Run(name, func(t *testing.T) {
			cc, err := NewLive(ConnConfig{Host: "h", Port: 5432, SSLMode: c.mode, RootPEM: c.pem}).ParseConfig("db")
			if err != nil {
				t.Fatal(err)
			}
			tc := cc.TLSConfig
			if !c.tls {
				if tc != nil {
					t.Fatal("expected no TLS")
				}
				return
			}
			if tc == nil {
				t.Fatal("expected TLS")
			}
			if tc.InsecureSkipVerify != c.skipVerify || (tc.VerifyPeerCertificate != nil) != c.verifyFunc || (tc.RootCAs != nil) != c.roots {
				t.Fatalf("skipVerify=%v verifyFunc=%v roots=%v", tc.InsecureSkipVerify, tc.VerifyPeerCertificate != nil, tc.RootCAs != nil)
			}
		})
	}
}

func TestBadPEM(t *testing.T) {
	if _, err := NewLive(ConnConfig{Host: "h", Port: 1, SSLMode: "verify-full", RootPEM: "not a cert"}).ParseConfig("db"); err == nil {
		t.Fatal("expected error")
	}
}

// TestCustomCAHandshake runs real TLS handshakes against a fake Postgres server whose
// certificate is signed by a test CA, checking that --sslrootcert <pem> is honoured by
// pgx's verify-ca and verify-full paths and that an untrusted CA is rejected.
func TestCustomCAHandshake(t *testing.T) {
	caPEM, caCert, caKey := newCA(t, "test CA")
	otherPEM, _, _ := newCA(t, "other CA")
	serverCert := newServerCert(t, caCert, caKey)

	cases := []struct {
		name, mode, pem string
		host            string
		wantHandshake   bool
	}{
		{"verify-ca trusted", "verify-ca", caPEM, "127.0.0.1", true},
		{"verify-ca ignores host name", "verify-ca", caPEM, "localhost", true},
		{"verify-full trusted", "verify-full", caPEM, "127.0.0.1", true},
		{"require+pem trusted", "require", caPEM, "127.0.0.1", true},
		{"verify-ca untrusted", "verify-ca", otherPEM, "127.0.0.1", false},
		{"verify-full untrusted", "verify-full", otherPEM, "127.0.0.1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port, result := fakeTLSPostgres(t, serverCert)
			l := NewLive(ConnConfig{Host: c.host, Port: port, User: "u", Password: "p", SSLMode: c.mode, RootPEM: c.pem})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, connErr := l.In(ctx, "db")
			if connErr == nil {
				t.Fatal("fake server never completes startup; expected an error")
			}
			handshake := <-result
			if handshake != c.wantHandshake {
				t.Fatalf("handshake=%v want %v (client error: %v)", handshake, c.wantHandshake, connErr)
			}
			if !c.wantHandshake && !strings.Contains(connErr.Error(), "certificate") {
				t.Fatalf("expected a certificate error, got %v", connErr)
			}
		})
	}
}

// fakeTLSPostgres accepts one connection, answers the SSLRequest with 'S', performs the
// TLS handshake, reports whether it succeeded, then closes.
func fakeTLSPostgres(t *testing.T, cert tls.Certificate) (int, <-chan bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	result := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- false
			return
		}
		defer conn.Close()
		req := make([]byte, 8)
		if _, err := io.ReadFull(conn, req); err != nil {
			result <- false
			return
		}
		conn.Write([]byte{'S'})
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		err = tc.Handshake()
		result <- err == nil
		if err == nil {
			// Read the startup message, then hang up.
			buf := make([]byte, 1024)
			tc.SetReadDeadline(time.Now().Add(2 * time.Second))
			tc.Read(buf)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, result
}

func newCA(t *testing.T, cn string) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

func newServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}

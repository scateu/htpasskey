package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	var (
		listen   = flag.String("listen", ":8443", "listen address")
		htpasskey = flag.String("htpasskey", ".htpasskey", "credential file path")
		rpID     = flag.String("rp-id", "localhost", "WebAuthn RP ID (domain)")
		rpOrigin = flag.String("rp-origin", "", "RP origin (default: https://<rp-id>:<port>)")
		rpName   = flag.String("rp-name", "WebAuthn Gate", "RP display name")
		tlsCert  = flag.String("tls-cert", "", "TLS cert file (omit = self-signed)")
		tlsKey   = flag.String("tls-key", "", "TLS key file")
		prefix   = flag.String("prefix", "/__webauthn", "auth endpoint prefix")
		backend  = flag.String("backend", "", "reverse proxy backend (e.g. http://127.0.0.1:3000)")
		webroot  = flag.String("webroot", "", "serve static files from this dir (if no backend)")
		sessionTTL = flag.Duration("session-ttl", 24*time.Hour, "session lifetime")
	)
	flag.Parse()

	// resolve htpasskey
	absPath, _ := filepath.Abs(*htpasskey)
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		os.WriteFile(absPath, []byte("# .htpasskey — WebAuthn credentials\n# format: username:base64(json)\n"), 0600)
		log.Printf("Created %s", absPath)
	}

	// auto origin
	if *rpOrigin == "" {
		_, port, _ := net.SplitHostPort(*listen)
		if port == "443" || port == "" {
			*rpOrigin = "https://" + *rpID
		} else {
			*rpOrigin = "https://" + *rpID + ":" + port
		}
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: *rpName,
		RPID:          *rpID,
		RPOrigins:     []string{*rpOrigin},
	})
	if err != nil {
		log.Fatalf("webauthn init: %v", err)
	}

	srv := &Server{
		wa:       wa,
		store:    NewStore(absPath),
		sessions: NewSessions(*sessionTTL),
		prefix:   *prefix,
	}

	// build protected handler (what authenticated users see)
	var protected http.Handler
	switch {
	case *backend != "":
		u, err := url.Parse(*backend)
		if err != nil {
			log.Fatalf("bad backend URL: %v", err)
		}
		protected = httputil.NewSingleHostReverseProxy(u)
		log.Printf("Proxying authenticated requests to %s", *backend)
	case *webroot != "":
		abs, _ := filepath.Abs(*webroot)
		protected = http.FileServer(http.Dir(abs))
		log.Printf("Serving authenticated files from %s", abs)
	default:
		// default: a simple welcome page
		protected = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := r.Header.Get("X-Webauthn-User")
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Welcome</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{background:#1e293b;padding:2rem;border-radius:12px;text-align:center}
a{color:#60a5fa}</style></head>
<body><div class="c"><h1>✅ Authenticated</h1><p>Hello, <strong>%s</strong></p>
<p style="margin-top:1rem"><a href="%s/logout">Logout</a></p></div></body></html>`,
				user, *prefix)
		})
	}

	mux := http.NewServeMux()

	// auth endpoints — no auth required
	p := *prefix
	mux.HandleFunc(p+"/register", srv.RegisterPage)
	mux.HandleFunc(p+"/register/begin", srv.RegisterBegin)
	mux.HandleFunc(p+"/register/finish", srv.RegisterFinish)
	mux.HandleFunc(p+"/login", srv.LoginPage)
	mux.HandleFunc(p+"/login/begin", srv.LoginBegin)
	mux.HandleFunc(p+"/login/finish", srv.LoginFinish)
	mux.HandleFunc(p+"/logout", srv.Logout)
	mux.HandleFunc(p+"/check", srv.Check) // programmatic check

	// everything else → auth middleware → protected
	mux.Handle("/", srv.RequireAuth(protected))

	hs := &http.Server{
		Addr:    *listen,
		Handler: withLog(mux),
	}

	fmt.Println("══════════════════════════════════════")
	fmt.Println("  WebAuthn Gate (standalone)")
	fmt.Printf("  Listen:    %s\n", *listen)
	fmt.Printf("  RP ID:     %s\n", *rpID)
	fmt.Printf("  Origin:    %s\n", *rpOrigin)
	fmt.Printf("  Htpasskey: %s\n", absPath)
	fmt.Printf("  Prefix:    %s\n", *prefix)
	fmt.Printf("  Register:  %s%s/register\n", *rpOrigin, *prefix)
	fmt.Printf("  Login:     %s%s/login\n", *rpOrigin, *prefix)
	fmt.Println("══════════════════════════════════════")

	if *tlsCert != "" && *tlsKey != "" {
		log.Fatal(hs.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		c, _ := selfSigned(*rpID)
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{c}}
		log.Println("Using self-signed TLS certificate")
		log.Fatal(hs.ListenAndServeTLS("", ""))
	}
}

// ── logging ────────────────────────────────────────────────

func withLog(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		sw := &sWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		log.Printf("%d %s %s (%v) [%s]", sw.code, r.Method, r.URL, time.Since(t), r.RemoteAddr)
	})
}

type sWriter struct {
	http.ResponseWriter
	code int
}

func (w *sWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// ── self-signed cert ───────────────────────────────────────

func selfSigned(host string) (tls.Certificate, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	t := x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{Organization: []string{"webauthn-gate"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		t.IPAddresses = []net.IP{ip}
	} else {
		t.DNSNames = []string{host, "localhost"}
	}
	t.IPAddresses = append(t.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	d, _ := x509.CreateCertificate(rand.Reader, &t, &t, &k.PublicKey, k)
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})
	kd, _ := x509.MarshalECPrivateKey(k)
	kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	return tls.X509KeyPair(cp, kp)
}
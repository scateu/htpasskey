> 请参考.htpasswd的实现方式，实现一个go standalone https server，当前目录的.htpasskey文件里会存有用户的公钥和其它webauthn信息。可以参考https://github.com/Quiq/webauthn_proxy。类似于.ssh/authorized_keys的方案。需要nginx在未注册时自动401 302重定向到注册页面。注册后，产生的webauthn公钥凭据由用户自行复制粘贴给管理员。管理员使用pbpaste >> .htpasskey的类似方式来授权

# WebAuthn Gate - 独立 HTTPS Server

去除 nginx 依赖，所有功能（静态文件服务、反向代理、认证拦截、注册/登录页面）全部由 Go 服务自身处理。

## 架构

```
浏览器 → webauthn-gate(:8443)
              ├── /__webauthn/*    认证相关端点（注册/登录/检查）
              ├── 已认证请求       → 反向代理到后端 或 直接服务静态文件
              └── 未认证请求       → 302 重定向到登录页
```

## 项目结构

```
webauthn-gate/
├── main.go         # 入口、TLS、配置
├── store.go        # .htpasskey 文件读写
├── sessions.go     # 内存会话管理
├── handlers.go     # WebAuthn 注册/登录/检查
├── middleware.go   # 认证拦截中间件
├── pages.go        # 内嵌 HTML 页面
├── go.mod
└── .htpasskey      # 凭据文件（管理员维护）
```

---

## go.mod

```go
module webauthn-gate

go 1.22.0

require github.com/go-webauthn/webauthn v0.11.2
```

初始化后执行 `go mod tidy` 拉取间接依赖。

---

## main.go

```go
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
```

---

## store.go

```go
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CredEntry is the JSON payload inside each .htpasskey line
type CredEntry struct {
	User      string   `json:"u"`
	CredID    string   `json:"id"`             // base64url(raw)
	PubKey    string   `json:"pub"`            // base64url(COSE)
	AAGUID    string   `json:"aaguid,omitempty"`
	SignCount uint32   `json:"cnt"`
	AttType   string   `json:"att,omitempty"`
	Transport []string `json:"tp,omitempty"`
	Created   string   `json:"ts,omitempty"`
}

// WUser implements webauthn.User
type WUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *WUser) WebAuthnID() []byte                         { return u.id }
func (u *WUser) WebAuthnName() string                       { return u.name }
func (u *WUser) WebAuthnDisplayName() string                { return u.name }
func (u *WUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// Store manages .htpasskey with auto-reload on file change
type Store struct {
	path string
	mu   sync.Mutex
	mod  time.Time
	data map[string]*WUser
}

func NewStore(path string) *Store {
	s := &Store{path: path, data: make(map[string]*WUser)}
	s.load()
	return s
}

// b64d tries multiple base64 variants
func b64d(s string) []byte {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

func (s *Store) load() {
	info, err := os.Stat(s.path)
	if err != nil || !info.ModTime().After(s.mod) {
		return
	}
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()

	users := make(map[string]*WUser)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 1 {
			log.Printf("htpasskey:%d: bad format", ln)
			continue
		}
		uname := line[:i]
		raw := b64d(line[i+1:])
		if raw == nil {
			log.Printf("htpasskey:%d: bad base64", ln)
			continue
		}
		var e CredEntry
		if json.Unmarshal(raw, &e) != nil {
			log.Printf("htpasskey:%d: bad json", ln)
			continue
		}
		cid := b64d(e.CredID)
		pub := b64d(e.PubKey)
		if cid == nil || pub == nil {
			log.Printf("htpasskey:%d: bad credential fields", ln)
			continue
		}

		c := webauthn.Credential{
			ID:              cid,
			PublicKey:       pub,
			AttestationType: e.AttType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    b64d(e.AAGUID),
				SignCount: e.SignCount,
			},
		}
		for _, t := range e.Transport {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}

		u, ok := users[uname]
		if !ok {
			u = &WUser{id: []byte(uname), name: uname}
			users[uname] = u
		}
		u.creds = append(u.creds, c)
	}

	s.data = users
	s.mod = info.ModTime()
	total := 0
	for _, u := range users {
		total += len(u.creds)
	}
	log.Printf("Loaded %d credentials for %d users from %s", total, len(users), s.path)
}

func (s *Store) Find(name string) *WUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	return s.data[name]
}

func (s *Store) FindByID(id []byte) *WUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	return s.data[string(id)]
}

// FormatLine produces a pasteable .htpasskey line (with comment)
func FormatLine(username string, c *webauthn.Credential) string {
	e := CredEntry{
		User:      username,
		CredID:    base64.RawURLEncoding.EncodeToString(c.ID),
		PubKey:    base64.RawURLEncoding.EncodeToString(c.PublicKey),
		AAGUID:    base64.RawURLEncoding.EncodeToString(c.Authenticator.AAGUID),
		SignCount: c.Authenticator.SignCount,
		AttType:   c.AttestationType,
		Created:   time.Now().UTC().Format(time.RFC3339),
	}
	for _, t := range c.Transport {
		e.Transport = append(e.Transport, string(t))
	}
	j, _ := json.Marshal(e)
	b := base64.StdEncoding.EncodeToString(j)
	short := e.CredID
	if len(short) > 20 {
		short = short[:20] + "…"
	}
	return fmt.Sprintf("# %s | cred:%s | %s\n%s:%s",
		username, short, e.Created, username, b)
}
```

---

## sessions.go

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Session struct {
	WAData       *webauthn.SessionData
	CeremonyUser string // username during ceremony
	AuthUser     string // authenticated username
	Authed       bool
	Exp          time.Time
}

type Sessions struct {
	mu  sync.Mutex
	m   map[string]*Session
	ttl time.Duration
}

const cookieName = "__wa_sid"

func NewSessions(ttl time.Duration) *Sessions {
	s := &Sessions{m: make(map[string]*Session), ttl: ttl}
	go func() {
		for range time.Tick(5 * time.Minute) {
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.m {
				if now.After(v.Exp) {
					delete(s.m, k)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s
}

func newSID() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (ss *Sessions) get(r *http.Request) (*Session, string) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, ""
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.m[c.Value]
	if s == nil || time.Now().After(s.Exp) {
		delete(ss.m, c.Value)
		return nil, ""
	}
	return s, c.Value
}

func (ss *Sessions) ensure(w http.ResponseWriter, r *http.Request) *Session {
	if s, _ := ss.get(r); s != nil {
		return s
	}
	id := newSID()
	s := &Session{Exp: time.Now().Add(ss.ttl)}
	ss.mu.Lock()
	ss.m[id] = s
	ss.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(ss.ttl.Seconds()),
	})
	return s
}

func (ss *Sessions) SaveCeremony(w http.ResponseWriter, r *http.Request, sd *webauthn.SessionData, user string) {
	s := ss.ensure(w, r)
	ss.mu.Lock()
	s.WAData = sd
	s.CeremonyUser = user
	ss.mu.Unlock()
}

func (ss *Sessions) GetCeremony(r *http.Request) (*webauthn.SessionData, string, error) {
	s, _ := ss.get(r)
	if s == nil || s.WAData == nil {
		return nil, "", fmt.Errorf("no ceremony in progress")
	}
	return s.WAData, s.CeremonyUser, nil
}

func (ss *Sessions) SetAuth(w http.ResponseWriter, r *http.Request, user string) {
	s := ss.ensure(w, r)
	ss.mu.Lock()
	s.Authed = true
	s.AuthUser = user
	s.WAData = nil
	s.Exp = time.Now().Add(ss.ttl)
	ss.mu.Unlock()
}

func (ss *Sessions) CheckAuth(r *http.Request) (string, bool) {
	s, _ := ss.get(r)
	if s == nil {
		return "", false
	}
	return s.AuthUser, s.Authed
}

func (ss *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	ss.mu.Lock()
	delete(ss.m, c.Value)
	ss.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
}
```

---

## middleware.go

```go
package main

import (
	"net/http"
	"net/url"
)

// RequireAuth wraps a handler: unauthenticated requests get 302 to login page
func (s *Server) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.sessions.CheckAuth(r)
		if !ok {
			// redirect to login, preserving the original URL
			target := s.prefix + "/login?redirect=" + url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// inject user identity into request for downstream
		r.Header.Set("X-Webauthn-User", user)
		next.ServeHTTP(w, r)
	})
}
```

---

## handlers.go

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	wa       *webauthn.WebAuthn
	store    *Store
	sessions *Sessions
	prefix   string
}

// ── Check (programmatic, for external integrations) ────────

func (s *Server) Check(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.sessions.CheckAuth(r); ok {
		w.Header().Set("X-Webauthn-User", u)
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(401)
}

// ── Logout ─────────────────────────────────────────────────

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Destroy(w, r)
	http.Redirect(w, r, s.prefix+"/login", 302)
}

// ── Register page ──────────────────────────────────────────

func (s *Server) RegisterPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprint(w, registerHTML(s.prefix))
}

func (s *Server) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		jerr(w, "bad request", 400)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || strings.ContainsAny(body.Username, ": \t\n\r") {
		jerr(w, "invalid username (no spaces or colons)", 400)
		return
	}

	user := &WUser{id: []byte(body.Username), name: body.Username}

	// exclude existing credentials to prevent re-registration of same key
	var excl []protocol.CredentialDescriptor
	if ex := s.store.Find(body.Username); ex != nil {
		for _, c := range ex.creds {
			excl = append(excl, protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: c.ID,
			})
		}
	}

	opts, sd, err := s.wa.BeginRegistration(user,
		webauthn.WithExclusions(excl),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyPreferred),
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
	)
	if err != nil {
		log.Printf("BeginRegistration: %v", err)
		jerr(w, "server error", 500)
		return
	}

	s.sessions.SaveCeremony(w, r, sd, body.Username)
	jok(w, opts)
}

func (s *Server) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	sd, uname, err := s.sessions.GetCeremony(r)
	if err != nil {
		jerr(w, "no registration session — please start over", 400)
		return
	}

	user := &WUser{id: []byte(uname), name: uname}

	cred, err := s.wa.FinishRegistration(user, *sd, r)
	if err != nil {
		log.Printf("FinishRegistration: %v", err)
		jerr(w, fmt.Sprintf("registration failed: %v", err), 400)
		return
	}

	line := FormatLine(uname, cred)
	log.Printf("New credential for %q (pending admin approval)", uname)

	jok(w, map[string]any{
		"status":     "ok",
		"credential": line,
	})
}

// ── Login page ─────────────────────────────────────────────

func (s *Server) LoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.CheckAuth(r); ok {
		rd := r.URL.Query().Get("redirect")
		if rd == "" {
			rd = "/"
		}
		http.Redirect(w, r, rd, 302)
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprint(w, loginHTML(s.prefix))
}

func (s *Server) LoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	body.Username = strings.TrimSpace(body.Username)

	if body.Username == "" {
		// discoverable credential (passkey) flow — no username needed
		opts, sd, err := s.wa.BeginDiscoverableLogin(
			webauthn.WithUserVerification(protocol.VerificationPreferred),
		)
		if err != nil {
			log.Printf("BeginDiscoverableLogin: %v", err)
			jerr(w, "server error", 500)
			return
		}
		s.sessions.SaveCeremony(w, r, sd, "")
		jok(w, opts)
		return
	}

	user := s.store.Find(body.Username)
	if user == nil {
		jerr(w, "user not found in .htpasskey — ask admin to add your credential", 404)
		return
	}

	opts, sd, err := s.wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		log.Printf("BeginLogin(%s): %v", body.Username, err)
		jerr(w, "server error", 500)
		return
	}

	s.sessions.SaveCeremony(w, r, sd, body.Username)
	jok(w, opts)
}

func (s *Server) LoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	sd, uname, err := s.sessions.GetCeremony(r)
	if err != nil {
		jerr(w, "no login session — start over", 400)
		return
	}

	if uname == "" {
		// discoverable flow
		var authedUser string
		_, err := s.wa.FinishDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				u := s.store.FindByID(userHandle)
				if u == nil {
					return nil, fmt.Errorf("unknown user")
				}
				authedUser = u.name
				return u, nil
			},
			*sd, r,
		)
		if err != nil {
			log.Printf("FinishDiscoverableLogin: %v", err)
			jerr(w, fmt.Sprintf("login failed: %v", err), 401)
			return
		}
		log.Printf("Authenticated %q (discoverable)", authedUser)
		s.sessions.SetAuth(w, r, authedUser)
		jok(w, map[string]string{"status": "ok", "user": authedUser})
		return
	}

	// username flow
	user := s.store.Find(uname)
	if user == nil {
		jerr(w, "user disappeared from .htpasskey", 404)
		return
	}

	_, err = s.wa.FinishLogin(user, *sd, r)
	if err != nil {
		log.Printf("FinishLogin(%s): %v", uname, err)
		jerr(w, fmt.Sprintf("login failed: %v", err), 401)
		return
	}

	log.Printf("Authenticated %q", uname)
	s.sessions.SetAuth(w, r, uname)
	jok(w, map[string]string{"status": "ok", "user": uname})
}

// ── JSON helpers ───────────────────────────────────────────

func jok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
```

---

## pages.go

```go
package main

import "fmt"

func registerHTML(prefix string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register Passkey</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:12px;padding:2rem;max-width:600px;width:100%%;
  box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:.3rem}
.sub{color:#94a3b8;margin-bottom:1.5rem;font-size:.9rem;line-height:1.4}
label{display:block;font-size:.85rem;color:#cbd5e1;margin-bottom:.3rem}
input{width:100%%;padding:.6rem .8rem;border:1px solid #334155;border-radius:6px;
  background:#0f172a;color:#f1f5f9;font-size:1rem;margin-bottom:1rem;outline:none}
input:focus{border-color:#3b82f6}
.btn{display:block;width:100%%;padding:.7rem;border:none;border-radius:6px;font-size:1rem;
  cursor:pointer;color:#fff;text-align:center}
.btn-primary{background:#3b82f6}.btn-primary:hover{background:#2563eb}
.btn-copy{background:#059669;margin-top:.5rem}.btn-copy:hover{background:#047857}
.btn:disabled{background:#475569;cursor:not-allowed}
.result{display:none;margin-top:1.5rem}
.result.show{display:block}
.ok-box{background:#052e16;border:1px solid #16a34a;border-radius:8px;padding:1rem;margin-bottom:1rem}
.ok-box h3{color:#4ade80;margin-bottom:.3rem}
.cred-box{background:#020617;border:1px solid #334155;border-radius:6px;padding:.8rem;
  font-family:"SF Mono",Monaco,monospace;font-size:.72rem;word-break:break-all;
  white-space:pre-wrap;max-height:220px;overflow-y:auto;color:#a5b4fc;line-height:1.5;
  margin:.8rem 0;user-select:all}
.info{background:#172554;border:1px solid #1d4ed8;border-radius:8px;padding:1rem;
  font-size:.85rem;line-height:1.5;margin-top:1rem}
.info code{background:#0f172a;padding:.1rem .4rem;border-radius:3px;color:#93c5fd;font-size:.8rem}
.err{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:1rem;
  margin-top:1rem;display:none;color:#fca5a5}
.err.show{display:block}
.spinner{display:none;text-align:center;padding:1rem;color:#94a3b8}
.spinner.show{display:block}
.links{margin-top:1.5rem;text-align:center}
.links a{color:#60a5fa;text-decoration:none;font-size:.9rem}
</style></head>
<body>
<div class="card">
  <h1>🔐 Register Passkey</h1>
  <p class="sub">Create a WebAuthn credential. After registration, copy the credential text and send it to your administrator for approval.</p>

  <div id="form">
    <label for="u">Username</label>
    <input id="u" type="text" placeholder="alice" autocomplete="username webauthn"
           onkeydown="if(event.key==='Enter')go()">
    <button class="btn btn-primary" onclick="go()" id="gobtn">Register Passkey</button>
  </div>

  <div id="spin" class="spinner">⏳ Waiting for authenticator…</div>
  <div id="err" class="err"></div>

  <div id="result" class="result">
    <div class="ok-box">
      <h3>✅ Credential Created</h3>
      <p>Copy the text below and send it to your administrator.</p>
    </div>
    <div class="cred-box" id="cred"></div>
    <button class="btn btn-copy" onclick="doCopy()">📋 Copy to Clipboard</button>
    <div class="info">
      <strong>Admin:</strong> paste into <code>.htpasskey</code><br>
      <code>pbpaste >> /path/to/.htpasskey</code>
    </div>
  </div>

  <div class="links"><a href="%[1]s/login">Already registered? Login →</a></div>
</div>

<script>
const P=%[2]q;
const b2u=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%%4)s+='=';const d=atob(s),a=new Uint8Array(d.length);for(let i=0;i<d.length;i++)a[i]=d.charCodeAt(i);return a.buffer};

function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('show')}

async function go(){
  const username=document.getElementById('u').value.trim();
  if(!username){showErr('Enter a username');return}
  document.getElementById('err').classList.remove('show');
  document.getElementById('gobtn').disabled=true;
  document.getElementById('spin').classList.add('show');

  try{
    const r1=await fetch(P+'/register/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    if(!r1.ok)throw new Error((await r1.json()).error||'begin failed');
    const opts=await r1.json();

    opts.publicKey.challenge=u2b(opts.publicKey.challenge);
    opts.publicKey.user.id=u2b(opts.publicKey.user.id);
    if(opts.publicKey.excludeCredentials)opts.publicKey.excludeCredentials=opts.publicKey.excludeCredentials.map(c=>({...c,id:u2b(c.id)}));

    const cred=await navigator.credentials.create(opts);
    const body={id:cred.id,rawId:b2u(cred.rawId),type:cred.type,response:{
      attestationObject:b2u(cred.response.attestationObject),
      clientDataJSON:b2u(cred.response.clientDataJSON)}};
    if(cred.response.getTransports)body.response.transports=cred.response.getTransports();

    const r2=await fetch(P+'/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const res=await r2.json();
    if(!r2.ok)throw new Error(res.error||'finish failed');

    document.getElementById('cred').textContent=res.credential;
    document.getElementById('result').classList.add('show');
    document.getElementById('form').style.display='none';
  }catch(e){
    showErr(e.message||'Registration failed');
    document.getElementById('gobtn').disabled=false;
  }finally{
    document.getElementById('spin').classList.remove('show');
  }
}

function doCopy(){
  navigator.clipboard.writeText(document.getElementById('cred').textContent).then(()=>{
    const b=document.querySelector('.btn-copy');b.textContent='✅ Copied!';
    setTimeout(()=>b.textContent='📋 Copy to Clipboard',2000);
  });
}
</script>
</body></html>`, prefix, prefix)
}

func loginHTML(prefix string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Passkey</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:12px;padding:2rem;max-width:420px;width:100%%;
  box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:.3rem}
.sub{color:#94a3b8;margin-bottom:1.5rem;font-size:.9rem}
label{display:block;font-size:.85rem;color:#cbd5e1;margin-bottom:.3rem}
input{width:100%%;padding:.6rem .8rem;border:1px solid #334155;border-radius:6px;
  background:#0f172a;color:#f1f5f9;font-size:1rem;margin-bottom:1rem;outline:none}
input:focus{border-color:#3b82f6}
.btn{display:block;width:100%%;padding:.7rem;border:none;border-radius:6px;font-size:1rem;
  cursor:pointer;color:#fff;text-align:center;margin-bottom:.6rem}
.btn-primary{background:#3b82f6}.btn-primary:hover{background:#2563eb}
.btn-secondary{background:#475569;font-size:.9rem}.btn-secondary:hover{background:#374151}
.btn:disabled{background:#475569;cursor:not-allowed}
.or{text-align:center;color:#64748b;margin:.6rem 0;font-size:.85rem}
.err{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:1rem;
  margin-bottom:1rem;display:none;color:#fca5a5}
.err.show{display:block}
.spinner{display:none;text-align:center;padding:1rem;color:#94a3b8}
.spinner.show{display:block}
.links{margin-top:1.5rem;text-align:center}
.links a{color:#60a5fa;text-decoration:none;font-size:.9rem}
</style></head>
<body>
<div class="card">
  <h1>🔑 Login</h1>
  <p class="sub">Authenticate with your passkey.</p>
  <div id="err" class="err"></div>

  <button class="btn btn-primary" onclick="doLogin('')" id="pkbtn">🔐 Login with Passkey</button>
  <div class="or">— or enter username —</div>
  <label for="u">Username</label>
  <input id="u" type="text" placeholder="alice" autocomplete="username webauthn"
         onkeydown="if(event.key==='Enter')doLoginUser()">
  <button class="btn btn-secondary" onclick="doLoginUser()" id="ubtn">Login as User</button>
  <div id="spin" class="spinner">⏳ Waiting for authenticator…</div>
  <div class="links"><a href="%[1]s/register">Need to register? →</a></div>
</div>

<script>
const P=%[2]q;
const b2u=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%%4)s+='=';const d=atob(s),a=new Uint8Array(d.length);for(let i=0;i<d.length;i++)a[i]=d.charCodeAt(i);return a.buffer};

function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('show')}
function getRedir(){return new URLSearchParams(location.search).get('redirect')||'/'}

async function doLogin(username){
  document.getElementById('err').classList.remove('show');
  document.getElementById('pkbtn').disabled=true;
  document.getElementById('ubtn').disabled=true;
  document.getElementById('spin').classList.add('show');

  try{
    const r1=await fetch(P+'/login/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    if(!r1.ok)throw new Error((await r1.json()).error||'begin failed');
    const opts=await r1.json();

    opts.publicKey.challenge=u2b(opts.publicKey.challenge);
    if(opts.publicKey.allowCredentials)
      opts.publicKey.allowCredentials=opts.publicKey.allowCredentials.map(c=>({...c,id:u2b(c.id)}));

    const assertion=await navigator.credentials.get(opts);
    const body={id:assertion.id,rawId:b2u(assertion.rawId),type:assertion.type,response:{
      authenticatorData:b2u(assertion.response.authenticatorData),
      clientDataJSON:b2u(assertion.response.clientDataJSON),
      signature:b2u(assertion.response.signature)}};
    if(assertion.response.userHandle)body.response.userHandle=b2u(assertion.response.userHandle);

    const r2=await fetch(P+'/login/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const res=await r2.json();
    if(!r2.ok)throw new Error(res.error||'login failed');

    location.href=getRedir();
  }catch(e){
    showErr(e.message||'Login failed');
    document.getElementById('pkbtn').disabled=false;
    document.getElementById('ubtn').disabled=false;
  }finally{
    document.getElementById('spin').classList.remove('show');
  }
}

function doLoginUser(){
  const u=document.getElementById('u').value.trim();
  if(!u){showErr('Enter a username');return}
  doLogin(u);
}
</script>
</body></html>`, prefix, prefix)
}
```

---

## 构建与运行

```bash
# 初始化
go mod tidy
go build -o webauthn-gate .

# 最简运行（自签证书，内置欢迎页）
./webauthn-gate

# 反向代理模式（保护后端服务）
./webauthn-gate -backend http://127.0.0.1:3000

# 静态文件模式（保护目录）
./webauthn-gate -webroot ./public

# 完整参数
./webauthn-gate \
  -listen :443 \
  -rp-id example.com \
  -rp-origin https://example.com \
  -tls-cert /etc/ssl/cert.pem \
  -tls-key /etc/ssl/key.pem \
  -htpasskey /etc/webauthn/.htpasskey \
  -backend /fwd?q=aHR0cDovLzEyNy4wLjAu1:8080 \
  -session-ttl 12h
```

---

## 使用流程

### 1. 用户注册

```
浏览器访问 https://yoursite/__webauthn/register
  → 输入用户名，触发 Touch ID / Windows Hello / 安全密钥
  → 得到一段凭据文本
  → 用户把这段文本发给管理员（Slack、邮件等）
```

### 2. 管理员授权

```bash
# macOS: 用户把凭据复制到剪贴板发过来
pbpaste >> .htpasskey

# 或直接编辑
echo '# alice | cred:AbCdEf... | 2024-01-15
alice:eyJ1Ijoi...' >> .htpasskey

# 服务自动检测文件变更并重新加载，无需重启
```

### 3. 用户登录

```
浏览器访问任意受保护页面
  → 自动 302 重定向到 /__webauthn/login
  → 点击 "Login with Passkey" 或输入用户名
  → Touch ID / 安全密钥验证
  → 跳回原始页面
```

---

## .htpasskey 文件格式

```
# .htpasskey — WebAuthn credentials
# 格式: username:base64(json)
# 服务自动监测文件修改，热加载

# alice | cred:R0x1Y2tJZEhlcm... | 2024-07-15T08:30:00Z
alice:eyJ1IjoiYWxpY2UiLCJpZCI6IlIweDFZMnRKWkdobGNnIiwicHViIjoicE...

# bob | cred:U2VjdXJpdHlLZX... | 2024-07-16T10:00:00Z
bob:eyJ1IjoiYm9iIiwiaWQiOiJVMlZqZFhKcGRIbExaWGgi...
```


---

./handlers.go:80:48: undefined: protocol.ResidentKeyPreferred
我感觉是webauthn版本升级了？


是的，`go-webauthn/webauthn` 库在不同版本间 API 有变化。让我修复所有兼容性问题。

先查清当前版本的正确 API：

```bash
go doc github.com/go-webauthn/webauthn/protocol ResidentKeyRequirement
```

**核心变化**：`protocol.ResidentKeyPreferred` 改为了 `protocol.ResidentKeyRequirementPreferred`，以及其他一些 API 调整。

以下是修正后的完整 **handlers.go**：

## handlers.go

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	wa       *webauthn.WebAuthn
	store    *Store
	sessions *Sessions
	prefix   string
}

// ── Check (programmatic) ──────────────────────────────────

func (s *Server) Check(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.sessions.CheckAuth(r); ok {
		w.Header().Set("X-Webauthn-User", u)
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(401)
}

// ── Logout ────────────────────────────────────────────────

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Destroy(w, r)
	http.Redirect(w, r, s.prefix+"/login", 302)
}

// ── Register ──────────────────────────────────────────────

func (s *Server) RegisterPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprint(w, registerHTML(s.prefix))
}

func (s *Server) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		jerr(w, "bad request", 400)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if body.Username == "" || strings.ContainsAny(body.Username, ": \t\n\r") {
		jerr(w, "invalid username (no spaces or colons)", 400)
		return
	}

	user := &WUser{id: []byte(body.Username), name: body.Username}

	// exclude already-registered credentials
	var excl []protocol.CredentialDescriptor
	if ex := s.store.Find(body.Username); ex != nil {
		for _, c := range ex.creds {
			excl = append(excl, protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: c.ID,
			})
		}
	}

	opts, sd, err := s.wa.BeginRegistration(user,
		webauthn.WithExclusions(excl),
		// 使用兼容方式设置 authenticator selection
		func(cco *protocol.PublicKeyCredentialCreationOptions) {
			cco.AuthenticatorSelection = protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementPreferred,
				UserVerification: protocol.VerificationPreferred,
			}
			cco.Attestation = protocol.PreferDirectAttestation
		},
	)
	if err != nil {
		log.Printf("BeginRegistration: %v", err)
		jerr(w, "server error", 500)
		return
	}

	s.sessions.SaveCeremony(w, r, sd, body.Username)
	jok(w, opts)
}

func (s *Server) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	sd, uname, err := s.sessions.GetCeremony(r)
	if err != nil {
		jerr(w, "no registration session — please start over", 400)
		return
	}

	user := &WUser{id: []byte(uname), name: uname}

	cred, err := s.wa.FinishRegistration(user, *sd, r)
	if err != nil {
		log.Printf("FinishRegistration: %v", err)
		jerr(w, fmt.Sprintf("registration failed: %v", err), 400)
		return
	}

	line := FormatLine(uname, cred)
	log.Printf("New credential for %q (pending admin approval)", uname)

	jok(w, map[string]any{
		"status":     "ok",
		"credential": line,
	})
}

// ── Login ─────────────────────────────────────────────────

func (s *Server) LoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.CheckAuth(r); ok {
		rd := r.URL.Query().Get("redirect")
		if rd == "" {
			rd = "/"
		}
		http.Redirect(w, r, rd, 302)
		return
	}
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprint(w, loginHTML(s.prefix))
}

func (s *Server) LoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	var body struct {
		Username string `json:"username"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	body.Username = strings.TrimSpace(body.Username)

	if body.Username == "" {
		// discoverable credential (passkey) flow
		opts, sd, err := s.wa.BeginDiscoverableLogin(
			func(opts *protocol.PublicKeyCredentialRequestOptions) {
				opts.UserVerification = protocol.VerificationPreferred
			},
		)
		if err != nil {
			log.Printf("BeginDiscoverableLogin: %v", err)
			jerr(w, "server error", 500)
			return
		}
		s.sessions.SaveCeremony(w, r, sd, "")
		jok(w, opts)
		return
	}

	user := s.store.Find(body.Username)
	if user == nil {
		jerr(w, "user not found in .htpasskey — ask admin to add your credential", 404)
		return
	}

	opts, sd, err := s.wa.BeginLogin(user,
		func(opts *protocol.PublicKeyCredentialRequestOptions) {
			opts.UserVerification = protocol.VerificationPreferred
		},
	)
	if err != nil {
		log.Printf("BeginLogin(%s): %v", body.Username, err)
		jerr(w, "server error", 500)
		return
	}

	s.sessions.SaveCeremony(w, r, sd, body.Username)
	jok(w, opts)
}

func (s *Server) LoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}

	sd, uname, err := s.sessions.GetCeremony(r)
	if err != nil {
		jerr(w, "no login session — start over", 400)
		return
	}

	if uname == "" {
		// discoverable flow
		var authedUser string
		_, err := s.wa.FinishDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				u := s.store.FindByID(userHandle)
				if u == nil {
					return nil, fmt.Errorf("unknown user")
				}
				authedUser = u.name
				return u, nil
			},
			*sd, r,
		)
		if err != nil {
			log.Printf("FinishDiscoverableLogin: %v", err)
			jerr(w, fmt.Sprintf("login failed: %v", err), 401)
			return
		}
		log.Printf("Authenticated %q (discoverable)", authedUser)
		s.sessions.SetAuth(w, r, authedUser)
		jok(w, map[string]string{"status": "ok", "user": authedUser})
		return
	}

	user := s.store.Find(uname)
	if user == nil {
		jerr(w, "user disappeared from .htpasskey", 404)
		return
	}

	_, err = s.wa.FinishLogin(user, *sd, r)
	if err != nil {
		log.Printf("FinishLogin(%s): %v", uname, err)
		jerr(w, fmt.Sprintf("login failed: %v", err), 401)
		return
	}

	log.Printf("Authenticated %q", uname)
	s.sessions.SetAuth(w, r, uname)
	jok(w, map[string]string{"status": "ok", "user": uname})
}

// ── JSON helpers ──────────────────────────────────────────

func jok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
```

**关键改动**：

1. **`RegisterBegin`** — 不再用 `webauthn.WithResidentKeyRequirement()` 和 `webauthn.WithConveyancePreference()`，改用直接传 `func(cco *protocol.PublicKeyCredentialCreationOptions)` 闭包手动设置字段
2. **`LoginBegin`** — 不再用 `webauthn.WithUserVerification()`，改用 `func(opts *protocol.PublicKeyCredentialRequestOptions)` 闭包
3. **`ResidentKeyRequirementPreferred`** — 这是新版本中的正确常量名

如果编译时还有其他符号找不到，运行这个查看你实际安装的版本中可用的常量：

```bash
go doc github.com/go-webauthn/webauthn/protocol | grep -i resident
go doc github.com/go-webauthn/webauthn/protocol | grep -i verification
go doc github.com/go-webauthn/webauthn/protocol | grep -i attestation
```

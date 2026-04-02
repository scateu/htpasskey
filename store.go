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
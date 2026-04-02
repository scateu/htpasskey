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
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
		// 处理BackupEligible不一致的问题，降级处理
		errStr := err.Error()
		if strings.Contains(errStr, "BackupEligible") || strings.Contains(errStr, "backup") {
			log.Printf("Ignoring BackupEligible flag mismatch for %q", authedUser)
		} else {

			log.Printf("FinishDiscoverableLogin: %v", err)
			jerr(w, fmt.Sprintf("login failed: %v", err), 401)
			return
		}
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

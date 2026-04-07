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

// ── Check ─────────────────────────────────────────────────

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
    log.Printf("New credential for %q — BE=%v BS=%v (pending admin approval)",
        uname, cred.Flags.BackupEligible, cred.Flags.BackupState)

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

// parseLoginAuthData 从 authenticatorData 前几个字节中提取 flags
// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
// authData[32] = flags byte:  bit0=UP, bit2=UV, bit3=BE, bit4=BS, bit6=AT, bit7=ED
func parseLoginFlags(authData []byte) (be bool, bs bool, ok bool) {
    if len(authData) < 33 {
        return false, false, false
    }
    flags := authData[32]
    be = (flags & 0x08) != 0 // bit 3
    bs = (flags & 0x10) != 0 // bit 4
    return be, bs, true
}

// getStoredFlags 从 store 中查找匹配的 credential 返回注册时保存的 flags
func (s *Server) getStoredFlags(user *WUser, credID []byte) (be bool, bs bool, found bool) {
    if user == nil {
        return
    }
    for _, c := range user.creds {
        if bytesEqual(c.ID, credID) {
            return c.Flags.BackupEligible, c.Flags.BackupState, true
        }
    }
    return
}

func bytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
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
        var resolvedUser *WUser
        cred, err := s.wa.FinishDiscoverableLogin(
            func(rawID, userHandle []byte) (webauthn.User, error) {
                u := s.store.FindByID(userHandle)
                if u == nil {
                    return nil, fmt.Errorf("unknown user")
                }
                authedUser = u.name
                resolvedUser = u
                return u, nil
            },
            *sd, r,
        )
        if err != nil {
            errStr := err.Error()
            if strings.Contains(errStr, "BackupEligible") || strings.Contains(errStr, "backup") {
                // 输出详细的 flag 比较信息
                var loginBE, loginBS bool
                if cred != nil {
                    loginBE = cred.Flags.BackupEligible
                    loginBS = cred.Flags.BackupState
                }
                storedBE, storedBS, found := s.getStoredFlags(resolvedUser, sd.UserID)
                log.Printf("BackupEligible mismatch for %q — "+
                    "stored(BE=%v, BS=%v, found=%v) vs login(BE=%v, BS=%v) — allowing anyway",
                    authedUser, storedBE, storedBS, found, loginBE, loginBS)
            } else {
                log.Printf("FinishDiscoverableLogin: %v", err)
                jerr(w, fmt.Sprintf("login failed: %v", err), 401)
                return
            }
        }
        if authedUser == "" {
            jerr(w, "login failed: user not resolved", 401)
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

    cred, err := s.wa.FinishLogin(user, *sd, r)
    if err != nil {
        errStr := err.Error()
        if strings.Contains(errStr, "BackupEligible") || strings.Contains(errStr, "backup") {
            // 从返回的 credential 中拿登录时的 flags
            var loginBE, loginBS bool
            if cred != nil {
                loginBE = cred.Flags.BackupEligible
                loginBS = cred.Flags.BackupState
            }
            // 从 store 中拿注册时的 flags
            storedBE, storedBS, found := false, false, false
            if cred != nil {
                storedBE, storedBS, found = s.getStoredFlags(user, cred.ID)
            }
            log.Printf("BackupEligible mismatch for %q — "+
                "stored(BE=%v, BS=%v, found=%v) vs login(BE=%v, BS=%v) — allowing anyway",
                uname, storedBE, storedBS, found, loginBE, loginBS)
        } else {
            log.Printf("FinishLogin(%s): %v", uname, err)
            jerr(w, fmt.Sprintf("login failed: %v", err), 401)
            return
        }
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
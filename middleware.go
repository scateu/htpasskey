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
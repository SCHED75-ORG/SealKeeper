package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
)

// cspDirectives is the policy for every response. Pages that need inline
// scripts swap in a per-response nonce via scriptNonce; there is no
// 'unsafe-inline' for scripts. Styles stay inline-capable (style= attributes
// throughout the templates) and fonts come from fonts.bunny.net.
const cspDirectives = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.bunny.net; " +
	"font-src https://fonts.bunny.net; img-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func cspWithScripts(scriptSrc string) string {
	return cspDirectives + "; script-src " + scriptSrc
}

// securityHeaders sets the browser hardening headers on every response.
// Referrer-Policy matters most on /reveal/{token}: without it the token
// leaks to fonts.bunny.net in the Referer of the stylesheet request.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	hsts := strings.HasPrefix(s.cfg.BaseURL, "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspWithScripts("'self'"))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// scriptNonce mints a nonce, allows it in this response's CSP and returns
// it for the template (<script nonce="{{ $.CSPNonce }}">). Call it before
// writing the body.
func scriptNonce(w http.ResponseWriter) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// No nonce means inline scripts are blocked: fail closed.
		return ""
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	w.Header().Set("Content-Security-Policy", cspWithScripts("'self' 'nonce-"+n+"'"))
	return n
}

// slugRe is the shape of every ?err= / ?ok= value the handlers emit.
var slugRe = regexp.MustCompile(`^[a-z0-9_]{1,48}$`)

// querySlug returns the named query parameter only when it looks like one
// of our status slugs. Free text from a crafted link (content spoofing on
// the login page of a security product) is dropped.
func querySlug(r *http.Request, name string) string {
	v := r.URL.Query().Get(name)
	if !slugRe.MatchString(v) {
		return ""
	}
	return v
}

// staticFS serves files from dir but refuses directories (no listings, no
// index.html fallbacks) and any path segment starting with '.' (.env, .git).
type staticFS struct{ dir http.Dir }

func (f staticFS) Open(name string) (http.File, error) {
	for _, seg := range strings.Split(path.Clean("/"+name), "/") {
		if strings.HasPrefix(seg, ".") {
			return nil, os.ErrNotExist
		}
	}
	file, err := f.dir.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := file.Stat()
	if err != nil || st.IsDir() {
		_ = file.Close()
		return nil, os.ErrNotExist
	}
	return file, nil
}

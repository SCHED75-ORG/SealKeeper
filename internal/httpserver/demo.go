package httpserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/mailcapture"
)

// Public demo model (FR-H.78..81)
//
// A demo is shared by strangers, so it must never let one visitor affect
// another beyond the 24h reset, nor see another visitor's data:
//
//   - The admin console is read-only except for the demo story itself:
//     the first-login setup wizard and the domains / policies / elevations /
//     templates tables, which the reset wipes. Accounts, branding, SMTP,
//     security keys, integrations and libraries are refused here, on top
//     of the per-handler FR-H.80/81 checks.
//   - The reset (internal/demo) restores accounts, branding, SMTP and kv
//     from the boot snapshot and purges the capture queue.
//   - Captured mail is scoped per browser: POST /api/v1/request sets an
//     opaque capture cookie and the mail is tagged with it, so a visitor
//     only ever sees the reveal link they asked for themselves.

// cookieDemoCapture carries the per-browser capture handle (demo only).
const cookieDemoCapture = "sk_demo_capture"

// demoWritable lists the session-gated POST routes a demo visitor may use.
// Entries ending in "/" match a whole subtree.
var demoWritable = []string{
	"/admin/setup",
	"/admin/domains/",
	"/admin/policies/",
	"/admin/elevations/",
	"/admin/templates/",
}

func demoWritablePath(p string) bool {
	for _, allowed := range demoWritable {
		if strings.HasSuffix(allowed, "/") {
			if strings.HasPrefix(p, allowed) {
				return true
			}
		} else if p == allowed {
			return true
		}
	}
	return false
}

// demoReadOnly refuses every mutating admin request outside demoWritable
// when the instance runs as a public demo. A no-op otherwise.
func (s *Server) demoReadOnly(next http.Handler) http.Handler {
	if !s.cfg.IsDemo() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || demoWritablePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		s.logger.Info("demo mode — admin mutation refused", "path", r.URL.Path)
		section, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/admin/"), "/")
		// The WebAuthn ceremonies are fetch() calls that expect a status,
		// not a page.
		if section == "security" && (strings.HasSuffix(r.URL.Path, "/begin") || strings.HasSuffix(r.URL.Path, "/finish")) {
			http.Error(w, "disabled on the public demo", http.StatusForbidden)
			return
		}
		if section == "" || !slugRe.MatchString(section) {
			section = "dashboard"
		}
		http.Redirect(w, r, "/admin/"+section+"?err=demo_readonly", http.StatusSeeOther)
	})
}

// demoCaptureHandle returns the capture owner for this request and, on a
// public demo, (re)sets the browser's capture cookie. It is called on
// every POST /api/v1/request whatever the outcome, so the cookie itself
// says nothing about the allowlist. Returns "" outside demo mode.
func (s *Server) demoCaptureHandle(w http.ResponseWriter, r *http.Request) string {
	if !s.cfg.IsDemo() {
		return ""
	}
	value := ""
	if c, err := r.Cookie(cookieDemoCapture); err == nil && validCaptureHandle(c.Value) {
		value = c.Value
	} else {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return ""
		}
		value = base64.RawURLEncoding.EncodeToString(buf)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieDemoCapture,
		Value:    value,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   strings.HasPrefix(strings.ToLower(s.cfg.BaseURL), "https://"),
	})
	return captureOwner(value)
}

// demoCaptureOwner resolves the capture owner from the request cookie,
// "" when absent or malformed (which matches no mail).
func (s *Server) demoCaptureOwner(r *http.Request) string {
	c, err := r.Cookie(cookieDemoCapture)
	if err != nil || !validCaptureHandle(c.Value) {
		return ""
	}
	return captureOwner(c.Value)
}

// capturedMailFor is the captured-mail view for this caller: the whole
// queue in eval mode, only the caller's own mail on a public demo.
func (s *Server) capturedMailFor(r *http.Request) []mailcapture.Mail {
	if s.cfg.IsDemo() {
		return s.mail.SnapshotFor(s.demoCaptureOwner(r))
	}
	return s.mail.Snapshot()
}

func validCaptureHandle(v string) bool {
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// captureOwner stores a digest, not the cookie, in the capture queue.
func captureOwner(handle string) string {
	sum := sha256.Sum256([]byte("sealkeeper-demo-capture:" + handle))
	return hex.EncodeToString(sum[:])
}

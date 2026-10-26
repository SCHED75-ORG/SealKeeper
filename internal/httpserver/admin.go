package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/totp"
	"github.com/sched75/sealkeeper/internal/webauthn"
	"rsc.io/qr"
)

// opaqueToken returns n random bytes encoded as URL-safe base64 (no padding).
func opaqueToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// adminConstantTime is the minimum wall-clock cost of POST /admin/login.
// FR-C.9 — pad fast paths so success / failure / "not found" look identical
// to a stopwatch attacker.
const adminConstantTime = 300 * time.Millisecond

const (
	cookieAdminSession = "sk_admin_session"
	cookieAdminCSRF    = "sk_admin_csrf"
	cookieLoginCSRF    = "sk_admin_login_csrf"
)

// SetAdmin binds the admin repo + cryptobox. /admin/* routes only mount when
// this has been called.
func (s *Server) SetAdmin(repo *admin.Repo, instanceLabel string) {
	s.adminRepo = repo
	if instanceLabel != "" {
		s.adminLabel = instanceLabel
	} else {
		s.adminLabel = s.cfg.InstanceDomain
	}
}

func (s *Server) registerAdminRoutes(r chi.Router) {
	r.Route("/admin", func(r chi.Router) {
		r.Use(sameOriginPOST)
		r.Get("/", s.handleAdminRoot)
		r.Get("/login", s.handleAdminLoginGet)
		r.Post("/login", s.handleAdminLoginPost)
		r.Get("/login/webauthn", s.handleAdminLoginWebauthnGet)
		r.Post("/login/webauthn/begin", s.handleAdminLoginWebauthnBegin)
		r.Post("/login/webauthn/finish", s.handleAdminLoginWebauthnFinish)
		r.Post("/login/webauthn/cancel", s.handleAdminLoginWebauthnCancel)
		r.Post("/logout", s.handleAdminLogout)
		r.Group(func(r chi.Router) {
			r.Use(s.adminRequireSession)
			r.Get("/setup", s.handleAdminSetupGet)
			r.Post("/setup", s.handleAdminSetupPost)
			r.Get("/dashboard", s.handleAdminDashboard)
			r.Get("/audit", s.handleAdminAudit)
			r.Get("/captured-mail", s.handleAdminCapturedMail)
			r.Get("/domains", s.handleAdminDomains)
			r.Post("/domains/add", s.handleAdminDomainAdd)
			r.Post("/domains/import", s.handleAdminDomainImport)
			r.Post("/domains/{id}/toggle", s.handleAdminDomainToggle)
			r.Post("/domains/{id}/delete", s.handleAdminDomainDelete)
			r.Get("/policies", s.handleAdminPolicies)
			r.Post("/policies/add", s.handleAdminPolicyAdd)
			r.Get("/policies/{id}/edit", s.handleAdminPolicyEdit)
			r.Post("/policies/{id}/save", s.handleAdminPolicySave)
			r.Post("/policies/{id}/toggle", s.handleAdminPolicyToggle)
			r.Post("/policies/{id}/delete", s.handleAdminPolicyDelete)
			r.Get("/elevations", s.handleAdminElevations)
			r.Post("/elevations/add", s.handleAdminElevationAdd)
			r.Post("/elevations/import", s.handleAdminElevationImport)
			r.Post("/elevations/{id}/delete", s.handleAdminElevationDelete)
			r.Get("/libraries", s.handleAdminLibraries)
			r.Post("/libraries/upload", s.handleAdminLibraryUpload)
			r.Get("/libraries/{id}/download", s.handleAdminLibraryDownload)
			r.Get("/libraries/{id}/sample", s.handleAdminLibrarySample)
			r.Post("/libraries/{id}/delete", s.handleAdminLibraryDelete)
			r.Get("/templates", s.handleAdminTemplates)
			r.Get("/templates/edit", s.handleAdminTemplateEdit)
			r.Post("/templates/save", s.handleAdminTemplateSave)
			r.Post("/templates/preview", s.handleAdminTemplatePreview)
			r.Post("/templates/reset", s.handleAdminTemplateReset)
			r.Get("/integrations", s.handleAdminIntegrations)
			r.Post("/integrations/add", s.handleAdminIntegrationAdd)
			r.Post("/integrations/{id}/toggle", s.handleAdminIntegrationToggle)
			r.Post("/integrations/{id}/delete", s.handleAdminIntegrationDelete)
			r.Post("/integrations/{id}/test", s.handleAdminIntegrationTest)
			r.Get("/branding", s.handleAdminBranding)
			r.Post("/branding/save", s.handleAdminBrandingSave)
			r.Post("/branding/logo", s.handleAdminBrandingLogo)
			r.Post("/branding/logo/clear", s.handleAdminBrandingLogoClear)
			r.Get("/smtp", s.handleAdminSMTP)
			r.Post("/smtp/save", s.handleAdminSMTPSave)
			r.Post("/smtp/test", s.handleAdminSMTPTest)
			r.Post("/smtp/clear", s.handleAdminSMTPClear)
			r.Get("/security", s.handleAdminSecurity)
			r.Post("/security/begin", s.handleAdminWebauthnBegin)
			r.Post("/security/finish", s.handleAdminWebauthnFinish)
			r.Post("/security/{id}/rename", s.handleAdminWebauthnRename)
			r.Post("/security/{id}/delete", s.handleAdminWebauthnDelete)
			r.Get("/account", s.handleAdminAccount)
			r.Post("/account/email", s.handleAdminAccountEmailChange)
			r.Post("/account/password", s.handleAdminAccountPasswordChange)
			r.Get("/admins", s.handleAdminAdmins)
			r.Post("/admins/add", s.handleAdminAdminAdd)
			r.Post("/admins/{id}/toggle", s.handleAdminAdminToggle)
			r.Post("/admins/{id}/delete", s.handleAdminAdminDelete)
		})
	})
}

// adminRequireSession is the gate for everything past /admin/login. It
// loads the session, redirects to /admin/login on miss, and forces the
// setup flow when password / TOTP enrollment is pending.
func (s *Server) adminRequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ad, err := s.loadAdminSession(r)
		if err != nil {
			s.clearAdminCookies(w)
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		// FR-C.3 / FR-C.4: until both bits clear, the only allowed route is
		// /admin/setup. Logout stays available so a stuck user can bail out.
		needsSetup := ad.ForcePasswordChange || ad.ForceTOTPEnroll
		if needsSetup && !strings.HasPrefix(r.URL.Path, "/admin/setup") {
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyAdmin, ad)
		ctx = context.WithValue(ctx, ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type adminCtxKey struct{ name string }

var (
	ctxKeyAdmin   = adminCtxKey{name: "admin"}
	ctxKeySession = adminCtxKey{name: "admin-session"}
)

func adminFromCtx(r *http.Request) (admin.Admin, admin.Session, bool) {
	a, _ := r.Context().Value(ctxKeyAdmin).(admin.Admin)
	s, _ := r.Context().Value(ctxKeySession).(admin.Session)
	return a, s, a.ID != 0
}

// ----- handlers -------------------------------------------------------------

func (s *Server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.loadAdminSession(r); err == nil {
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (s *Server) handleAdminLoginGet(w http.ResponseWriter, r *http.Request) {
	if s.adminRepo == nil {
		http.Error(w, "admin disabled (no storage)", http.StatusServiceUnavailable)
		return
	}
	csrf, _ := opaqueToken(24)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieLoginCSRF,
		Value:    csrf,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(15 * time.Minute),
	})
	s.renderAdmin(w, "login", map[string]any{
		"CSRF":       csrf,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Error":      querySlug(r, "err"),
	})
}

func (s *Server) handleAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(adminConstantTime)
	defer func() {
		if rem := time.Until(deadline); rem > 0 {
			time.Sleep(rem)
		}
	}()

	if s.adminRepo == nil {
		http.Error(w, "admin disabled (no storage)", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminLoginError(w, r, "bad_form")
		return
	}
	if !s.checkLoginCSRF(r) {
		s.adminLoginError(w, r, "csrf")
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "rate_limited"})
		s.adminLoginError(w, r, "rate_limited")
		return
	}
	totpCode := strings.TrimSpace(r.FormValue("totp"))

	res, err := s.adminRepo.Authenticate(r.Context(), email, password, totpCode)
	switch {
	case errors.Is(err, admin.ErrInvalidCreds):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "credentials"})
		s.adminLoginError(w, r, "bad_creds")
		return
	case errors.Is(err, admin.ErrAccountLocked):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "locked"})
		s.adminLoginError(w, r, "locked")
		return
	case errors.Is(err, admin.ErrAccountDisabled):
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "disabled"})
		s.adminLoginError(w, r, "disabled")
		return
	case errors.Is(err, admin.ErrTOTPUnrecoverable):
		s.logger.Error("admin.Authenticate: TOTP secret unrecoverable", "err", err, "email", email)
		s.auditAppend(r.Context(), "admin.login_failed", email, "", map[string]any{"reason": "totp_unrecoverable"})
		s.adminLoginError(w, r, "totp_unrecoverable")
		return
	case errors.Is(err, admin.ErrTOTPRequired):
		// Password OK, but the second factor still needs to be supplied.
		// Branch to the WebAuthn step-up flow when the admin has at least
		// one registered key — otherwise re-render the form asking for
		// the TOTP code on top of the existing inputs.
		if s.tryWebauthnStepUp(w, r, res.Admin) {
			return
		}
		s.adminLoginError(w, r, "totp_required")
		return
	case err != nil:
		s.logger.Error("admin.Authenticate failed", "err", err)
		s.adminLoginError(w, r, "internal")
		return
	}
	if res.UsedRecoveryCode {
		s.auditAppend(r.Context(), "admin.recovery_code_used", email, "", nil)
	}

	sess, err := s.adminRepo.CreateSession(r.Context(), res.Admin.ID,
		s.hashShort(s.clientIP(r)), s.hashShort(r.UserAgent()))
	if err != nil {
		s.logger.Error("admin.CreateSession failed", "err", err)
		s.adminLoginError(w, r, "internal")
		return
	}
	s.setAdminCookies(w, sess)
	s.auditAppend(r.Context(), "admin.login", res.Admin.Email, "", map[string]any{
		"needs_setup": res.NeedsPasswordChange || res.NeedsTOTPEnrollment,
	})
	if res.NeedsPasswordChange || res.NeedsTOTPEnrollment {
		http.Redirect(w, r, "/admin/setup", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieAdminSession); err == nil {
		// Require the session's CSRF token so a cross-site POST cannot log
		// the operator out (e.g. in the middle of an incident).
		if sess, _, err := s.adminRepo.LookupSession(r.Context(), c.Value); err == nil {
			_ = r.ParseForm()
			if !constantTimeEqualString(sess.CSRFToken, r.FormValue("csrf_token")) {
				http.Error(w, "csrf", http.StatusForbidden)
				return
			}
		}
		_ = s.adminRepo.RevokeSession(r.Context(), c.Value)
	}
	s.clearAdminCookies(w)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// cookieAdminLoginStep is the HttpOnly cookie carrying the in-memory
// pending-login token between the password POST and the WebAuthn
// assertion exchange. SameSite=Strict and a 5-minute TTL.
const cookieAdminLoginStep = "sk_admin_login_step"

// cookieAdminLoginAssertion carries the (encrypted-on-disk-only because
// it's just a JSON blob signed by the WebAuthn library's own challenge)
// session data from /begin to /finish so the server can stay stateless
// about the in-flight assertion. Mirrors how the registration path uses
// cookieWebauthnSession.
const cookieAdminLoginAssertion = "sk_admin_login_assertion"

// tryWebauthnStepUp checks whether the admin has registered any WebAuthn
// keys and, if so, issues a pending-login token + redirects the browser to
// the WebAuthn assertion page. Returns true when the redirect was emitted
// (caller should not write again).
func (s *Server) tryWebauthnStepUp(w http.ResponseWriter, r *http.Request, ad admin.Admin) bool {
	if s.webauthn == nil || s.loginPending == nil {
		return false
	}
	has, err := s.webauthn.HasCredentials(r.Context(), ad.ID)
	if err != nil {
		s.logger.Warn("webauthn.HasCredentials failed during login", "err", err)
		return false
	}
	if !has {
		return false
	}
	tok, expires, err := s.loginPending.Issue(ad.ID)
	if err != nil {
		s.logger.Error("loginPending.Issue failed", "err", err)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminLoginStep,
		Value:    tok,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  expires,
	})
	s.auditAppend(r.Context(), "admin.webauthn_login_started", ad.Email, "", nil)
	http.Redirect(w, r, "/admin/login/webauthn", http.StatusSeeOther)
	return true
}

// loadPendingLogin reads the step-up cookie and resolves it back to the
// admin row. Returns the admin and the pending-token so /finish can
// consume it; returns ok=false when the token is missing or expired.
func (s *Server) loadPendingLogin(r *http.Request) (admin.Admin, string, bool) {
	if s.loginPending == nil || s.adminRepo == nil {
		return admin.Admin{}, "", false
	}
	c, err := r.Cookie(cookieAdminLoginStep)
	if err != nil {
		return admin.Admin{}, "", false
	}
	adminID, ok := s.loginPending.Lookup(c.Value)
	if !ok {
		return admin.Admin{}, "", false
	}
	ad, err := s.adminRepo.FindByID(r.Context(), adminID)
	if err != nil {
		return admin.Admin{}, "", false
	}
	return ad, c.Value, true
}

func (s *Server) handleAdminLoginWebauthnGet(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil || s.adminRepo == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	ad, _, ok := s.loadPendingLogin(r)
	if !ok {
		http.Redirect(w, r, "/admin/login?err=session_expired", http.StatusSeeOther)
		return
	}
	csrf, _ := opaqueToken(24)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieLoginCSRF,
		Value:    csrf,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(15 * time.Minute),
	})
	s.renderAdmin(w, "login_webauthn", map[string]any{
		"CSRF":       csrf,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Email":      ad.Email,
		"Error":      querySlug(r, "err"),
	})
}

func (s *Server) handleAdminLoginWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkLoginCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ad, _, ok := s.loadPendingLogin(r)
	if !ok {
		http.Error(w, "session expired", http.StatusGone)
		return
	}
	options, session, err := s.webauthn.BeginLogin(r.Context(), webauthnIdentityFromAdmin(ad))
	if err != nil {
		s.logger.Error("webauthn.BeginLogin failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminLoginAssertion,
		Value:    base64.RawURLEncoding.EncodeToString(session),
		Path:     "/admin/login/webauthn",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(5 * time.Minute),
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(options)
}

func (s *Server) handleAdminLoginWebauthnFinish(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(adminConstantTime)
	defer func() {
		if rem := time.Until(deadline); rem > 0 {
			time.Sleep(rem)
		}
	}()

	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.checkLoginCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	ad, pendingToken, ok := s.loadPendingLogin(r)
	if !ok {
		http.Error(w, "session expired", http.StatusGone)
		return
	}

	sessionCookie, err := r.Cookie(cookieAdminLoginAssertion)
	if err != nil {
		http.Error(w, "no assertion session", http.StatusBadRequest)
		return
	}
	if len(sessionCookie.Value) > adminMaxWebauthnSessionBytes {
		http.Error(w, "session too large", http.StatusBadRequest)
		return
	}
	sessionBytes, err := base64.RawURLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}

	// Always clear the assertion cookie — whether we succeed or fail, the
	// challenge has been consumed and must not be replayable.
	defer http.SetCookie(w, &http.Cookie{
		Name: cookieAdminLoginAssertion, Value: "", Path: "/admin/login/webauthn",
		Expires: time.Unix(0, 0), MaxAge: -1,
	})

	cred, err := s.webauthn.FinishLogin(r.Context(), webauthnIdentityFromAdmin(ad), sessionBytes, r)
	if err != nil {
		s.logger.Warn("webauthn.FinishLogin failed", "err", err, "admin_id", ad.ID)
		s.auditAppend(r.Context(), "admin.webauthn_login_failed", ad.Email, "", map[string]any{
			"reason": err.Error(),
		})
		http.Error(w, "assertion failed", http.StatusUnauthorized)
		return
	}

	// Consume the pending token so the same step-up state can't mint two
	// sessions.
	if _, consumed := s.loginPending.Consume(pendingToken); !consumed {
		http.Error(w, "session expired", http.StatusGone)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieAdminLoginStep, Value: "", Path: "/admin",
		Expires: time.Unix(0, 0), MaxAge: -1,
	})
	// Password + WebAuthn both passed: only now clear the failure counter.
	s.adminRepo.RecordLoginSuccess(r.Context(), ad.ID)

	sess, err := s.adminRepo.CreateSession(r.Context(), ad.ID,
		s.hashShort(s.clientIP(r)), s.hashShort(r.UserAgent()))
	if err != nil {
		s.logger.Error("admin.CreateSession failed after webauthn", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.setAdminCookies(w, sess)
	s.auditAppend(r.Context(), "admin.webauthn_login_succeeded", ad.Email, cred.CredentialID, nil)

	redirect := "/admin/dashboard"
	if ad.ForcePasswordChange || ad.ForceTOTPEnroll {
		redirect = "/admin/setup"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"redirect": redirect})
}

// handleAdminLoginWebauthnCancel lets the user back out of the WebAuthn
// step-up and return to the password form (or use TOTP). We just drop the
// pending token + cookies and bounce to /admin/login.
func (s *Server) handleAdminLoginWebauthnCancel(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkLoginCSRF(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if c, err := r.Cookie(cookieAdminLoginStep); err == nil && s.loginPending != nil {
		s.loginPending.Consume(c.Value)
	}
	for _, n := range []string{cookieAdminLoginStep, cookieAdminLoginAssertion} {
		http.SetCookie(w, &http.Cookie{
			Name: n, Value: "", Path: "/admin",
			Expires: time.Unix(0, 0), MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *Server) handleAdminSetupGet(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	secret, otpURL, codes := s.draftSetup(r)
	blob := ""
	if secret != "" {
		var err error
		if blob, err = s.adminRepo.SealSetup(a.ID, sess.Token, secret, codes); err != nil {
			s.logger.Error("SealSetup failed", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
	}

	s.renderAdmin(w, "setup", map[string]any{
		"Admin":               a,
		"EvalBanner":          s.cfg.IsEval(),
		"DemoBanner":          s.cfg.IsDemo(),
		"Label":               s.adminLabel,
		"NeedsPasswordChange": a.ForcePasswordChange,
		"NeedsTOTP":           a.ForceTOTPEnroll,
		"Secret":              secret,
		"OtpauthURL":          otpURL,
		"OtpauthQR":           otpauthQRDataURL(otpURL),
		"RecoveryCodes":       codes,
		"SetupBlob":           blob,
		"CSRF":                s.requireSessionCSRF(r),
	})
}

// otpauthQRDataURL renders the otpauth URL as a Medium-recovery QR
// code, base64-encoded so the template can drop it straight into an
// <img src> attribute. The return type is template.URL because
// html/template otherwise neuters every "data:" scheme it sees in a
// URL attribute (replaces the value with #ZgotmplZ). The string is
// safe by construction — we mint the bytes ourselves and base64-encode
// them, so user input never lands here.
//
// Returns an empty template.URL when generation fails — the template
// falls back to the existing text URL in that case so enrollment is
// never blocked by a QR hiccup.
func otpauthQRDataURL(otpURL string) htmltemplate.URL {
	if otpURL == "" {
		return ""
	}
	code, err := qr.Encode(otpURL, qr.M)
	if err != nil {
		return ""
	}
	return htmltemplate.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
}

func (s *Server) handleAdminSetupPost(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}

	// Step 1 — password change.
	if a.ForcePasswordChange {
		np := r.FormValue("new_password")
		conf := r.FormValue("new_password_confirm")
		if np == "" || np != conf {
			s.adminSetupError(w, r, "passwords_mismatch")
			return
		}
		if err := s.adminRepo.ChangePassword(r.Context(), a.ID, np); err != nil {
			if errors.Is(err, admin.ErrPasswordTooWeak) {
				s.adminSetupError(w, r, "password_too_weak")
				return
			}
			s.logger.Error("ChangePassword failed", "err", err)
			s.adminSetupError(w, r, "password_invalid")
			return
		}
		_ = s.adminRepo.RevokeOtherSessions(r.Context(), a.ID, sess.Token)
		s.auditAppend(r.Context(), "admin.password_changed", a.Email, "", nil)
	}

	// Step 2 — TOTP enrollment + verify a fresh code so we know the user
	// scanned the QR successfully.
	if a.ForceTOTPEnroll {
		// The secret and recovery codes come back sealed (SealSetup), never
		// as client-chosen plaintext: a forged form could otherwise enrol a
		// secret like "AA" and recovery codes of the attacker's choosing.
		code := strings.TrimSpace(r.FormValue("totp_code"))
		blob := strings.TrimSpace(r.FormValue("setup_blob"))
		if blob == "" || code == "" {
			s.adminSetupError(w, r, "totp_required")
			return
		}
		secret, codes, err := s.adminRepo.OpenSetup(a.ID, sess.Token, blob)
		if err != nil {
			s.adminSetupError(w, r, "totp_invalid")
			return
		}
		step, ok, err := totp.VerifyStep(secret, code, time.Now())
		if err != nil || !ok {
			s.adminSetupError(w, r, "totp_invalid")
			return
		}
		if err := s.adminRepo.EnrollTOTP(r.Context(), a.ID, secret, codes); err != nil {
			s.logger.Error("EnrollTOTP failed", "err", err)
			s.adminSetupError(w, r, "internal")
			return
		}
		// The enrolment code is spent: it cannot be replayed at login.
		if _, err := s.adminRepo.UseTOTPStep(r.Context(), a.ID, step); err != nil {
			s.logger.Error("UseTOTPStep failed", "err", err)
		}
		s.auditAppend(r.Context(), "admin.totp_enrolled", a.Email, "", nil)
	}
	// /admin (handleAdminRoot) inspects the session and lands the user
	// on /admin/dashboard or back on /admin/login as appropriate. Sending
	// the user there instead of /admin/dashboard means a stale
	// force_password_change bit can't sneak the admin past the gate.
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	count := int64(0)
	if s.audit != nil {
		count, _ = s.audit.Count(r.Context())
	}
	mode := "production"
	switch {
	case s.cfg.IsEval():
		mode = "eval"
	case s.cfg.IsDemo():
		mode = "demo"
	}
	s.renderAdmin(w, "dashboard", map[string]any{
		"Admin":          a,
		"Session":        sess,
		"EvalBanner":     s.cfg.IsEval(),
		"DemoBanner":     s.cfg.IsDemo(),
		"Label":          s.adminLabel,
		"AuditCount":     count,
		"CSRF":           sess.CSRFToken,
		"Mode":           mode,
		"BaseURL":        s.cfg.BaseURL,
		"InstanceDomain": s.cfg.InstanceDomain,
		"SenderName":     s.sender.Name(),
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.audit == nil || s.adminRepo == nil {
		http.Error(w, "audit not wired", http.StatusServiceUnavailable)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50

	db := s.adminRepo.DB()
	rows, err := db.QueryContext(r.Context(), storage.Rebind(db,
		`SELECT sequence_no, occurred_at, event_type,
		 COALESCE(actor, ''), COALESCE(target, ''), details_json
		 FROM audit_log
		 ORDER BY sequence_no DESC
		 LIMIT ? OFFSET ?`), pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("audit query failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type entry struct {
		SequenceNo int64
		Occurred   string
		EventType  string
		Actor      string
		Target     string
		Details    string
	}
	var items []entry
	for rows.Next() {
		var e entry
		var occurred any
		if err := rows.Scan(&e.SequenceNo, &occurred, &e.EventType, &e.Actor, &e.Target, &e.Details); err != nil {
			continue
		}
		e.Occurred = fmt.Sprintf("%v", occurred)
		items = append(items, e)
	}

	chainOK := true
	if bad, _ := s.audit.VerifyChain(r.Context()); bad != 0 {
		chainOK = false
	}

	s.renderAdmin(w, "audit", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      items,
		"Page":       page,
		"PrevPage":   page - 1,
		"NextPage":   page + 1,
		"ChainOK":    chainOK,
	})
}

// ----- domains --------------------------------------------------------------

func (s *Server) handleAdminDomains(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.domains == nil {
		http.Error(w, "domains repo not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.domains.List(r.Context())
	if err != nil {
		s.logger.Error("domains.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "domains", map[string]any{
		"Admin":         a,
		"Session":       sess,
		"EvalBanner":    s.cfg.IsEval(),
		"DemoBanner":    s.cfg.IsDemo(),
		"Label":         s.adminLabel,
		"Items":         list,
		"CSRF":          sess.CSRFToken,
		"Error":         querySlug(r, "err"),
		"OK":            querySlug(r, "ok"),
		"Details":       r.URL.Query().Get("details"),
		"ImportCreated": r.URL.Query().Get("created"),
		"ImportSkipped": r.URL.Query().Get("skipped"),
		"ImportErrors":  r.URL.Query().Get("errors"),
	})
}

func (s *Server) handleAdminDomainAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	name := r.FormValue("name")
	description := r.FormValue("description")
	active := r.FormValue("active") == "on"

	d, err := s.domains.Create(r.Context(), name, description, active, &a.ID)
	switch {
	case errors.Is(err, domains.ErrInvalidName):
		http.Redirect(w, r, "/admin/domains?err=invalid_name", http.StatusSeeOther)
		return
	case errors.Is(err, domains.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/domains?err=already_exists", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("domains.Create failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "domain.created", a.Email, d.Name, map[string]any{
		"id":     d.ID,
		"active": d.Active,
	})
	http.Redirect(w, r, "/admin/domains?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminDomainToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d, err := s.domains.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/domains?err=not_found", http.StatusSeeOther)
		return
	}
	next := !d.Active
	if err := s.domains.SetActive(r.Context(), id, next); err != nil {
		s.logger.Error("domains.SetActive failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	event := "domain.disabled"
	if next {
		event = "domain.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, d.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/domains?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminDomainDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	d, err := s.domains.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/domains?err=not_found", http.StatusSeeOther)
		return
	}
	// FR-C.24 double-confirmation: the form must echo the domain name in a
	// `confirm` field so a stray click does not nuke a row.
	if strings.TrimSpace(r.FormValue("confirm")) != d.Name {
		http.Redirect(w, r, "/admin/domains?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.domains.Delete(r.Context(), id); err != nil {
		s.logger.Error("domains.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/domains?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "domain.deleted", a.Email, d.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/domains?ok=deleted", http.StatusSeeOther)
}

// adminMaxCSVBytes caps CSV uploads. 2 MB easily fits a five-figure
// domain list while keeping pathological inputs out of memory.
const adminMaxCSVBytes = 2 * 1024 * 1024

func (s *Server) handleAdminDomainImport(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.domains == nil {
		http.Error(w, "domains not wired", http.StatusServiceUnavailable)
		return
	}
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/domains?err=demo_readonly", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxCSVBytes+4*1024)
	if err := r.ParseMultipartForm(adminMaxCSVBytes); err != nil {
		http.Redirect(w, r, "/admin/domains?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	file, _, err := r.FormFile("csv")
	if err != nil {
		http.Redirect(w, r, "/admin/domains?err=no_file", http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()

	sum, err := s.domains.Import(r.Context(), io.LimitReader(file, adminMaxCSVBytes+1), &a.ID)
	if err != nil {
		s.logger.Error("domains.Import failed", "err", err)
		http.Redirect(w, r,
			"/admin/domains?err=import_failed&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "domain.imported", a.Email, "", map[string]any{
		"created": sum.Created,
		"skipped": sum.Skipped,
		"errors":  len(sum.Errors),
	})
	q := url.Values{}
	q.Set("ok", "imported")
	q.Set("created", strconv.Itoa(sum.Created))
	q.Set("skipped", strconv.Itoa(sum.Skipped))
	q.Set("errors", strconv.Itoa(len(sum.Errors)))
	if len(sum.Errors) > 0 {
		// Surface up to three failing rows in the query string so the
		// admin can fix them without re-uploading the full file. The
		// rest are visible in the audit log.
		lines := make([]string, 0, 3)
		for i, e := range sum.Errors {
			if i == 3 {
				break
			}
			lines = append(lines, fmt.Sprintf("L%d %s — %s", e.Line, e.Domain, e.Reason))
		}
		q.Set("details", strings.Join(lines, " | "))
	}
	http.Redirect(w, r, "/admin/domains?"+q.Encode(), http.StatusSeeOther)
}

// ----- policies -------------------------------------------------------------

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.policies == nil || s.domains == nil {
		http.Error(w, "policies not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.policies.ListAll(r.Context())
	if err != nil {
		s.logger.Error("policies.ListAll failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	doms, _ := s.domains.List(r.Context())
	s.renderAdmin(w, "policies", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      list,
		"Domains":    doms,
		"CSRF":       sess.CSRFToken,
		"Error":      querySlug(r, "err"),
		"OK":         querySlug(r, "ok"),
	})
}

func (s *Server) handleAdminPolicyAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	in := policies.CreateInputs{
		DomainID:          domainID,
		ANSSILevel:        elevations.Level(strings.TrimSpace(r.FormValue("anssi_level"))),
		Name:              r.FormValue("name"),
		Generator:         policies.Generator(strings.TrimSpace(r.FormValue("generator"))),
		ParamsJSON:        r.FormValue("params_json"),
		ProposalCount:     atoiOr(r.FormValue("proposal_count"), 5),
		RegenerateLimit:   atoiOr(r.FormValue("regenerate_limit"), 3),
		SessionTTLSeconds: atoiOr(r.FormValue("session_ttl_seconds"), 900),
		NotifyOnConsult:   r.FormValue("notify_on_consult") == "on",
		Active:            r.FormValue("active") == "on",
	}
	p, err := s.policies.Create(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, policies.ErrInvalidShape):
		http.Redirect(w, r, "/admin/policies?err=invalid", http.StatusSeeOther)
		return
	case errors.Is(err, policies.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/policies?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("policies.Create failed", "err", err)
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "policy.created", a.Email, fmt.Sprintf("%d", p.ID), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
		"generator": string(p.Generator),
	})
	http.Redirect(w, r, "/admin/policies?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminPolicyEdit(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.policies == nil || s.domains == nil {
		http.Error(w, "policies not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := s.policies.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/policies?err=not_found", http.StatusSeeOther)
		return
	}
	doms, _ := s.domains.List(r.Context())
	paramsJSON := string(p.Params)
	if paramsJSON == "" {
		paramsJSON = "{}"
	}
	s.renderAdmin(w, "policy_edit", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"CSRF":       sess.CSRFToken,
		"Domains":    doms,
		"Policy":     p,
		"ParamsJSON": paramsJSON,
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
		"Details":    r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminPolicySave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	in := policies.CreateInputs{
		DomainID:          domainID,
		ANSSILevel:        elevations.Level(strings.TrimSpace(r.FormValue("anssi_level"))),
		Name:              r.FormValue("name"),
		Generator:         policies.Generator(strings.TrimSpace(r.FormValue("generator"))),
		ParamsJSON:        r.FormValue("params_json"),
		ProposalCount:     atoiOr(r.FormValue("proposal_count"), 5),
		RegenerateLimit:   atoiOr(r.FormValue("regenerate_limit"), 3),
		SessionTTLSeconds: atoiOr(r.FormValue("session_ttl_seconds"), 900),
		NotifyOnConsult:   r.FormValue("notify_on_consult") == "on",
		Active:            r.FormValue("active") == "on",
	}
	err := s.policies.Update(r.Context(), id, in)
	switch {
	case errors.Is(err, policies.ErrInvalidShape):
		http.Redirect(w, r, fmt.Sprintf("/admin/policies/%d/edit?err=invalid&details=%s", id, url.QueryEscape(err.Error())), http.StatusSeeOther)
		return
	case errors.Is(err, policies.ErrAlreadyExists):
		http.Redirect(w, r, fmt.Sprintf("/admin/policies/%d/edit?err=duplicate", id), http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("policies.Update failed", "err", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/policies/%d/edit?err=internal", id), http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "policy.updated", a.Email, fmt.Sprintf("%d", id), map[string]any{
		"domain_id": in.DomainID,
		"level":     string(in.ANSSILevel),
		"generator": string(in.Generator),
	})
	http.Redirect(w, r, "/admin/policies?ok=updated", http.StatusSeeOther)
}

func (s *Server) handleAdminPolicyToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := s.policies.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/policies?err=not_found", http.StatusSeeOther)
		return
	}
	next := !p.Active
	if err := s.policies.SetActive(r.Context(), id, next); err != nil {
		s.logger.Error("policies.SetActive failed", "err", err)
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	event := "policy.disabled"
	if next {
		event = "policy.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, fmt.Sprintf("%d", id), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
	})
	http.Redirect(w, r, "/admin/policies?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminPolicyDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := s.policies.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/policies?err=not_found", http.StatusSeeOther)
		return
	}
	confirm := strings.TrimSpace(r.FormValue("confirm"))
	if confirm != p.Name {
		http.Redirect(w, r, "/admin/policies?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.policies.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/policies?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "policy.deleted", a.Email, fmt.Sprintf("%d", id), map[string]any{
		"domain_id": p.DomainID,
		"level":     string(p.ANSSILevel),
	})
	http.Redirect(w, r, "/admin/policies?ok=deleted", http.StatusSeeOther)
}

// ----- elevations -----------------------------------------------------------

func (s *Server) handleAdminElevations(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.elevations == nil || s.domains == nil {
		http.Error(w, "elevations not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.elevations.ListAll(r.Context())
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	doms, _ := s.domains.List(r.Context())
	s.renderAdmin(w, "elevations", map[string]any{
		"Admin":         a,
		"Session":       sess,
		"EvalBanner":    s.cfg.IsEval(),
		"DemoBanner":    s.cfg.IsDemo(),
		"Label":         s.adminLabel,
		"Items":         list,
		"Domains":       doms,
		"CSRF":          sess.CSRFToken,
		"Error":         querySlug(r, "err"),
		"OK":            querySlug(r, "ok"),
		"Details":       r.URL.Query().Get("details"),
		"ImportCreated": r.URL.Query().Get("created"),
		"ImportSkipped": r.URL.Query().Get("skipped"),
		"ImportErrors":  r.URL.Query().Get("errors"),
	})
}

func (s *Server) handleAdminElevationAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	level := elevations.Level(strings.TrimSpace(r.FormValue("level")))
	email := r.FormValue("email")
	reason := r.FormValue("reason")
	e, err := s.elevations.Create(r.Context(), domainID, email, level, reason, &a.ID)
	switch {
	case errors.Is(err, elevations.ErrInvalidLevel):
		http.Redirect(w, r, "/admin/elevations?err=invalid_level", http.StatusSeeOther)
		return
	case errors.Is(err, elevations.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/elevations?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("elevations.Create failed", "err", err)
		http.Redirect(w, r, "/admin/elevations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "elevation.created", a.Email, e.Email, map[string]any{
		"domain_id": e.DomainID,
		"level":     string(e.Level),
	})
	http.Redirect(w, r, "/admin/elevations?ok=added", http.StatusSeeOther)
}

func (s *Server) handleAdminElevationDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	e, err := s.elevations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/elevations?err=not_found", http.StatusSeeOther)
		return
	}
	if err := s.elevations.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/elevations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "elevation.deleted", a.Email, e.Email, map[string]any{
		"domain_id": e.DomainID,
		"level":     string(e.Level),
	})
	http.Redirect(w, r, "/admin/elevations?ok=removed", http.StatusSeeOther)
}

func (s *Server) handleAdminElevationImport(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.elevations == nil || s.domains == nil {
		http.Error(w, "elevations or domains not wired", http.StatusServiceUnavailable)
		return
	}
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/elevations?err=demo_readonly", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxCSVBytes+4*1024)
	if err := r.ParseMultipartForm(adminMaxCSVBytes); err != nil {
		http.Redirect(w, r, "/admin/elevations?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	file, _, err := r.FormFile("csv")
	if err != nil {
		http.Redirect(w, r, "/admin/elevations?err=no_file", http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()

	resolver := func(ctx context.Context, name string) (int64, error) {
		row, err := s.domains.GetByName(ctx, name)
		if err != nil {
			return 0, err
		}
		return row.ID, nil
	}
	sum, err := s.elevations.Import(r.Context(), io.LimitReader(file, adminMaxCSVBytes+1), resolver, &a.ID)
	if err != nil {
		s.logger.Error("elevations.Import failed", "err", err)
		http.Redirect(w, r,
			"/admin/elevations?err=import_failed&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "elevation.imported", a.Email, "", map[string]any{
		"created": sum.Created,
		"skipped": sum.Skipped,
		"errors":  len(sum.Errors),
	})
	q := url.Values{}
	q.Set("ok", "imported")
	q.Set("created", strconv.Itoa(sum.Created))
	q.Set("skipped", strconv.Itoa(sum.Skipped))
	q.Set("errors", strconv.Itoa(len(sum.Errors)))
	if len(sum.Errors) > 0 {
		lines := make([]string, 0, 3)
		for i, e := range sum.Errors {
			if i == 3 {
				break
			}
			lines = append(lines, fmt.Sprintf("L%d %s — %s", e.Line, e.Email, e.Reason))
		}
		q.Set("details", strings.Join(lines, " | "))
	}
	http.Redirect(w, r, "/admin/elevations?"+q.Encode(), http.StatusSeeOther)
}

func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return def
}

// ----- libraries ------------------------------------------------------------

func (s *Server) handleAdminLibraries(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.libraries.List(r.Context())
	if err != nil {
		s.logger.Error("libraries.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "libraries", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"Error":      querySlug(r, "err"),
		"OK":         querySlug(r, "ok"),
		"Details":    r.URL.Query().Get("details"),
	})
}

const adminMaxLibraryBytes = 32 * 1024 * 1024 // 32 MB hard ceiling

func (s *Server) handleAdminLibraryUpload(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	// FR-H.81: library uploads are forbidden on a public demo. Only the
	// system libraries shipped with the binary stay active.
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/libraries?err=demo_readonly", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxLibraryBytes)
	if err := r.ParseMultipartForm(adminMaxLibraryBytes); err != nil {
		http.Redirect(w, r, "/admin/libraries?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	kind := libraries.Kind(strings.TrimSpace(r.FormValue("kind")))
	name := r.FormValue("name")
	language := r.FormValue("language")
	description := r.FormValue("description")

	file, hdr, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/admin/libraries?err=no_file", http.StatusSeeOther)
		return
	}
	defer file.Close()

	lib, report, err := s.libraries.Upload(r.Context(), libraries.UploadInputs{
		Name:        name,
		Kind:        kind,
		Language:    language,
		Description: description,
		Content:     file,
		AdminID:     &a.ID,
	})
	switch {
	case errors.Is(err, libraries.ErrAlreadyExists):
		s.auditAppend(r.Context(), "library.duplicate_upload", a.Email, lib.SHA256, map[string]any{
			"existing_id":   lib.ID,
			"existing_name": lib.Name,
		})
		http.Redirect(w, r, "/admin/libraries?err=duplicate&details="+lib.Name, http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrInvalidEncoding):
		http.Redirect(w, r, "/admin/libraries?err=encoding", http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrEmptyFile):
		http.Redirect(w, r, "/admin/libraries?err=empty", http.StatusSeeOther)
		return
	case errors.Is(err, libraries.ErrUnknownKind):
		http.Redirect(w, r, "/admin/libraries?err=kind", http.StatusSeeOther)
		return
	case err != nil && report.HasErrors():
		// Format the first error so the admin can fix the file.
		detail := url.QueryEscape(report.FirstErrors[0].Error())
		http.Redirect(w, r, "/admin/libraries?err=validation&details="+detail, http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("libraries.Upload failed", "err", err)
		http.Redirect(w, r, "/admin/libraries?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "library.uploaded", a.Email, lib.SHA256, map[string]any{
		"id":         lib.ID,
		"kind":       string(lib.Kind),
		"language":   lib.Language,
		"entries":    lib.EntryCount,
		"size_bytes": lib.SizeBytes,
		"filename":   hdr.Filename,
	})
	msg := "uploaded"
	if len(report.Warnings) > 0 {
		msg = "uploaded_with_warnings"
	}
	http.Redirect(w, r, "/admin/libraries?ok="+msg, http.StatusSeeOther)
}

func (s *Server) handleAdminLibraryDownload(w http.ResponseWriter, r *http.Request) {
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, rc, err := s.libraries.Open(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s-%s.txt"`, lib.Kind, lib.Name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleAdminLibrarySample(w http.ResponseWriter, r *http.Request) {
	if s.libraries == nil {
		http.Error(w, "libraries not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, sample, err := s.libraries.Sample(r.Context(), id, 10)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      lib.ID,
		"name":    lib.Name,
		"kind":    string(lib.Kind),
		"entries": sample,
		"count":   lib.EntryCount,
	})
}

func (s *Server) handleAdminLibraryDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	lib, err := s.libraries.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/libraries?err=not_found", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != lib.Name {
		http.Redirect(w, r, "/admin/libraries?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	switch err := s.libraries.Delete(r.Context(), id); {
	case errors.Is(err, libraries.ErrSystemReadOnly):
		http.Redirect(w, r, "/admin/libraries?err=system_readonly", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("libraries.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/libraries?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "library.deleted", a.Email, lib.SHA256, map[string]any{
		"id":   lib.ID,
		"name": lib.Name,
	})
	http.Redirect(w, r, "/admin/libraries?ok=deleted", http.StatusSeeOther)
}

// ----- mail templates -------------------------------------------------------

func (s *Server) handleAdminTemplates(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.mailTpls == nil {
		http.Error(w, "mail templates not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.mailTpls.List(r.Context())
	if err != nil {
		s.logger.Error("mailtemplates.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "templates", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
	})
}

func (s *Server) handleAdminTemplateEdit(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.mailTpls == nil {
		http.Error(w, "mail templates not wired", http.StatusServiceUnavailable)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.URL.Query().Get("kind")))
	lang := strings.TrimSpace(r.URL.Query().Get("language"))
	tpl, err := s.mailTpls.Get(r.Context(), kind, lang)
	if err != nil {
		http.Redirect(w, r, "/admin/templates?err=not_found", http.StatusSeeOther)
		return
	}
	s.renderAdmin(w, "template_edit", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"CSRF":       sess.CSRFToken,
		"Template":   tpl,
		"Vars":       templateVarsDocumentation(),
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
		"Details":    r.URL.Query().Get("details"),
		"Preview":    "",
	})
}

func (s *Server) handleAdminTemplateSave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	subject := r.FormValue("subject")
	text := r.FormValue("text_body")
	html := r.FormValue("html_body")

	if err := s.mailTpls.Upsert(r.Context(), kind, lang, subject, text, html, &a.ID); err != nil {
		if errors.Is(err, mailtemplates.ErrParse) {
			http.Redirect(w, r, fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&err=parse&details=%s",
				url.QueryEscape(string(kind)), url.QueryEscape(lang), url.QueryEscape(err.Error())), http.StatusSeeOther)
			return
		}
		s.logger.Error("mailtemplates.Upsert failed", "err", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&err=internal",
			kind, lang), http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "template.saved", a.Email,
		fmt.Sprintf("%s/%s", kind, lang), map[string]any{"kind": string(kind), "language": lang})
	http.Redirect(w, r,
		fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&ok=saved", kind, lang),
		http.StatusSeeOther)
}

func (s *Server) handleAdminTemplatePreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	subject := r.FormValue("subject")
	text := r.FormValue("text_body")
	html := r.FormValue("html_body")

	if err := mailtemplates.ValidateTemplates(subject, text, html); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse_failed", err.Error())
		return
	}

	rendered, rerr := renderInline(kind, lang, subject, text, html, samplePreviewVars(s.adminLabel))
	if rerr != nil {
		writeJSONError(w, http.StatusBadRequest, "render_failed", rerr.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":  rendered.Subject,
		"text":     rendered.Text,
		"html":     rendered.HTML,
		"kind":     string(rendered.Kind),
		"language": rendered.Language,
	})
}

func (s *Server) handleAdminTemplateReset(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	kind := mailtemplates.Kind(strings.TrimSpace(r.FormValue("kind")))
	lang := strings.TrimSpace(r.FormValue("language"))
	if err := s.mailTpls.Reset(r.Context(), kind, lang); err != nil {
		s.logger.Error("mailtemplates.Reset failed", "err", err)
		http.Redirect(w, r, "/admin/templates?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "template.reset", a.Email,
		fmt.Sprintf("%s/%s", kind, lang), map[string]any{"kind": string(kind), "language": lang})
	http.Redirect(w, r,
		fmt.Sprintf("/admin/templates/edit?kind=%s&language=%s&ok=reset", kind, lang),
		http.StatusSeeOther)
}

// renderInline mirrors mailtemplates.Repo.Render but takes raw template
// sources instead of a stored row — handy for the live preview form.
func renderInline(kind mailtemplates.Kind, lang, subject, text, html string, vars mailtemplates.Vars) (mailtemplates.Rendered, error) {
	// Reuse mailtemplates' validation + rendering by faking a Template row.
	tpl := mailtemplates.Template{Kind: kind, Language: lang, Subject: subject, Text: text, HTML: html}
	return mailtemplates.RenderTemplate(tpl, vars)
}

func samplePreviewVars(instance string) mailtemplates.Vars {
	return mailtemplates.Vars{
		RevealURL:          "https://example.com/reveal/preview-token-deadbeef",
		UserEmail:          "preview@example.com",
		ExpiresAt:          time.Now().Add(15 * time.Minute),
		ValidityMinutes:    15,
		InstanceName:       instance,
		InstanceDomain:     instance,
		ContactURL:         "https://example.com/contact",
		ConsultedAt:        time.Now().Format(time.RFC3339),
		ConsultedIP:        "203.0.113.42",
		ConsultedUserAgent: "Mozilla/5.0 (preview)",
	}
}

func templateVarsDocumentation() []map[string]string {
	return []map[string]string{
		{"name": ".RevealURL", "doc": "Absolute URL the user clicks to land on /reveal/{token}."},
		{"name": ".UserEmail", "doc": "Recipient email address (lowercased)."},
		{"name": ".ExpiresAt", "doc": "Token expiry timestamp (time.Time)."},
		{"name": ".ValidityMinutes", "doc": "Convenience integer matching the TTL."},
		{"name": ".InstanceName", "doc": "Human label of this SealKeeper instance."},
		{"name": ".InstanceDomain", "doc": "Bare hostname (used in From:)."},
		{"name": ".ContactURL", "doc": "Optional support URL — wrap with `{{ if .ContactURL }}…{{ end }}`."},
		{"name": ".ConsultedAt", "doc": "RFC 3339 timestamp of a consultation (post-consultation template only)."},
		{"name": ".ConsultedIP", "doc": "Source IP of the consultation."},
		{"name": ".ConsultedUserAgent", "doc": "User-Agent of the consultation."},
	}
}

// ----- integrations ---------------------------------------------------------

func (s *Server) handleAdminIntegrations(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.integrations == nil {
		http.Error(w, "integrations not wired", http.StatusServiceUnavailable)
		return
	}
	list, err := s.integrations.List(r.Context())
	if err != nil {
		s.logger.Error("integrations.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	stats := integrations.Stats{}
	if s.dispatcher != nil {
		stats = s.dispatcher.Stats()
	}
	s.renderAdmin(w, "integrations", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      list,
		"CSRF":       sess.CSRFToken,
		"Stats":      stats,
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
		"Details":    r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminIntegrationAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// FR-H.80: no outbound integrations on a public demo, in or out.
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/integrations?err=demo_readonly", http.StatusSeeOther)
		return
	}
	in := integrations.CreateInputs{
		Name:        r.FormValue("name"),
		Kind:        integrations.Kind(strings.TrimSpace(r.FormValue("kind"))),
		Enabled:     r.FormValue("enabled") == "on",
		ConfigJSON:  r.FormValue("config_json"),
		FiltersJSON: r.FormValue("filters_json"),
	}
	row, err := s.integrations.Create(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, integrations.ErrInvalidKind):
		http.Redirect(w, r, "/admin/integrations?err=invalid_kind", http.StatusSeeOther)
		return
	case errors.Is(err, integrations.ErrInvalidConfig):
		http.Redirect(w, r,
			"/admin/integrations?err=invalid_config&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	case errors.Is(err, integrations.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/integrations?err=duplicate", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("integrations.Create failed", "err", err)
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.created", a.Email, row.Name, map[string]any{
		"id":   row.ID,
		"kind": string(row.Kind),
	})
	http.Redirect(w, r, "/admin/integrations?ok=created", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	next := !row.Enabled
	// FR-H.80: prevent enabling an integration on a public demo. Disable
	// is always allowed so an operator can roll back manually.
	if next && s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/integrations?err=demo_readonly", http.StatusSeeOther)
		return
	}
	if err := s.integrations.SetEnabled(r.Context(), id, next); err != nil {
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	event := "integration.disabled"
	if next {
		event = "integration.enabled"
	}
	s.auditAppend(r.Context(), event, a.Email, row.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/integrations?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != row.Name {
		http.Redirect(w, r, "/admin/integrations?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.integrations.Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/admin/integrations?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.deleted", a.Email, row.Name, map[string]any{"id": id})
	http.Redirect(w, r, "/admin/integrations?ok=deleted", http.StatusSeeOther)
}

func (s *Server) handleAdminIntegrationTest(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	row, err := s.integrations.Get(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/integrations?err=not_found", http.StatusSeeOther)
		return
	}
	if err := integrations.TestSink(r.Context(), row, s.cfg.InstanceDomain); err != nil {
		s.auditAppend(r.Context(), "integration.test_failed", a.Email, row.Name, map[string]any{
			"error": err.Error(),
		})
		http.Redirect(w, r,
			"/admin/integrations?err=test_failed&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "integration.test_ok", a.Email, row.Name, nil)
	http.Redirect(w, r, "/admin/integrations?ok=test_ok", http.StatusSeeOther)
}

// ----- branding -------------------------------------------------------------

const adminMaxLogoBytes = 256 * 1024 // mirrors branding.MaxLogoBytes

func (s *Server) handleAdminBranding(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.branding == nil {
		http.Error(w, "branding not wired", http.StatusServiceUnavailable)
		return
	}
	row, err := s.branding.Get(r.Context())
	if err != nil {
		s.logger.Error("branding.Get failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "branding", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Branding":   row,
		"CSRF":       sess.CSRFToken,
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
		"Details":    r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminBrandingSave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	in := branding.UpdateInputs{
		InstanceName:   r.FormValue("instance_name"),
		PrimaryColor:   r.FormValue("primary_color"),
		SecondaryColor: r.FormValue("secondary_color"),
		TertiaryColor:  r.FormValue("tertiary_color"),
		ContactURL:     r.FormValue("contact_url"),
	}
	err := s.branding.Update(r.Context(), in, &a.ID)
	switch {
	case errors.Is(err, branding.ErrInvalidName):
		http.Redirect(w, r, "/admin/branding?err=invalid_name", http.StatusSeeOther)
		return
	case errors.Is(err, branding.ErrInvalidColor):
		http.Redirect(w, r,
			"/admin/branding?err=invalid_color&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("branding.Update failed", "err", err)
		http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "branding.updated", a.Email, "", map[string]any{
		"instance_name": in.InstanceName,
	})
	http.Redirect(w, r, "/admin/branding?ok=saved", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogo(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.branding == nil {
		http.Error(w, "branding not wired", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxLogoBytes+4*1024) // small slack for form headers
	if err := r.ParseMultipartForm(adminMaxLogoBytes); err != nil {
		http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	file, hdr, err := r.FormFile("logo")
	if err != nil {
		http.Redirect(w, r, "/admin/branding?err=no_file", http.StatusSeeOther)
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, adminMaxLogoBytes+1))
	if err != nil {
		http.Redirect(w, r, "/admin/branding?err=read_failed", http.StatusSeeOther)
		return
	}
	if len(data) > adminMaxLogoBytes {
		http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		return
	}

	mime := hdr.Header.Get("Content-Type")
	if mime == "" {
		mime = http.DetectContentType(data)
	}
	// http.DetectContentType might miss SVG when the buffer starts with
	// whitespace; sniff for the literal '<svg' prefix as a fallback.
	if mime == "text/xml; charset=utf-8" || mime == "application/xml" {
		mime = "image/svg+xml"
	}

	if err := s.branding.SetLogo(r.Context(), mime, data, &a.ID); err != nil {
		switch {
		case errors.Is(err, branding.ErrInvalidLogo):
			http.Redirect(w, r, "/admin/branding?err=invalid_logo", http.StatusSeeOther)
		case errors.Is(err, branding.ErrLogoTooLarge):
			http.Redirect(w, r, "/admin/branding?err=too_large", http.StatusSeeOther)
		default:
			s.logger.Error("branding.SetLogo failed", "err", err)
			http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		}
		return
	}
	s.auditAppend(r.Context(), "branding.logo_updated", a.Email, "", map[string]any{
		"mime":  mime,
		"bytes": len(data),
	})
	http.Redirect(w, r, "/admin/branding?ok=logo_uploaded", http.StatusSeeOther)
}

func (s *Server) handleAdminBrandingLogoClear(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.branding.ClearLogo(r.Context(), &a.ID); err != nil {
		http.Redirect(w, r, "/admin/branding?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "branding.logo_cleared", a.Email, "", nil)
	http.Redirect(w, r, "/admin/branding?ok=logo_cleared", http.StatusSeeOther)
}

func (s *Server) handleAdminCapturedMail(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if !s.cfg.IsEval() && !s.cfg.IsDemo() {
		http.Error(w, "captured-mail is only available in eval or demo mode", http.StatusNotFound)
		return
	}
	items := s.mail.Snapshot()
	s.renderAdmin(w, "captured", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": true,
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"Items":      items,
	})
}

// ----- helpers --------------------------------------------------------------

func (s *Server) loadAdminSession(r *http.Request) (admin.Session, admin.Admin, error) {
	if s.adminRepo == nil {
		return admin.Session{}, admin.Admin{}, errors.New("admin repo not wired")
	}
	c, err := r.Cookie(cookieAdminSession)
	if err != nil {
		return admin.Session{}, admin.Admin{}, err
	}
	return s.adminRepo.LookupSession(r.Context(), c.Value)
}

func (s *Server) setAdminCookies(w http.ResponseWriter, sess admin.Session) {
	secure := !s.cfg.IsEval()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminSession,
		Value:    sess.Token,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Expires:  sess.ExpiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAdminCSRF,
		Value:    sess.CSRFToken,
		Path:     "/admin",
		HttpOnly: false, // readable by JS for header-based CSRF if we add an SPA later
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		Expires:  sess.ExpiresAt,
	})
}

func (s *Server) clearAdminCookies(w http.ResponseWriter) {
	for _, name := range []string{cookieAdminSession, cookieAdminCSRF, cookieLoginCSRF} {
		http.SetCookie(w, &http.Cookie{
			Name:    name,
			Value:   "",
			Path:    "/admin",
			Expires: time.Unix(0, 0),
			MaxAge:  -1,
		})
	}
}

func (s *Server) checkLoginCSRF(r *http.Request) bool {
	c, err := r.Cookie(cookieLoginCSRF)
	if err != nil {
		return false
	}
	form := r.FormValue("csrf_token")
	return constantTimeEqualString(c.Value, form)
}

// checkSessionCSRF compares the submitted token with the one derived from
// the authenticated session (admin.Repo sessionCSRF). Comparing against the
// sk_admin_csrf cookie instead let anyone able to plant that cookie (a
// sibling subdomain) forge requests, and an absent cookie plus an empty
// field compared equal.
func (s *Server) checkSessionCSRF(r *http.Request) bool {
	_, sess, ok := adminFromCtx(r)
	if !ok || sess.CSRFToken == "" {
		return false
	}
	form := r.FormValue("csrf_token")
	if form == "" {
		form = r.Header.Get("X-CSRF-Token")
	}
	return constantTimeEqualString(sess.CSRFToken, form)
}

// sameOriginPOST refuses state-changing admin requests that a browser marks
// as cross-origin, including same-site siblings (e.g. a compromised wiki on
// another subdomain). Sec-Fetch-Site is authoritative when present; Origin
// is the fallback for older clients. Non-browser clients send neither and
// remain subject to the CSRF token.
func sameOriginPOST(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			site := r.Header.Get("Sec-Fetch-Site")
			origin := r.Header.Get("Origin")
			switch {
			case site != "":
				if site != "same-origin" && site != "none" {
					http.Error(w, "cross-site request refused", http.StatusForbidden)
					return
				}
			// "null" is what Chrome sends on form posts under
			// Referrer-Policy: no-referrer; the CSRF token still applies.
			case origin != "" && origin != "null":
				u, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireCurrentPassword is the step-up for credential changes: a stolen
// session cookie alone must not let an attacker replace the password, the
// e-mail or the security keys and lock the operator out. Returns the
// error slug to show when the check fails.
func (s *Server) requireCurrentPassword(r *http.Request) (string, bool) {
	a, _, _ := adminFromCtx(r)
	err := s.adminRepo.VerifyPassword(r.Context(), a.ID, r.FormValue("current_password"))
	switch {
	case err == nil:
		return "", true
	case errors.Is(err, admin.ErrAccountLocked):
		s.auditAppend(r.Context(), "admin.step_up_failed", a.Email, "", map[string]any{"reason": "locked"})
		return "locked", false
	case errors.Is(err, admin.ErrInvalidCreds):
		s.auditAppend(r.Context(), "admin.step_up_failed", a.Email, "", map[string]any{"reason": "credentials"})
		return "current_password", false
	default:
		s.logger.Error("VerifyPassword failed", "err", err)
		return "internal", false
	}
}

func (s *Server) requireSessionCSRF(r *http.Request) string {
	if c, err := r.Cookie(cookieAdminCSRF); err == nil {
		return c.Value
	}
	return ""
}

func constantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// draftSetup builds the TOTP secret / otpauth / recovery codes shown on the
// setup page. Generated once per GET and embedded in the form so POST can
// commit them atomically.
func (s *Server) draftSetup(r *http.Request) (totp.Secret, string, []string) {
	a, _, _ := adminFromCtx(r)
	if !a.ForceTOTPEnroll {
		return "", "", nil
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.logger.Error("totp.NewSecret failed", "err", err)
		return "", "", nil
	}
	codes, err := totp.NewRecoveryCodes(8)
	if err != nil {
		s.logger.Error("totp.NewRecoveryCodes failed", "err", err)
		return "", "", nil
	}
	return secret, totp.Otpauth(secret, s.adminLabel, a.Email), codes
}

func (s *Server) adminLoginError(w http.ResponseWriter, r *http.Request, slug string) {
	q := "?err=" + slug
	if email := strings.TrimSpace(r.FormValue("email")); email != "" {
		q += "&email=" + url.QueryEscape(email)
	}
	http.Redirect(w, r, "/admin/login"+q, http.StatusSeeOther)
}

func (s *Server) adminSetupError(w http.ResponseWriter, r *http.Request, slug string) {
	http.Redirect(w, r, "/admin/setup?err="+slug, http.StatusSeeOther)
}

// renderAdmin executes the matching template against `data`.
func (s *Server) renderAdmin(w http.ResponseWriter, name string, data map[string]any) {
	if s.adminTpl == nil {
		http.Error(w, "admin templates not loaded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	data["CSPNonce"] = scriptNonce(w)
	// The header's logout form needs the CSRF token on every page.
	if _, ok := data["CSRF"]; !ok {
		if sess, ok := data["Session"].(admin.Session); ok {
			data["CSRF"] = sess.CSRFToken
		}
	}
	if err := s.adminTpl.ExecuteTemplate(w, name+".html", data); err != nil {
		s.logger.Error("admin template render failed", "name", name, "err", err)
	}
}

// ----- HTML templates -------------------------------------------------------

var adminTpls = htmltemplate.Must(htmltemplate.New("admin").Parse(adminBaseTpl + adminLoginTpl +
	adminSetupTpl + adminDashboardTpl + adminAuditTpl + adminCapturedTpl + adminDomainsTpl +
	adminPoliciesTpl + adminElevationsTpl + adminLibrariesTpl +
	adminTemplatesTpl + adminTemplateEditTpl + adminIntegrationsTpl + adminBrandingTpl +
	adminSecurityTpl + adminLoginWebauthnTpl + adminAccountTpl + adminAdminsTpl + adminSMTPTpl + adminPolicyEditTpl))

const adminBaseTpl = `{{define "header"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SealKeeper admin — {{ .Label }}</title>
<link rel="preconnect" href="https://fonts.bunny.net" crossorigin>
<link rel="stylesheet" href="https://fonts.bunny.net/css?family=cormorant-garamond:600,700|inter:400,500,600|jetbrains-mono:400,500&display=swap">
<style>
  :root {
    color-scheme: light dark;
    --cream:       #F4EFE6;
    --cream-deep:  #ECE5D5;
    --bg-elev:     #FBF7EE;
    --ink:         #1A1814;
    --stone:       #7A7670;
    --cardinal:    #7A1F2B;
    --gold:        #C9A961;
    --night:       #1E2D45;
    --rule:        rgba(26, 24, 20, 0.12);
    --font-display:"Cormorant Garamond","EB Garamond",Georgia,serif;
    --font-body:   "Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    --font-mono:   "JetBrains Mono","IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  body {
    max-width: 62rem; margin: 0 auto; padding: 1.25rem 1rem 3rem;
    background: var(--cream); color: var(--ink);
    font-family: var(--font-body); line-height: 1.5;
  }
  header { display: flex; align-items: center; flex-wrap: wrap; gap: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--rule); margin-bottom: 1.5rem; }
  .sk-brand { display: inline-flex; align-items: center; gap: 0.65rem; text-decoration: none; color: inherit; }
  .sk-brand:hover { color: var(--cardinal); }
  .sk-brand__mark { width: 30px; height: 30px; flex-shrink: 0; }
  .sk-brand > span { font-family: var(--font-display); font-weight: 500; font-size: 1.45rem; letter-spacing: -0.01em; color: var(--cardinal); }
  .sk-brand > span strong { font-weight: 700; }
  .sk-brand > span small { font-family: var(--font-body); font-size: 0.92rem; font-weight: 400; color: var(--stone); margin-left: 0.25rem; }
  nav { display: flex; flex-wrap: wrap; gap: 0.1rem 1rem; }
  nav a { text-decoration: none; color: var(--night); font-size: 0.92rem; }
  nav a:hover { color: var(--cardinal); }
  h2, h3 { font-family: var(--font-display); font-weight: 600; color: var(--ink); letter-spacing: -0.005em; }
  h2 { font-size: 1.7rem; margin: 1.25rem 0 1rem; }
  h3 { font-size: 1.25rem; margin: 1.5rem 0 0.6rem; }
  p, li { color: var(--ink); }
  small, .muted { color: var(--stone); }
  a { color: var(--night); }
  a:hover { color: var(--cardinal); }
  .banner { background: var(--gold); color: var(--ink); padding: 0.55rem 1rem; margin-bottom: 1rem; border-radius: 2px; font-size: 0.92rem; }
  .banner.demo { background: var(--cardinal); color: var(--cream); }
  .err { background: #FBE6E6; color: var(--cardinal); padding: 0.55rem 1rem; border-radius: 2px; margin-bottom: 1rem; border: 1px solid rgba(122,31,43,0.2); }
  label { display: block; margin: 0.85rem 0 0.25rem; font-weight: 500; color: var(--ink); }
  input[type=email], input[type=password], input[type=text], input[type=url], input[type=number], input[type=file], select, textarea {
    width: 100%; padding: 0.5rem 0.6rem;
    border: 1px solid var(--rule); border-radius: 2px; box-sizing: border-box;
    background: var(--bg-elev); color: var(--ink); font-family: inherit; font-size: 0.95rem;
  }
  input:focus, select:focus, textarea:focus { outline: 2px solid var(--gold); outline-offset: 1px; }
  textarea { font-family: var(--font-mono); }
  button {
    padding: 0.55rem 1.1rem; background: var(--cardinal); color: var(--cream);
    border: 1px solid var(--cardinal); border-radius: 2px; cursor: pointer;
    font-family: var(--font-body); font-weight: 500; letter-spacing: 0.01em;
  }
  button:hover { filter: brightness(0.92); }
  button.secondary { background: transparent; color: var(--cardinal); border: 1px solid var(--cardinal); }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.5rem 0.55rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
  th { font-weight: 600; color: var(--ink); }
  code { font-family: var(--font-mono); color: var(--ink); font-size: 0.88em; }
  pre { white-space: pre-wrap; word-break: break-all; background: var(--cream-deep); padding: 0.6rem 0.75rem; border-radius: 2px; font-family: var(--font-mono); }
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">
  <defs>
    <radialGradient id="wax-shade" cx="35%" cy="30%" r="80%">
      <stop offset="0%" stop-color="#9A2D3A"/>
      <stop offset="60%" stop-color="#7A1F2B"/>
      <stop offset="100%" stop-color="#4A1018"/>
    </radialGradient>
    <symbol id="sk-mark" viewBox="0 0 32 32">
      <path d="M4 22 L10 28 L22 16 L16 10 Z" fill="#C9A961" opacity="0.85"/>
      <path d="M4 22 L10 28 L22 16 L16 10 Z" fill="none" stroke="#1A1814" stroke-width="0.6" opacity="0.4"/>
      <circle cx="20" cy="14" r="10" fill="url(#wax-shade)"/>
      <circle cx="20" cy="14" r="10" fill="none" stroke="#4A1018" stroke-width="0.6"/>
      <circle cx="20" cy="14" r="7.5" fill="none" stroke="#C9A961" stroke-width="0.4" opacity="0.6"/>
      <text x="20" y="17.5" text-anchor="middle" font-family="Cormorant Garamond, serif" font-size="9" font-weight="700" fill="#C9A961">SK</text>
    </symbol>
  </defs>
</svg>
{{ if .EvalBanner }}<div class="banner">⚠ Evaluation mode — not for production</div>{{ end }}
{{ if .DemoBanner }}<div class="banner demo" data-testid="demo-banner">⚠ Public demo — all data is public and purged daily</div>{{ end }}
<header>
  <a href="/admin/dashboard" class="sk-brand" aria-label="SealKeeper admin, home">
    <svg class="sk-brand__mark" viewBox="0 0 32 32" aria-hidden="true"><use href="#sk-mark"/></svg>
    <span><strong>SealKeeper</strong> admin <small>— {{ .Label }}</small></span>
  </a>
  {{ if .Admin }}<nav>
    <a href="/admin/dashboard">Dashboard</a>
    <a href="/admin/domains">Domains</a>
    <a href="/admin/policies">Policies</a>
    <a href="/admin/elevations">Elevations</a>
    <a href="/admin/libraries">Libraries</a>
    <a href="/admin/templates">Email templates</a>
    <a href="/admin/integrations">Integrations</a>
    <a href="/admin/smtp">SMTP</a>
    <a href="/admin/branding">Branding</a>
    <a href="/admin/security">Security keys</a>
    <a href="/admin/admins">Admins</a>
    <a href="/admin/account">Account</a>
    <a href="/admin/audit">Audit log</a>
    {{ if or .EvalBanner .DemoBanner }}<a href="/admin/captured-mail">Captured mail</a>{{ end }}
    <form method="POST" action="/admin/logout" style="display:inline;margin-left:1rem">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">Logout {{ .Admin.Email }}</button>
    </form>
  </nav>{{ end }}
</header>
{{end}}

{{define "footer"}}
<script nonce="{{ $.CSPNonce }}">
// data-confirm replaces inline onclick/onsubmit handlers (blocked by CSP).
document.addEventListener('submit', function (e) {
  var msg = (e.submitter && e.submitter.dataset.confirm) || e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});
</script>
</body></html>
{{end}}
`

const adminLoginTpl = `{{define "login.html"}}{{template "header" .}}
<main>
<h2>Sign in</h2>
{{ if .Error }}
<div class="err" data-testid="error">
  {{ if eq .Error "totp_unrecoverable" }}
    The stored second-factor secret can no longer be decrypted — typically
    because the instance was restarted without a fixed
    <code>SK_MASTER_SECRET</code> and a fresh one was minted. Ask an
    operator to run
    <code>sealkeeper admin reset-password --email &lt;your-email&gt;</code>
    so you can re-enrol from scratch.
  {{ else if eq .Error "bad_creds" }}
    Email, password or authenticator code is incorrect.
  {{ else if eq .Error "locked" }}
    Too many failed attempts — this account is locked for the next 15 minutes.
  {{ else if eq .Error "rate_limited" }}
    Too many sign-in attempts from your network. Try again in a few minutes.
  {{ else if eq .Error "disabled" }}
    This account has been disabled by another administrator.
  {{ else if eq .Error "totp_required" }}
    Password accepted — enter your authenticator code to finish signing in.
  {{ else }}
    {{ .Error }}
  {{ end }}
</div>
{{ end }}
<form method="POST" action="/admin/login" data-testid="login-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autofocus autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <label for="totp">TOTP code or recovery code <small>(omit on first sign-in)</small></label>
  <input id="totp" name="totp" type="text" pattern="[0-9]{6}|[A-Za-z0-9]{5}-[A-Za-z0-9]{5}" autocomplete="one-time-code">
  <p style="margin-top:1rem"><button type="submit">Sign in</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminSetupTpl = `{{define "setup.html"}}{{template "header" .}}
<main>
<h2>Account setup required</h2>
<p>Before you can use the console you must {{ if .NeedsPasswordChange }}change the bootstrap password{{ end }}{{ if and .NeedsPasswordChange .NeedsTOTP }} and {{ end }}{{ if .NeedsTOTP }}enrol an authenticator{{ end }}.</p>
<form method="POST" action="/admin/setup">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  {{ if .NeedsPasswordChange }}
  <fieldset><legend>New password</legend>
    <label for="np">New password (ANSSI B3 — ≥ 16 chars, mixing 3 of lower/upper/digit/symbol)</label>
    <input id="np" name="new_password" type="password" minlength="16" required autocomplete="new-password">

    <div id="pw-meter" data-testid="password-entropy"
         style="margin:0.4rem 0 0.75rem; padding:0.5rem 0.75rem; background:var(--bg-elev); border:1px solid var(--rule); border-radius:2px; font-size:0.875rem">
      <div style="display:flex; gap:0.75rem; flex-wrap:wrap; align-items:center">
        <span>Estimated entropy:&nbsp;<strong data-testid="pw-bits" style="font-family:var(--font-mono)">—</strong>&nbsp;bits</span>
        <span data-testid="pw-level" style="padding:0.1rem 0.55rem; border-radius:999px; font-size:0.78rem; background:var(--stone); color:var(--cream)">—</span>
        <span data-testid="pw-classes" style="color:var(--stone)">classes: <span data-testid="pw-classes-count">0</span> / 4</span>
      </div>
      <div style="margin-top:0.45rem; height:6px; background:var(--cream-deep); border-radius:3px; overflow:hidden">
        <div data-testid="pw-bar" style="height:100%; width:0; background:linear-gradient(90deg,#B23A48 0%,var(--gold) 60%,#2A6F4F 100%); transition:width 120ms ease"></div>
      </div>
      <p data-testid="pw-hint" style="margin:0.4rem 0 0; color:var(--stone); font-size:0.8rem">Type to evaluate. ANSSI thresholds: B1 ≥ 50 bits, B2 ≥ 80, B3 ≥ 100.</p>
    </div>

    <label for="np2">Confirm new password</label>
    <input id="np2" name="new_password_confirm" type="password" minlength="16" required autocomplete="new-password">
  </fieldset>
  {{ end }}
  {{ if .NeedsTOTP }}
  <fieldset style="margin-top:1.5rem"><legend>Authenticator (TOTP)</legend>
    <p>Scan the QR code below with your authenticator app (Authy, Aegis, 1Password, Google Authenticator…), then enter the 6-digit code it displays.</p>
    {{ if .OtpauthQR }}
    <p style="margin:0.5rem 0 1rem">
      <img src="{{ .OtpauthQR }}" alt="QR code containing the otpauth URL" data-testid="totp-qr"
           style="display:block; width:200px; height:200px; image-rendering:pixelated; background:white; padding:6px; border:1px solid var(--rule); border-radius:2px">
    </p>
    {{ end }}
    <details style="margin:0 0 1rem">
      <summary style="cursor:pointer; color:var(--stone)">Can't scan? Show the secret + raw otpauth URL</summary>
      <p style="margin-top:0.5rem"><strong>Manual entry secret:</strong> <code data-testid="totp-secret">{{ .Secret }}</code></p>
      <p style="margin:0.5rem 0 0"><strong>otpauth URL:</strong></p>
      <pre data-testid="otpauth">{{ .OtpauthURL }}</pre>
    </details>
    <p><strong>Recovery codes (save these now — they will not be shown again):</strong></p>
    <ul data-testid="recovery-codes">{{ range .RecoveryCodes }}<li><code>{{ . }}</code></li>{{ end }}</ul>
    <input type="hidden" name="setup_blob" value="{{ .SetupBlob }}">
    <label for="tc">Code from your authenticator</label>
    <input id="tc" name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{6}" required>
  </fieldset>
  {{ end }}
  <p style="margin-top:1rem"><button type="submit">Save and continue</button></p>
</form>

{{ if .NeedsPasswordChange }}
<script nonce="{{ $.CSPNonce }}">
(function () {
  // Live entropy gauge under the new-password field. Uses a quick
  // length × log2(detected-charset-size) estimate — the same kind of
  // heuristic zxcvbn falls back to when no dictionary fires — and the
  // ANSSI B1/B2/B3 thresholds for the badge.
  var np = document.getElementById('np');
  var meter = document.getElementById('pw-meter');
  if (!np || !meter) return;
  var bitsEl    = meter.querySelector('[data-testid="pw-bits"]');
  var levelEl   = meter.querySelector('[data-testid="pw-level"]');
  var classesEl = meter.querySelector('[data-testid="pw-classes-count"]');
  var barEl     = meter.querySelector('[data-testid="pw-bar"]');
  var hintEl    = meter.querySelector('[data-testid="pw-hint"]');
  var LOG2      = Math.log2 || function (x) { return Math.log(x) / Math.LN2; };

  function evaluate(s) {
    if (!s) return { bits: 0, classes: 0, level: '—', tone: 'stone', hint: 'Type to evaluate.' };
    var hasLower = /[a-z]/.test(s);
    var hasUpper = /[A-Z]/.test(s);
    var hasDigit = /[0-9]/.test(s);
    var hasSym   = /[^A-Za-z0-9]/.test(s);
    var classes  = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSym ? 1 : 0);
    var charsetSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasDigit ? 10 : 0) + (hasSym ? 33 : 0);
    if (charsetSize === 0) charsetSize = 1;
    var bits = s.length * LOG2(charsetSize);
    var level = 'below B1', tone = '#B23A48';
    if (bits >= 100) { level = '✓ B3'; tone = '#2A6F4F'; }
    else if (bits >= 80) { level = '✓ B2'; tone = '#7A1F2B'; }
    else if (bits >= 50) { level = '✓ B1'; tone = '#C9A961'; }
    var hint = 'Server requires ANSSI B3 (≥ 16 chars + 3 classes).';
    if (s.length < 16) hint = 'Server requires ≥ 16 characters (you have ' + s.length + ').';
    else if (classes < 3) hint = 'Server requires 3 of lower / upper / digit / symbol (you have ' + classes + ').';
    return { bits: bits, classes: classes, level: level, tone: tone, hint: hint };
  }

  function render() {
    var v = evaluate(np.value);
    bitsEl.textContent = v.bits.toFixed(1);
    levelEl.textContent = v.level;
    levelEl.style.background = v.tone;
    classesEl.textContent = v.classes;
    barEl.style.width = Math.min(100, v.bits) + '%';
    hintEl.textContent = v.hint;
  }
  np.addEventListener('input', render);
  render();
})();
</script>
{{ end }}
</main>
{{template "footer" .}}{{end}}
`

const adminDashboardTpl = `{{define "dashboard.html"}}{{template "header" .}}
<main>
<h2>Welcome, {{ .Admin.Email }}</h2>

<section style="display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:0.75rem; margin:1rem 0 1.5rem">
  <div style="background:var(--bg-elev); border:1px solid var(--rule); border-radius:2px; padding:0.75rem 0.9rem">
    <div style="color:var(--stone); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em">Run mode</div>
    <div style="font-family:var(--font-display); font-size:1.6rem; color:{{ if eq .Mode "production" }}var(--ink){{ else if eq .Mode "demo" }}var(--cardinal){{ else }}var(--gold-dim){{ end }}">{{ .Mode }}</div>
  </div>
  <div style="background:var(--bg-elev); border:1px solid var(--rule); border-radius:2px; padding:0.75rem 0.9rem">
    <div style="color:var(--stone); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em">Mail sender</div>
    <div style="font-family:var(--font-mono); font-size:1rem; padding-top:0.4rem">{{ .SenderName }}</div>
  </div>
  <div style="background:var(--bg-elev); border:1px solid var(--rule); border-radius:2px; padding:0.75rem 0.9rem">
    <div style="color:var(--stone); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em">Audit entries</div>
    <div style="font-family:var(--font-display); font-size:1.6rem">{{ .AuditCount }}</div>
  </div>
  <div style="background:var(--bg-elev); border:1px solid var(--rule); border-radius:2px; padding:0.75rem 0.9rem">
    <div style="color:var(--stone); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em">Last login</div>
    <div style="font-family:var(--font-mono); font-size:0.9rem; padding-top:0.4rem">{{ if .Admin.LastLoginAt }}{{ .Admin.LastLoginAt.Format "2006-01-02 15:04 UTC" }}{{ else }}—{{ end }}</div>
  </div>
</section>

<p style="color:var(--stone); font-size:0.9rem">
  Base URL <code>{{ .BaseURL }}</code> · Instance domain <code>{{ .InstanceDomain }}</code> · Session expires <code>{{ .Session.ExpiresAt.Format "15:04 UTC" }}</code>.
</p>

{{ if ne .Mode "production" }}
<section style="margin-top:1.5rem; background:#FBF7EE; border:1px solid var(--gold); border-radius:2px; padding:1rem 1.25rem">
  <h3 style="margin-top:0; color:var(--ink)">Switching to production mode</h3>
  <p style="margin:0.4rem 0">The run mode is decided at startup by the <code>SK_MODE</code> environment variable. Switching requires a restart with the right env in place.</p>
  <p style="margin:0.4rem 0"><strong>Minimum production envelope</strong> (set before <code>docker run</code>):</p>
  <pre style="margin:0.5rem 0">SK_MODE=production
SK_BASE_URL=https://seal.example.eu
SK_MASTER_SECRET=$(openssl rand -base64 32)
SK_DATABASE_URL=postgres://sk:secret@db:5432/sealkeeper?sslmode=require
SK_INSTANCE_DOMAIN=seal.example.eu</pre>
  <p style="margin:0.4rem 0">In production the <em>Evaluation mode</em> and <em>Public demo</em> banners both disappear, the in-memory mail capture is replaced by the real SMTP relay (see <a href="/admin/smtp">SMTP</a>), and rate-limiting / lockout durations apply at full strength.</p>
  <p style="margin:0.4rem 0; color:var(--stone); font-size:0.875rem">Reference recipe: see the <em>Operator docs</em> at <a href="https://github.com/sched75/SealKeeper/blob/main/docs/prd/H-deployment.md">docs/prd/H-deployment.md</a> and the production Compose stack at <code>docker-compose.yml</code> in the repo root.</p>
</section>
{{ end }}

<p style="margin-top:1.5rem">Jump straight to a surface from the nav above. The audit log and captured mail viewer are wired today.</p>
</main>
{{template "footer" .}}{{end}}
`

const adminAuditTpl = `{{define "audit.html"}}{{template "header" .}}
<main>
<h2>Audit log{{ if not .ChainOK }} <span class="err" style="display:inline-block">⚠ chain integrity break</span>{{ end }}</h2>
<table><thead><tr><th>#</th><th>When (UTC)</th><th>Event</th><th>Actor</th><th>Target</th><th>Details</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .SequenceNo }}</td>
  <td><code>{{ .Occurred }}</code></td>
  <td><code>{{ .EventType }}</code></td>
  <td>{{ .Actor }}</td>
  <td><code>{{ .Target }}</code></td>
  <td><details><summary>view</summary><pre>{{ .Details }}</pre></details></td>
</tr>{{ else }}<tr><td colspan="6"><em>No entries yet.</em></td></tr>{{ end }}
</tbody></table>
<p style="margin-top:1rem">
  {{ if gt .PrevPage 0 }}<a href="/admin/audit?page={{ .PrevPage }}">← previous</a>{{ end }}
  <a href="/admin/audit?page={{ .NextPage }}" style="margin-left:1rem">next →</a>
</p>
</main>
{{template "footer" .}}{{end}}
`

const adminDomainsTpl = `{{define "domains.html"}}{{template "header" .}}
<main>
<h2>Allowed domains</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if eq .OK "imported" }} — created <strong>{{ .ImportCreated }}</strong>, skipped <strong>{{ .ImportSkipped }}</strong>, errors <strong>{{ .ImportErrors }}</strong>{{ if .Details }}<br><small>{{ .Details }}</small>{{ end }}{{ end }}</div>{{ end }}
<p>An empty list keeps the public flow open (handy for eval). As soon as you add one entry the allowlist gates every <code>POST /api/v1/request</code>. Use <code>*.entreprise.com</code> to match any subdomain (does not match the bare apex).</p>

<table data-testid="domains-table"><thead><tr><th>Name</th><th>Description</th><th>Active</th><th>Created</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .Name }}</code></td>
  <td>{{ .Description }}</td>
  <td>{{ if .Active }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02 15:04 UTC" }}</code></td>
  <td>
    <form method="POST" action="/admin/domains/{{ .ID }}/toggle" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Active }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/domains/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="5"><em>No domains yet — the public flow accepts every recipient.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add a domain</h3>
<form method="POST" action="/admin/domains/add" data-testid="add-domain-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="name">Name (FQDN or <code>*.example.com</code>)</label>
  <input id="name" name="name" type="text" required>
  <label for="description">Description (optional)</label>
  <input id="description" name="description" type="text">
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="active" checked> Active immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add domain</button></p>
</form>

<h3 style="margin-top:2rem">Import CSV</h3>
<p style="font-size:0.875rem;color:#4b5563">Columns: <code>name,description,active</code>. Header row optional. Existing names are skipped silently; invalid rows are reported but don't abort the import.</p>
<form method="POST" action="/admin/domains/import" enctype="multipart/form-data" data-testid="import-domain-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="csv-domains">CSV file (max 2 MB)</label>
  <input id="csv-domains" name="csv" type="file" accept=".csv,text/csv" required>
  <p style="margin-top:1rem"><button type="submit">Import</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminPoliciesTpl = `{{define "policies.html"}}{{template "header" .}}
<main>
<h2>Policies</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>One policy per (domain, ANSSI level). When no policy is configured for an email's bucket the public flow drops the request silently (FR-B.13). Policies must reference an allowed domain — add one in <a href="/admin/domains">Domains</a> first.</p>

<table data-testid="policies-table"><thead><tr><th>Domain</th><th>Level</th><th>Name</th><th>Generator</th><th>N props</th><th>Active</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .DomainName }}</code></td>
  <td><span class="badge">{{ .ANSSILevel }}</span></td>
  <td>{{ .Name }}</td>
  <td><code>{{ .Generator }}</code></td>
  <td>{{ .ProposalCount }}</td>
  <td>{{ if .Active }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <a href="/admin/policies/{{ .ID }}/edit" class="secondary" style="display:inline-block;padding:0.55rem 1.1rem;border:1px solid var(--cardinal);color:var(--cardinal);text-decoration:none;border-radius:2px">Edit</a>
    <form method="POST" action="/admin/policies/{{ .ID }}/toggle" style="display:inline;margin-left:0.5rem">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Active }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/policies/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="8"><em>No policies yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add a policy</h3>
<form method="POST" action="/admin/policies/add" data-testid="add-policy-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="domain_id">Domain</label>
  <select id="domain_id" name="domain_id" required>
    {{ range .Domains }}<option value="{{ .ID }}">{{ .Name }}</option>{{ else }}<option value="" disabled selected>(add a domain first)</option>{{ end }}
  </select>
  <label for="anssi_level">ANSSI level</label>
  <select id="anssi_level" name="anssi_level" required>
    <option value="B1">B1 — default (every user not elevated)</option>
    <option value="B2">B2 — elevated managers</option>
    <option value="B3">B3 — elevated system admins</option>
  </select>
  <label for="name">Name</label>
  <input id="name" name="name" type="text" required>
  <label for="generator">Generator</label>
  <select id="generator" name="generator" required>
    <option value="G1">G1 — citation + transforms (B1 target)</option>
    <option value="G2" selected>G2 — Diceware (B2 target)</option>
    <option value="G3">G3 — random alphanumeric (B3 target)</option>
  </select>
  <label for="params_json">Parameters (JSON)</label>
  <textarea id="params_json" name="params_json" rows="8" style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{
  "library": ["alpha","beta","gamma","delta","epsilon","zeta","eta","theta"],
  "numberOfWords": 6,
  "separatorOptions": ["-","_",".","/","+",":","|",";",",","~"]
}</textarea>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">PolicyDescriptor parameters per module A. Validated as a JSON object.</small>

  <fieldset id="entropy-preview" data-testid="entropy-preview"
    style="margin-top:1rem;padding:0.75rem 1rem;border:1px solid #d1d5db;border-radius:4px;background:#f9fafb">
    <legend style="padding:0 0.5rem;font-weight:600">Entropy preview</legend>
    <p style="margin:0.25rem 0;font-family:ui-monospace,monospace">
      min: <strong data-testid="entropy-min">—</strong> bits
      &nbsp;·&nbsp; expected: <strong data-testid="entropy-expected">—</strong> bits
      &nbsp;·&nbsp; max: <strong data-testid="entropy-max">—</strong> bits
    </p>
    <p style="margin:0.5rem 0">
      <span data-testid="entropy-badge-B1" class="ent-badge">B1 ≥ 50</span>
      <span data-testid="entropy-badge-B2" class="ent-badge">B2 ≥ 80</span>
      <span data-testid="entropy-badge-B3" class="ent-badge">B3 ≥ 100</span>
    </p>
    <details style="margin:0.4rem 0 0">
      <summary style="cursor:pointer;color:var(--stone);font-size:0.85rem">Breakdown — how the bits add up</summary>
      <table data-testid="entropy-breakdown" style="margin-top:0.4rem;font-size:0.85rem">
        <thead><tr><th style="text-align:left">Component</th><th style="text-align:right">bits</th></tr></thead>
        <tbody></tbody>
      </table>
    </details>
    <p data-testid="entropy-mismatch" style="margin:0.4rem 0 0;color:#7A1F2B;font-size:0.85rem;display:none"></p>
    <p data-testid="entropy-warning" style="margin:0.25rem 0 0;color:#991b1b;font-size:0.875rem;display:none"></p>
    <p data-testid="entropy-status" style="margin:0.25rem 0 0;color:#6b7280;font-size:0.875rem">Loading generator bundle…</p>
  </fieldset>
  <style>
    .ent-badge { display:inline-block; padding:0.15rem 0.5rem; margin-right:0.35rem; border-radius:3px; font-size:0.85rem; border:1px solid transparent }
    .ent-badge.met { background:#dcfce7; color:#166534; border-color:#86efac }
    .ent-badge.miss { background:#fee2e2; color:#991b1b; border-color:#fca5a5 }
  </style>

  <label for="proposal_count">Proposals shown</label>
  <input id="proposal_count" name="proposal_count" type="number" value="5" min="1" max="20">
  <label for="regenerate_limit">Re-generate limit</label>
  <input id="regenerate_limit" name="regenerate_limit" type="number" value="3" min="0" max="10">
  <label for="session_ttl_seconds">Session TTL (seconds)</label>
  <input id="session_ttl_seconds" name="session_ttl_seconds" type="number" value="900" min="60" max="86400">
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="notify_on_consult"> Email notification post-consultation
  </label><br>
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.25rem">
    <input type="checkbox" name="active" checked> Active immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add policy</button></p>
</form>

<script src="/static/sealkeeper-generation.umd.js" defer></script>
<script nonce="{{ $.CSPNonce }}">
(function () {
  var form = document.querySelector('[data-testid="add-policy-form"]');
  var preview = document.getElementById('entropy-preview');
  if (!form || !preview) return;

  var status = preview.querySelector('[data-testid="entropy-status"]');
  var warn = preview.querySelector('[data-testid="entropy-warning"]');
  var els = {
    min: preview.querySelector('[data-testid="entropy-min"]'),
    expected: preview.querySelector('[data-testid="entropy-expected"]'),
    max: preview.querySelector('[data-testid="entropy-max"]'),
    B1: preview.querySelector('[data-testid="entropy-badge-B1"]'),
    B2: preview.querySelector('[data-testid="entropy-badge-B2"]'),
    B3: preview.querySelector('[data-testid="entropy-badge-B3"]'),
  };
  var generatorSel = form.querySelector('#generator');
  var paramsTA = form.querySelector('#params_json');
  var anssiSel = form.querySelector('#anssi_level');
  var breakdownBody = preview.querySelector('[data-testid="entropy-breakdown"] tbody');
  var mismatch = preview.querySelector('[data-testid="entropy-mismatch"]');

  function paramsMismatch(gen, params) {
    if (!params || typeof params !== 'object') return '';
    var hasWords = typeof params.numberOfWords === 'number' && params.numberOfWords > 0;
    var hasLibrary = Array.isArray(params.library) && params.library.length > 0;
    var hasLength = typeof params.length === 'number' && params.length > 0;
    if (gen === 'G1' && hasWords) {
      return 'numberOfWords is ignored by G1 (one citation only). Switch to G2 if you want N independent word picks.';
    }
    if ((gen === 'G1' || gen === 'G2') && !hasLibrary) {
      return gen + ' needs an inline "library" array; without it the reveal page refuses to generate.';
    }
    if (gen === 'G3' && (hasWords || hasLibrary)) {
      return 'G3 ignores library / numberOfWords (random alphanumeric draw); only length (and excludeAmbiguous) matter.';
    }
    if (gen === 'G3' && !hasLength) {
      return 'G3 expects a "length" parameter.';
    }
    return '';
  }

  function calc() {
    var fn = window.SealKeeper && window.SealKeeper.Generation && window.SealKeeper.Generation.calculateEntropy;
    if (!fn) {
      status.textContent = 'Generator bundle not loaded — entropy preview unavailable.';
      return;
    }
    var parsed;
    try {
      parsed = paramsTA.value.trim() ? JSON.parse(paramsTA.value) : {};
    } catch (e) {
      status.textContent = 'Parameters JSON invalid: ' + e.message;
      els.min.textContent = els.expected.textContent = els.max.textContent = '—';
      [els.B1, els.B2, els.B3].forEach(function (b) { b.className = 'ent-badge'; });
      warn.style.display = 'none';
      mismatch.style.display = 'none';
      if (breakdownBody) breakdownBody.innerHTML = '';
      return;
    }
    var generator = generatorSel.value;
    var policy = { generator: generator, parameters: parsed };
    var report;
    try {
      report = fn(policy);
    } catch (e) {
      // Clear the previous figures: a stale B3 badge next to a policy the
      // reveal page will refuse is exactly the misleading state to avoid.
      status.textContent = 'Cannot compute: ' + e.message;
      els.min.textContent = els.expected.textContent = els.max.textContent = '—';
      [els.B1, els.B2, els.B3].forEach(function (b) { b.className = 'ent-badge'; });
      warn.style.display = 'none';
      mismatch.style.display = 'none';
      if (breakdownBody) breakdownBody.innerHTML = '';
      return;
    }
    status.textContent = 'Live preview · same calculator the user bundle uses.';
    els.min.textContent = report.minBits.toFixed(1);
    els.expected.textContent = report.expectedBits.toFixed(1);
    els.max.textContent = report.maxBits.toFixed(1);
    if (breakdownBody) {
      breakdownBody.innerHTML = (report.breakdown || []).map(function (b) {
        return '<tr><td><code>' + b.component + '</code></td><td style="text-align:right;font-family:var(--font-mono,monospace)">' +
          b.bits.toFixed(1) + '</td></tr>';
      }).join('');
    }
    var levels = report.anssiLevels || {};
    [['B1', 50], ['B2', 80], ['B3', 100]].forEach(function (pair) {
      var key = pair[0];
      var met = levels[key];
      els[key].className = 'ent-badge ' + (met ? 'met' : 'miss');
      els[key].textContent = (met ? '✓ ' : '✗ ') + key + ' ≥ ' + pair[1];
    });
    var target = anssiSel.value;
    var thresholds = { B1: 50, B2: 80, B3: 100 };
    if (target in thresholds && report.expectedBits < thresholds[target]) {
      warn.style.display = '';
      warn.textContent = 'Expected entropy is below the configured ' + target +
        ' threshold (' + thresholds[target] + ' bits). You can save anyway — SealKeeper advises, the admin decides.';
    } else {
      warn.style.display = 'none';
    }
    var msg = paramsMismatch(generator, parsed);
    if (msg) { mismatch.style.display = ''; mismatch.textContent = '⚠ ' + msg; }
    else { mismatch.style.display = 'none'; }
  }

  // Recompute on every input within the form. Debounce so JSON parsing
  // doesn't fire on every keystroke for the params textarea.
  var timer = null;
  function schedule() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(calc, 120);
  }
  form.addEventListener('input', schedule);
  form.addEventListener('change', schedule);

  // First paint — wait briefly for the UMD bundle to register itself.
  function tryFirst(retries) {
    if (window.SealKeeper && window.SealKeeper.Generation) { calc(); return; }
    if (retries <= 0) { status.textContent = 'Generator bundle did not load.'; return; }
    setTimeout(function () { tryFirst(retries - 1); }, 100);
  }
  tryFirst(20);
})();
</script>
</main>
{{template "footer" .}}{{end}}
`

const adminElevationsTpl = `{{define "elevations.html"}}{{template "header" .}}
<main>
<h2>Elevations</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if eq .OK "imported" }} — created <strong>{{ .ImportCreated }}</strong>, skipped <strong>{{ .ImportSkipped }}</strong>, errors <strong>{{ .ImportErrors }}</strong>{{ if .Details }}<br><small>{{ .Details }}</small>{{ end }}{{ end }}</div>{{ end }}
<p>Elevations bind a specific email to the B2 or B3 policy of its domain (FR-C.38..46). An email can be in at most one list per domain.</p>

<table data-testid="elevations-table"><thead><tr><th>Domain</th><th>Email</th><th>Level</th><th>Reason</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>id={{ .DomainID }}</code></td>
  <td>{{ .Email }}</td>
  <td><span class="badge">{{ .Level }}</span></td>
  <td>{{ .Reason }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02" }}</code></td>
  <td>{{ if .LastUsedAt }}<code>{{ .LastUsedAt.Format "2006-01-02" }}</code>{{ else }}—{{ end }}</td>
  <td>
    <form method="POST" action="/admin/elevations/{{ .ID }}/delete">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">Remove</button>
    </form>
  </td>
</tr>{{ else }}<tr><td colspan="7"><em>No elevations yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add an elevation</h3>
<form method="POST" action="/admin/elevations/add">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="el-domain">Domain</label>
  <select id="el-domain" name="domain_id" required>
    {{ range .Domains }}<option value="{{ .ID }}">{{ .Name }}</option>{{ else }}<option value="" disabled selected>(add a domain first)</option>{{ end }}
  </select>
  <label for="el-email">Email</label>
  <input id="el-email" name="email" type="email" required>
  <label for="el-level">Level</label>
  <select id="el-level" name="level" required>
    <option value="B2">B2 — manager bucket</option>
    <option value="B3">B3 — system admin bucket</option>
  </select>
  <label for="el-reason">Reason (optional)</label>
  <input id="el-reason" name="reason" type="text">
  <p style="margin-top:1rem"><button type="submit">Add elevation</button></p>
</form>

<h3 style="margin-top:2rem">Import CSV</h3>
<p style="font-size:0.875rem;color:#4b5563">Columns: <code>domain,email,level,reason</code>. Level must be <code>B2</code> or <code>B3</code>. Header row optional. Existing rows are skipped; rows referencing an unknown domain are reported but don't abort the import.</p>
<form method="POST" action="/admin/elevations/import" enctype="multipart/form-data" data-testid="import-elevation-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="csv-elevations">CSV file (max 2 MB)</label>
  <input id="csv-elevations" name="csv" type="file" accept=".csv,text/csv" required>
  <p style="margin-top:1rem"><button type="submit">Import</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminLibrariesTpl = `{{define "libraries.html"}}{{template "header" .}}
<main>
<h2>Libraries</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
<p>Two kinds of libraries: <strong>dictionaries</strong> (one word per line, 4-12 letters, used by generator G2) and <strong>corpora</strong> (one citation per line, 3-25 words, used by generator G1). Comments lines starting with <code>#</code> are ignored. Files MUST be UTF-8 without BOM (module A §5.2/5.3). Identical content uploaded twice deduplicates via the SHA-256 hash.</p>

<table data-testid="libraries-table"><thead><tr><th>Name</th><th>Kind</th><th>Lang</th><th>Entries</th><th>Size</th><th>SHA-256</th><th>System</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .Name }}</td>
  <td><span class="badge">{{ .Kind }}</span></td>
  <td><code>{{ .Language }}</code></td>
  <td>{{ .EntryCount }}</td>
  <td>{{ printf "%d" .SizeBytes }} B</td>
  <td><code title="{{ .SHA256 }}">{{ slice .SHA256 0 12 }}…</code></td>
  <td>{{ if .System }}<strong>yes</strong>{{ else }}no{{ end }}</td>
  <td><code>{{ .CreatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <a class="secondary" href="/admin/libraries/{{ .ID }}/download" style="display:inline-block;padding:0.4rem 0.75rem;border:1px solid #1d4ed8;border-radius:4px;text-decoration:none">Download</a>
    <a class="secondary" href="/admin/libraries/{{ .ID }}/sample" style="display:inline-block;padding:0.4rem 0.75rem;border:1px solid #1d4ed8;border-radius:4px;text-decoration:none;margin-left:0.25rem" target="_blank">Sample</a>
    {{ if not .System }}<details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/libraries/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>{{ end }}
  </td>
</tr>{{ else }}<tr><td colspan="9"><em>No libraries uploaded yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Upload a library</h3>
<form method="POST" action="/admin/libraries/upload" enctype="multipart/form-data" data-testid="upload-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="kind">Kind</label>
  <select id="kind" name="kind" required>
    <option value="dictionary">Dictionary (one word per line)</option>
    <option value="corpus">Corpus (one citation per line)</option>
  </select>
  <label for="name">Name</label>
  <input id="name" name="name" type="text" required>
  <label for="language">Language code</label>
  <input id="language" name="language" type="text" placeholder="fr, en, es…" required>
  <label for="description">Description (optional)</label>
  <input id="description" name="description" type="text">
  <label for="file">File (UTF-8 plain text, ≤ 32 MB)</label>
  <input id="file" name="file" type="file" required accept=".txt,text/plain">
  <p style="margin-top:1rem"><button type="submit">Upload</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminTemplatesTpl = `{{define "templates.html"}}{{template "header" .}}
<main>
<h2>Email templates</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Two kinds are wired: <code>reveal_link</code> (used now by every request issuance) and <code>post_consultation</code> (used by the post-reveal notification when that feature ships). When the row is marked <em>system</em>, the built-in default applies; once you save changes the override takes precedence.</p>

<table><thead><tr><th>Kind</th><th>Language</th><th>Subject preview</th><th>Status</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td><code>{{ .Kind }}</code></td>
  <td><code>{{ .Language }}</code></td>
  <td>{{ .Subject }}</td>
  <td>{{ if .IsSystem }}<span style="color:#6b7280">system</span>{{ else }}<strong style="color:#1d4ed8">customised</strong>{{ end }}</td>
  <td>{{ if .UpdatedAt.IsZero }}—{{ else }}<code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code>{{ end }}</td>
  <td><a href="/admin/templates/edit?kind={{ .Kind }}&language={{ .Language }}">Edit</a></td>
</tr>{{ end }}
</tbody></table>
</main>
{{template "footer" .}}{{end}}
`

const adminTemplateEditTpl = `{{define "template_edit.html"}}{{template "header" .}}
<main>
<h2>Edit template — <code>{{ .Template.Kind }}</code> / <code>{{ .Template.Language }}</code>
{{ if .Template.IsSystem }}<span style="color:#6b7280;font-size:1rem">(system default)</span>{{ end }}</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }}<pre style="white-space:pre-wrap">{{ .Details }}</pre>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}

<details style="margin-bottom:1.5rem"><summary>Variables available (FR-C.72)</summary>
<table style="margin-top:0.5rem"><thead><tr><th>Name</th><th>Meaning</th></tr></thead><tbody>
{{ range .Vars }}<tr><td><code>{{ index . "name" }}</code></td><td>{{ index . "doc" }}</td></tr>{{ end }}
</tbody></table></details>

<form method="POST" action="/admin/templates/save">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <input type="hidden" name="kind" value="{{ .Template.Kind }}">
  <input type="hidden" name="language" value="{{ .Template.Language }}">

  <label for="subject">Subject (text/template)</label>
  <input id="subject" name="subject" type="text" value="{{ .Template.Subject }}" required>

  <label for="text_body">Plain text body (text/template)</label>
  <textarea id="text_body" name="text_body" rows="14" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{{ .Template.Text }}</textarea>

  <label for="html_body">HTML body (html/template — auto-escaped)</label>
  <textarea id="html_body" name="html_body" rows="14" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{{ .Template.HTML }}</textarea>

  <p style="margin-top:1rem">
    <button type="submit">Save</button>
    <button type="button" id="preview-btn" class="secondary" style="margin-left:0.5rem">Preview</button>
  </p>
</form>

<form method="POST" action="/admin/templates/reset" style="margin-top:0.5rem">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <input type="hidden" name="kind" value="{{ .Template.Kind }}">
  <input type="hidden" name="language" value="{{ .Template.Language }}">
  <button type="submit" class="secondary" data-confirm="Reset this template to the built-in default?">Reset to system default</button>
</form>

<section id="preview-out" hidden style="margin-top:2rem;border-top:1px solid #d1d5db;padding-top:1rem">
  <h3>Preview</h3>
  <p><strong>Subject:</strong> <code id="prev-subject"></code></p>
  <details open><summary>Plain text</summary><pre id="prev-text" style="background:#f3f4f6;padding:0.5rem"></pre></details>
  <details><summary>HTML (rendered)</summary><iframe id="prev-html" sandbox="" style="width:100%;height:24rem;border:1px solid #d1d5db"></iframe></details>
</section>

<script nonce="{{ $.CSPNonce }}">
document.getElementById('preview-btn').addEventListener('click', async () => {
  const fd = new FormData();
  fd.set('csrf_token', '{{ .CSRF }}');
  fd.set('kind', '{{ .Template.Kind }}');
  fd.set('language', '{{ .Template.Language }}');
  fd.set('subject', document.getElementById('subject').value);
  fd.set('text_body', document.getElementById('text_body').value);
  fd.set('html_body', document.getElementById('html_body').value);
  const r = await fetch('/admin/templates/preview', { method: 'POST', body: fd });
  const body = await r.json();
  if (!r.ok) {
    alert('Preview failed: ' + (body.detail || r.status));
    return;
  }
  document.getElementById('prev-subject').textContent = body.subject;
  document.getElementById('prev-text').textContent = body.text;
  const ifr = document.getElementById('prev-html');
  ifr.srcdoc = body.html;
  document.getElementById('preview-out').hidden = false;
});
</script>
</main>
{{template "footer" .}}{{end}}
`

const adminIntegrationsTpl = `{{define "integrations.html"}}{{template "header" .}}
<main>
<h2>Outbound integrations</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
<p>Forward audit events to a SIEM or webhook. Five kinds are wired: <code>webhook</code> (generic JSON POST), <code>splunk</code> (HEC), <code>sentinel</code> (Log Analytics Data Collector), <code>elastic</code> (_bulk), <code>syslog</code> (RFC 5424). Configuration is per-kind JSON — examples in the form below.</p>
<p style="font-size:0.875rem;color:#4b5563">Dispatcher stats: delivered <strong>{{ .Stats.Delivered }}</strong> · failed <strong>{{ .Stats.Failed }}</strong> · drops <strong>{{ .Stats.Drops }}</strong></p>

<table><thead><tr><th>Name</th><th>Kind</th><th>Enabled</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .Name }}</td>
  <td><code>{{ .Kind }}</code></td>
  <td>{{ if .Enabled }}<strong style="color:#166534">yes</strong>{{ else }}<span style="color:#991b1b">no</span>{{ end }}</td>
  <td><code>{{ .UpdatedAt.Format "2006-01-02 15:04" }}</code></td>
  <td>
    <form method="POST" action="/admin/integrations/{{ .ID }}/toggle" style="display:inline">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">{{ if .Enabled }}Disable{{ else }}Enable{{ end }}</button>
    </form>
    <form method="POST" action="/admin/integrations/{{ .ID }}/test" style="display:inline;margin-left:0.25rem">
      <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
      <button type="submit" class="secondary">Test</button>
    </form>
    <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
      <form method="POST" action="/admin/integrations/{{ .ID }}/delete" style="margin-top:0.5rem">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <label>Type <code>{{ .Name }}</code> to confirm:</label>
        <input name="confirm" type="text" required style="width:auto;display:inline-block">
        <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </details>
  </td>
</tr>{{ else }}<tr><td colspan="5"><em>No integrations configured yet.</em></td></tr>{{ end }}
</tbody></table>

<h3 style="margin-top:2rem">Add an integration</h3>
<form method="POST" action="/admin/integrations/add">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="name">Name (unique)</label>
  <input id="name" name="name" type="text" required>
  <label for="kind">Kind</label>
  <select id="kind" name="kind" required>
    <option value="webhook">webhook — generic JSON POST</option>
    <option value="splunk">splunk — HTTP Event Collector</option>
    <option value="sentinel">sentinel — MS Sentinel Log Analytics</option>
    <option value="elastic">elastic — Elasticsearch _bulk</option>
    <option value="syslog">syslog — RFC 5424 UDP/TCP</option>
  </select>
  <label for="config_json">Configuration (JSON)</label>
  <textarea id="config_json" name="config_json" rows="10" required style="width:100%;font-family:ui-monospace,monospace;padding:0.5rem">{
  "url": "https://example.com/events",
  "bearer_token": "REPLACE_ME",
  "timeout_sec": 5
}</textarea>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">
    webhook: <code>url, bearer_token|basic_user+basic_pass, headers, timeout_sec</code>.
    splunk: <code>url, token, index, sourcetype</code>.
    sentinel: <code>workspace_id, shared_key (base64), log_type</code>.
    elastic: <code>url, index, api_key|bearer_token</code>.
    syslog: <code>address ("host:port"), network ("udp"|"tcp"), facility, hostname, app_name</code>.
  </small>
  <label for="filters_json">Filters (JSON, optional)</label>
  <input id="filters_json" name="filters_json" type="text" placeholder='{"event_types":["admin.","request.rate_limited"]}'>
  <small style="display:block;color:#6b7280;margin-top:0.25rem">Empty filters forward every event. Entries ending in <code>.</code> match by prefix.</small>
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="enabled" checked> Enabled immediately
  </label>
  <p style="margin-top:1rem"><button type="submit">Add integration</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

const adminBrandingTpl = `{{define "branding.html"}}{{template "header" .}}
<main>
<h2>Branding</h2>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Customise the instance name, three accent colours, support contact and logo. The public landing page, the reveal page and outbound emails all consume these values. Live preview on user pages is reported to v0.2 (FR-C.68); for now use the public links below the form to eyeball.</p>

<section style="display:grid;grid-template-columns:1fr 1fr;gap:2rem">
  <div>
    <h3>Identity</h3>
    <form method="POST" action="/admin/branding/save">
      <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
      <label for="instance_name">Instance name</label>
      <input id="instance_name" name="instance_name" type="text" required value="{{ .Branding.InstanceName }}">
      <label for="primary_color">Primary colour</label>
      <input id="primary_color" name="primary_color" type="color" value="{{ .Branding.PrimaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.PrimaryColor }}</code></small>
      <label for="secondary_color">Secondary colour (banner + accent)</label>
      <input id="secondary_color" name="secondary_color" type="color" value="{{ .Branding.SecondaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.SecondaryColor }}</code></small>
      <label for="tertiary_color">Tertiary colour (titles)</label>
      <input id="tertiary_color" name="tertiary_color" type="color" value="{{ .Branding.TertiaryColor }}" style="width:6rem;height:2.25rem;padding:0">
      <small style="display:inline-block;margin-left:0.5rem;color:#6b7280"><code>{{ .Branding.TertiaryColor }}</code></small>
      <label for="contact_url">Support / contact URL (optional)</label>
      <input id="contact_url" name="contact_url" type="url" value="{{ .Branding.ContactURL }}" placeholder="https://example.com/support">
      <p style="margin-top:1rem"><button type="submit">Save</button></p>
    </form>
  </div>

  <div>
    <h3>Logo</h3>
    {{ if .Branding.HasLogo }}
      <p><img src="/static/branding/logo" alt="Current logo" style="max-height:64px;border:1px solid #d1d5db;padding:0.5rem;background:white"></p>
      <p style="font-size:0.875rem;color:#4b5563">Stored type: <code>{{ .Branding.LogoMIME }}</code></p>
      <form method="POST" action="/admin/branding/logo/clear" style="margin-bottom:1rem">
        <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
        <button type="submit" class="secondary">Remove logo</button>
      </form>
    {{ else }}
      <p style="color:#6b7280">No logo uploaded yet. The public pages hide the image when this is empty.</p>
    {{ end }}
    <form method="POST" action="/admin/branding/logo" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
      <label for="logo">Upload (PNG or SVG, ≤ 256 KB, ~64 px height)</label>
      <input id="logo" name="logo" type="file" accept="image/png,image/svg+xml" required>
      <p style="margin-top:1rem"><button type="submit">Upload logo</button></p>
    </form>
  </div>
</section>

<hr style="margin:2rem 0">
<p style="font-size:0.875rem;color:#4b5563">
  Preview targets:
  <a href="/" target="_blank">public landing</a> ·
  outbound email subject is rendered live in
  <a href="/admin/templates">Email templates</a>.
</p>
</main>
{{template "footer" .}}{{end}}
`

const adminCapturedTpl = `{{define "captured.html"}}{{template "header" .}}
<main>
<h2>Captured mail (eval mode)</h2>
<table><thead><tr><th>#</th><th>When (UTC)</th><th>To</th><th>Subject</th><th>Body</th></tr></thead><tbody>
{{ range .Items }}<tr>
  <td>{{ .ID }}</td>
  <td><code>{{ .Timestamp }}</code></td>
  <td>{{ .To }}</td>
  <td>{{ .Subject }}</td>
  <td><details><summary>view</summary><pre>{{ .Body }}</pre></details></td>
</tr>{{ else }}<tr><td colspan="5"><em>No captured mail yet.</em></td></tr>{{ end }}
</tbody></table>
</main>
{{template "footer" .}}{{end}}
`

// ----- account + admins management -----------------------------------------

func (s *Server) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	s.renderAdmin(w, "account", map[string]any{
		"Admin":      a,
		"Session":    sess,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Label":      s.adminLabel,
		"CSRF":       sess.CSRFToken,
		"OK":         querySlug(r, "ok"),
		"Error":      querySlug(r, "err"),
	})
}

func (s *Server) handleAdminAccountEmailChange(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if slug, ok := s.requireCurrentPassword(r); !ok {
		http.Redirect(w, r, "/admin/account?err="+slug, http.StatusSeeOther)
		return
	}
	oldEmail := a.Email
	newEmail := strings.TrimSpace(r.FormValue("email"))
	err := s.adminRepo.ChangeEmail(r.Context(), a.ID, newEmail)
	switch {
	case errors.Is(err, admin.ErrInvalidEmail):
		http.Redirect(w, r, "/admin/account?err=invalid_email", http.StatusSeeOther)
		return
	case errors.Is(err, admin.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/account?err=already_exists", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("admin.ChangeEmail failed", "err", err)
		http.Redirect(w, r, "/admin/account?err=internal", http.StatusSeeOther)
		return
	}
	_ = s.adminRepo.RevokeOtherSessions(r.Context(), a.ID, sess.Token)
	s.auditAppend(r.Context(), "admin.email_changed", oldEmail, newEmail, map[string]any{
		"admin_id": a.ID,
	})
	http.Redirect(w, r, "/admin/account?ok=email_changed", http.StatusSeeOther)
}

func (s *Server) handleAdminAccountPasswordChange(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if slug, ok := s.requireCurrentPassword(r); !ok {
		http.Redirect(w, r, "/admin/account?err="+slug, http.StatusSeeOther)
		return
	}
	np := r.FormValue("new_password")
	np2 := r.FormValue("new_password_confirm")
	if np != np2 {
		http.Redirect(w, r, "/admin/account?err=password_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.adminRepo.ChangePassword(r.Context(), a.ID, np); err != nil {
		if errors.Is(err, admin.ErrPasswordTooWeak) {
			http.Redirect(w, r,
				"/admin/account?err=password_too_weak&details="+url.QueryEscape(err.Error()),
				http.StatusSeeOther)
			return
		}
		s.logger.Error("admin.ChangePassword failed", "err", err)
		http.Redirect(w, r, "/admin/account?err=internal", http.StatusSeeOther)
		return
	}
	// Every other session dies with the old password.
	_ = s.adminRepo.RevokeOtherSessions(r.Context(), a.ID, sess.Token)
	s.auditAppend(r.Context(), "admin.password_changed", a.Email, "", map[string]any{
		"admin_id": a.ID,
	})
	http.Redirect(w, r, "/admin/account?ok=password_changed", http.StatusSeeOther)
}

func (s *Server) handleAdminAdmins(w http.ResponseWriter, r *http.Request) {
	s.renderAdminsPage(w, r, querySlug(r, "ok"), "", "")
}

// renderAdminsPage renders /admin/admins. bootstrapEmail/Password are only
// ever set by handleAdminAdminAdd on its own response: the one-time
// password must not travel in a redirect URL (proxy access logs, browser
// history, Referer).
func (s *Server) renderAdminsPage(w http.ResponseWriter, r *http.Request, ok, bootstrapEmail, bootstrapPassword string) {
	a, sess, _ := adminFromCtx(r)
	list, err := s.adminRepo.List(r.Context())
	if err != nil {
		s.logger.Error("admin.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "admins", map[string]any{
		"Admin":             a,
		"Session":           sess,
		"EvalBanner":        s.cfg.IsEval(),
		"DemoBanner":        s.cfg.IsDemo(),
		"Label":             s.adminLabel,
		"CSRF":              sess.CSRFToken,
		"Items":             list,
		"OK":                ok,
		"Error":             querySlug(r, "err"),
		"BootstrapEmail":    bootstrapEmail,
		"BootstrapPassword": bootstrapPassword,
	})
}

func (s *Server) handleAdminAdminAdd(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/admins?err=demo_readonly", http.StatusSeeOther)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	pwd, err := opaqueToken(15) // 20-char URL-safe random; satisfies ≥ 12.
	if err != nil {
		s.logger.Error("opaqueToken failed", "err", err)
		http.Redirect(w, r, "/admin/admins?err=internal", http.StatusSeeOther)
		return
	}
	created, err := s.adminRepo.Create(r.Context(), email, pwd)
	switch {
	case errors.Is(err, admin.ErrInvalidEmail):
		http.Redirect(w, r, "/admin/admins?err=invalid_email", http.StatusSeeOther)
		return
	case errors.Is(err, admin.ErrAlreadyExists):
		http.Redirect(w, r, "/admin/admins?err=already_exists", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("admin.Create failed", "err", err)
		http.Redirect(w, r, "/admin/admins?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "admin.created", a.Email, created.Email, map[string]any{
		"admin_id": created.ID,
	})
	// Show the freshly minted password once, in this response only (the
	// page is Cache-Control: no-store). The operator hands it to the new
	// admin out-of-band; the setup wizard forces a change at first login.
	s.renderAdminsPage(w, r, "created", created.Email, pwd)
}

func (s *Server) handleAdminAdminToggle(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == a.ID {
		http.Redirect(w, r, "/admin/admins?err=self_disable", http.StatusSeeOther)
		return
	}
	target, err := s.adminRepo.FindByID(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/admins?err=not_found", http.StatusSeeOther)
		return
	}
	next := !target.Disabled
	err = s.adminRepo.SetDisabled(r.Context(), id, next)
	switch {
	case errors.Is(err, admin.ErrLastActiveAdmin):
		http.Redirect(w, r, "/admin/admins?err=last_active", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("admin.SetDisabled failed", "err", err)
		http.Redirect(w, r, "/admin/admins?err=internal", http.StatusSeeOther)
		return
	}
	action := "admin.enabled"
	if next {
		action = "admin.disabled"
	}
	s.auditAppend(r.Context(), action, a.Email, target.Email, map[string]any{
		"admin_id": target.ID,
	})
	http.Redirect(w, r, "/admin/admins?ok=toggled", http.StatusSeeOther)
}

func (s *Server) handleAdminAdminDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == a.ID {
		http.Redirect(w, r, "/admin/admins?err=self_delete", http.StatusSeeOther)
		return
	}
	target, err := s.adminRepo.FindByID(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/admins?err=not_found", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != target.Email {
		http.Redirect(w, r, "/admin/admins?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	err = s.adminRepo.Delete(r.Context(), id)
	switch {
	case errors.Is(err, admin.ErrLastActiveAdmin):
		http.Redirect(w, r, "/admin/admins?err=last_active", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("admin.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/admins?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "admin.deleted", a.Email, target.Email, map[string]any{
		"admin_id": target.ID,
	})
	http.Redirect(w, r, "/admin/admins?ok=deleted", http.StatusSeeOther)
}

// ----- webauthn enrollment -------------------------------------------------

// cookieWebauthnSession holds the opaque ceremony state between
// /admin/security/begin and /admin/security/finish. It is set with
// SameSite=Strict + HttpOnly and lives only for a few minutes.
const cookieWebauthnSession = "sk_webauthn_enroll"

// adminMaxWebauthnSessionBytes caps the size of the cookie we accept back —
// keeps a malicious client from filling memory with arbitrary blobs.
const adminMaxWebauthnSessionBytes = 4 * 1024

func (s *Server) handleAdminSecurity(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	creds, err := s.webauthn.List(r.Context(), a.ID)
	if err != nil {
		s.logger.Error("webauthn.List failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	s.renderAdmin(w, "security", map[string]any{
		"Admin":       a,
		"Session":     sess,
		"EvalBanner":  s.cfg.IsEval(),
		"Label":       s.adminLabel,
		"Credentials": creds,
		"CSRF":        sess.CSRFToken,
		"OK":          querySlug(r, "ok"),
		"Error":       querySlug(r, "err"),
	})
}

// handleAdminWebauthnBegin issues the registration challenge as JSON and
// stashes the opaque ceremony session in a short-lived cookie. The browser
// posts the cookie back along with the credential response in /finish.
func (s *Server) handleAdminWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, ok := s.requireCurrentPassword(r); !ok {
		http.Error(w, "current password incorrect", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("friendly_name"))
	if name == "" {
		http.Error(w, "friendly_name required", http.StatusBadRequest)
		return
	}
	options, session, err := s.webauthn.BeginRegistration(r.Context(),
		webauthnIdentityFromAdmin(a), name)
	if err != nil {
		s.logger.Error("webauthn.BeginRegistration failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieWebauthnSession,
		Value:    base64.RawURLEncoding.EncodeToString(session),
		Path:     "/admin/security",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(5 * time.Minute),
	})
	// The friendly name is replayed back to /finish so the row carries it
	// without us having to persist any extra server-side state.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieWebauthnSession + "_name",
		Value:    base64.RawURLEncoding.EncodeToString([]byte(name)),
		Path:     "/admin/security",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.IsEval(),
		Expires:  time.Now().Add(5 * time.Minute),
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(options)
}

func (s *Server) handleAdminWebauthnFinish(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.checkSessionCSRF(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	sessionCookie, err := r.Cookie(cookieWebauthnSession)
	if err != nil {
		http.Error(w, "no enrollment session", http.StatusBadRequest)
		return
	}
	if len(sessionCookie.Value) > adminMaxWebauthnSessionBytes {
		http.Error(w, "session too large", http.StatusBadRequest)
		return
	}
	sessionBytes, err := base64.RawURLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	nameCookie, err := r.Cookie(cookieWebauthnSession + "_name")
	if err != nil {
		http.Error(w, "no friendly name", http.StatusBadRequest)
		return
	}
	nameBytes, err := base64.RawURLEncoding.DecodeString(nameCookie.Value)
	if err != nil {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	cred, err := s.webauthn.FinishRegistration(r.Context(),
		webauthnIdentityFromAdmin(a), string(nameBytes), sessionBytes, r)
	// Clear the ceremony cookies regardless of outcome.
	for _, n := range []string{cookieWebauthnSession, cookieWebauthnSession + "_name"} {
		http.SetCookie(w, &http.Cookie{
			Name: n, Value: "", Path: "/admin/security",
			Expires: time.Unix(0, 0), MaxAge: -1,
		})
	}
	if err != nil {
		s.logger.Warn("webauthn.FinishRegistration failed", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditAppend(r.Context(), "admin.webauthn_added", a.Email, cred.CredentialID, map[string]any{
		"friendly_name": cred.FriendlyName,
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"credential_id": cred.CredentialID,
		"redirect":      "/admin/security?ok=added",
	})
}

func (s *Server) handleAdminWebauthnRename(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	name := r.FormValue("friendly_name")
	err := s.webauthn.Rename(r.Context(), a.ID, id, name)
	switch {
	case errors.Is(err, webauthn.ErrInvalidName):
		http.Redirect(w, r, "/admin/security?err=invalid_name", http.StatusSeeOther)
		return
	case errors.Is(err, webauthn.ErrNotFound):
		http.Redirect(w, r, "/admin/security?err=not_found", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("webauthn.Rename failed", "err", err)
		http.Redirect(w, r, "/admin/security?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "admin.webauthn_renamed", a.Email, id, map[string]any{
		"friendly_name": name,
	})
	http.Redirect(w, r, "/admin/security?ok=renamed", http.StatusSeeOther)
}

func (s *Server) handleAdminWebauthnDelete(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.webauthn == nil {
		http.Error(w, "webauthn not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if slug, ok := s.requireCurrentPassword(r); !ok {
		http.Redirect(w, r, "/admin/security?err="+slug, http.StatusSeeOther)
		return
	}
	id := chi.URLParam(r, "id")
	confirm := strings.TrimSpace(r.FormValue("confirm"))
	if confirm != id {
		http.Redirect(w, r, "/admin/security?err=confirm_mismatch", http.StatusSeeOther)
		return
	}
	err := s.webauthn.Delete(r.Context(), a.ID, id)
	switch {
	case errors.Is(err, webauthn.ErrNotFound):
		http.Redirect(w, r, "/admin/security?err=not_found", http.StatusSeeOther)
		return
	case err != nil:
		s.logger.Error("webauthn.Delete failed", "err", err)
		http.Redirect(w, r, "/admin/security?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "admin.webauthn_deleted", a.Email, id, nil)
	http.Redirect(w, r, "/admin/security?ok=deleted", http.StatusSeeOther)
}

func webauthnIdentityFromAdmin(a admin.Admin) webauthn.AdminIdentity {
	return webauthn.AdminIdentity{
		ID:          a.ID,
		Email:       a.Email,
		DisplayName: a.Email,
	}
}

const adminSecurityTpl = `{{define "security.html"}}{{template "header" .}}
<main>
<h2>Security keys</h2>
<p>Enrol a FIDO2 / WebAuthn authenticator (security key, platform passkey, …) as an additional second factor.
TOTP remains the active second factor at sign-in; key-based login will land in a follow-up release.</p>
{{ if .OK }}<div class="banner" data-testid="ok">{{ .OK }}</div>{{ end }}
{{ if .Error }}<div class="err" data-testid="error">{{ .Error }}</div>{{ end }}

<h3>Registered keys</h3>
<table data-testid="webauthn-list">
  <thead><tr><th>Friendly name</th><th>Credential ID</th><th>Transports</th><th>Created</th><th>Last used</th><th>Actions</th></tr></thead>
  <tbody>
  {{ range .Credentials }}<tr>
    <td>
      <form method="POST" action="/admin/security/{{ .CredentialID }}/rename" style="display:flex;gap:0.5rem;align-items:center">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <input name="friendly_name" value="{{ .FriendlyName }}" required style="flex:1;min-width:10rem">
        <button type="submit" class="secondary">Rename</button>
      </form>
    </td>
    <td><code style="font-size:0.75rem;word-break:break-all">{{ .CredentialID }}</code></td>
    <td>{{ range $i, $t := .Transports }}{{ if $i }}, {{ end }}<code>{{ $t }}</code>{{ end }}</td>
    <td><code>{{ .CreatedAt }}</code></td>
    <td>{{ if .LastUsedAt }}<code>{{ .LastUsedAt }}</code>{{ else }}—{{ end }}</td>
    <td>
      <form method="POST" action="/admin/security/{{ .CredentialID }}/delete" data-confirm="Delete this credential? This cannot be undone.">
        <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
        <input type="hidden" name="confirm" value="{{ .CredentialID }}">
        <input name="current_password" type="password" required autocomplete="current-password" placeholder="Current password" aria-label="Current password">
        <button type="submit" class="secondary" style="color:#991b1b;border-color:#991b1b">Delete</button>
      </form>
    </td>
  </tr>{{ else }}
  <tr><td colspan="6"><em>No security keys registered yet.</em></td></tr>
  {{ end }}
  </tbody>
</table>

<h3 style="margin-top:2rem">Add a new key</h3>
<form id="webauthn-form" data-testid="webauthn-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="cp-webauthn">Current password</label>
  <input id="cp-webauthn" name="current_password" type="password" required autocomplete="current-password">
  <label for="friendly_name">Friendly name (e.g. "YubiKey 5 NFC")</label>
  <input id="friendly_name" name="friendly_name" required minlength="1" maxlength="64">
  <p style="margin-top:1rem"><button type="submit">Enrol authenticator</button></p>
  <p id="webauthn-status" role="status" style="color:#4b5563;font-size:0.875rem"></p>
</form>

<script nonce="{{ $.CSPNonce }}">
(function () {
  var form = document.getElementById('webauthn-form');
  var status = document.getElementById('webauthn-status');
  if (!form) return;
  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
    status.textContent = 'This browser does not expose WebAuthn — try Chrome, Edge, Firefox or Safari with a recent version.';
    form.querySelector('button[type=submit]').disabled = true;
    return;
  }

  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function decodePublicKey(p) {
    p.challenge = b64uToBuf(p.challenge);
    p.user.id = b64uToBuf(p.user.id);
    if (p.excludeCredentials) {
      p.excludeCredentials = p.excludeCredentials.map(function (c) {
        c.id = b64uToBuf(c.id);
        return c;
      });
    }
    return p;
  }

  form.addEventListener('submit', async function (ev) {
    ev.preventDefault();
    status.textContent = 'Requesting challenge…';
    var fd = new FormData(form);
    try {
      var beginResp = await fetch('/admin/security/begin', {
        method: 'POST',
        headers: { 'X-CSRF-Token': fd.get('csrf_token') },
        body: fd,
        credentials: 'same-origin',
      });
      if (!beginResp.ok) {
        status.textContent = 'Server refused challenge: ' + (await beginResp.text());
        return;
      }
      var opts = await beginResp.json();
      var publicKey = decodePublicKey(opts.publicKey || opts);
      status.textContent = 'Touch your authenticator now…';
      var cred = await navigator.credentials.create({ publicKey: publicKey });
      var payload = {
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
          attestationObject: bufToB64u(cred.response.attestationObject),
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        },
      };
      if (typeof cred.response.getTransports === 'function') {
        payload.response.transports = cred.response.getTransports();
      }
      if (cred.authenticatorAttachment) {
        payload.authenticatorAttachment = cred.authenticatorAttachment;
      }
      var finishResp = await fetch('/admin/security/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': fd.get('csrf_token'),
        },
        body: JSON.stringify(payload),
        credentials: 'same-origin',
      });
      if (!finishResp.ok) {
        status.textContent = 'Enrollment rejected: ' + (await finishResp.text());
        return;
      }
      var out = await finishResp.json();
      window.location.href = out.redirect || '/admin/security?ok=added';
    } catch (e) {
      status.textContent = 'Enrollment failed: ' + (e && e.message ? e.message : e);
    }
  });
})();
</script>
</main>
{{template "footer" .}}{{end}}
`

const adminLoginWebauthnTpl = `{{define "login_webauthn.html"}}{{template "header" .}}
<main>
<h2>Confirm with your security key</h2>
<p>Signed in as <strong>{{ .Email }}</strong>. Touch your registered authenticator to finish the sign-in.</p>
{{ if .Error }}<div class="err" data-testid="error">{{ .Error }}</div>{{ end }}

<p id="webauthn-status" role="status" style="margin:1rem 0;font-size:0.875rem;color:#4b5563">Preparing challenge…</p>

<form id="webauthn-cancel" method="POST" action="/admin/login/webauthn/cancel" style="margin-top:1rem">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <button type="submit" class="secondary">Cancel and use TOTP instead</button>
</form>

<script nonce="{{ $.CSPNonce }}">
(function () {
  var csrf = {{ .CSRF }};
  var status = document.getElementById('webauthn-status');
  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
    status.textContent = 'This browser does not expose WebAuthn — cancel and use your TOTP code instead.';
    return;
  }

  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function decodeAssertion(p) {
    p.challenge = b64uToBuf(p.challenge);
    if (p.allowCredentials) {
      p.allowCredentials = p.allowCredentials.map(function (c) {
        c.id = b64uToBuf(c.id);
        return c;
      });
    }
    return p;
  }

  async function run() {
    try {
      var fd = new FormData();
      fd.set('csrf_token', csrf);
      var begin = await fetch('/admin/login/webauthn/begin', {
        method: 'POST',
        body: fd,
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrf },
      });
      if (!begin.ok) {
        status.textContent = 'Could not start assertion: ' + (await begin.text());
        return;
      }
      var opts = await begin.json();
      var publicKey = decodeAssertion(opts.publicKey || opts);
      status.textContent = 'Touch your authenticator now…';
      var cred = await navigator.credentials.get({ publicKey: publicKey });
      var payload = {
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
          authenticatorData: bufToB64u(cred.response.authenticatorData),
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
          signature: bufToB64u(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
        },
      };
      var finish = await fetch('/admin/login/webauthn/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: JSON.stringify(payload),
        credentials: 'same-origin',
      });
      if (!finish.ok) {
        status.textContent = 'Authenticator rejected: ' + (await finish.text());
        return;
      }
      var out = await finish.json();
      window.location.href = out.redirect || '/admin/dashboard';
    } catch (e) {
      status.textContent = 'WebAuthn failed: ' + (e && e.message ? e.message : e);
    }
  }
  run();
})();
</script>
</main>
{{template "footer" .}}{{end}}
`

const adminAccountTpl = `{{define "account.html"}}{{template "header" .}}
<main>
<h2>My account</h2>
{{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
<p>Signed in as <strong>{{ .Admin.Email }}</strong>.</p>

<h3>Change my email</h3>
<form method="POST" action="/admin/account/email">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="cp-email">Current password</label>
  <input id="cp-email" name="current_password" type="password" required autocomplete="current-password">
  <label for="email">New email</label>
  <input id="email" name="email" type="email" required autocomplete="off" value="{{ .Admin.Email }}">
  <p style="margin-top:1rem"><button type="submit">Update email</button></p>
</form>

<h3 style="margin-top:2rem">Change my password</h3>
<form method="POST" action="/admin/account/password">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="cp-password">Current password</label>
  <input id="cp-password" name="current_password" type="password" required autocomplete="current-password">
  <label for="np">New password (ANSSI B3 — ≥ 16 chars, mixing 3 of lower/upper/digit/symbol)</label>
  <input id="np" name="new_password" type="password" minlength="16" required autocomplete="new-password">
  <label for="np2">Confirm new password</label>
  <input id="np2" name="new_password_confirm" type="password" minlength="16" required autocomplete="new-password">
  <p style="margin-top:1rem"><button type="submit">Update password</button></p>
</form>

<p style="margin-top:2rem;color:var(--stone);font-size:0.875rem">
  Enrolling additional FIDO2 keys is done from <a href="/admin/security">Security keys</a>;
  managing other operator accounts is on the <a href="/admin/admins">Admins</a> page.
</p>
</main>
{{template "footer" .}}{{end}}
`

const adminAdminsTpl = `{{define "admins.html"}}{{template "header" .}}
<main>
<h2>Administrators</h2>
{{ if .Error }}<div class="err" data-testid="error">{{ .Error }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}
{{ if .BootstrapPassword }}
<div style="background:#FBF7EE;border:1px solid var(--gold);border-radius:2px;padding:0.75rem 1rem;margin-bottom:1rem" data-testid="bootstrap-banner">
  <p style="margin:0 0 0.5rem"><strong>Bootstrap password for <code>{{ .BootstrapEmail }}</code> — shown once.</strong></p>
  <p style="margin:0"><code data-testid="bootstrap-password">{{ .BootstrapPassword }}</code></p>
  <p style="margin:0.5rem 0 0;font-size:0.875rem;color:var(--stone)">Copy it now and share it through a trusted channel. The new admin will be forced to change it and enrol TOTP on first login.</p>
</div>
{{ end }}

<table data-testid="admins-table">
  <thead><tr><th>Email</th><th>Status</th><th>Last login</th><th>Created</th><th>Actions</th></tr></thead>
  <tbody>
  {{ range .Items }}<tr>
    <td><code>{{ .Email }}</code>{{ if eq .ID $.Admin.ID }} <small>(you)</small>{{ end }}</td>
    <td>
      {{ if .Disabled }}<span style="color:#991b1b">disabled</span>
      {{ else if .ForceTOTPEnroll }}<span style="color:var(--stone)">pending setup</span>
      {{ else }}<strong style="color:#166534">active</strong>{{ end }}
    </td>
    <td>{{ if .LastLoginAt }}<code>{{ .LastLoginAt.Format "2006-01-02 15:04 UTC" }}</code>{{ else }}—{{ end }}</td>
    <td>—</td>
    <td>
      {{ if ne .ID $.Admin.ID }}
        <form method="POST" action="/admin/admins/{{ .ID }}/toggle" style="display:inline">
          <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
          <button type="submit" class="secondary">{{ if .Disabled }}Re-enable{{ else }}Disable{{ end }}</button>
        </form>
        <details style="display:inline-block;margin-left:0.5rem"><summary>Delete</summary>
          <form method="POST" action="/admin/admins/{{ .ID }}/delete" style="margin-top:0.5rem">
            <input type="hidden" name="csrf_token" value="{{ $.CSRF }}">
            <label>Type <code>{{ .Email }}</code> to confirm:</label>
            <input name="confirm" type="text" required style="width:auto;display:inline-block">
            <button type="submit" style="background:#991b1b;border-color:#991b1b">Delete</button>
          </form>
        </details>
      {{ else }}
        <small style="color:var(--stone)">cannot disable yourself</small>
      {{ end }}
    </td>
  </tr>{{ else }}<tr><td colspan="5"><em>No admins on file.</em></td></tr>{{ end }}
  </tbody>
</table>

<h3 style="margin-top:2rem">Add an administrator</h3>
<p style="font-size:0.875rem;color:var(--stone)">A random 20-character bootstrap password is generated server-side and revealed once on the next page. The new admin is forced into the standard setup wizard (password change + TOTP enrol) on first login.</p>
<form method="POST" action="/admin/admins/add" data-testid="add-admin-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="add-email">Email</label>
  <input id="add-email" name="email" type="email" required autocomplete="off">
  <p style="margin-top:1rem"><button type="submit">Create admin</button></p>
</form>
</main>
{{template "footer" .}}{{end}}
`

// ----- SMTP admin surface ---------------------------------------------------

func (s *Server) handleAdminSMTP(w http.ResponseWriter, r *http.Request) {
	a, sess, _ := adminFromCtx(r)
	if s.smtpConfig == nil {
		http.Error(w, "smtp config not wired", http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.smtpConfig.Get(r.Context())
	configured := true
	if err != nil {
		if errors.Is(err, smtpconfig.ErrNotConfigured) {
			configured = false
			cfg = smtpconfig.Config{Port: 587, TLSMode: "auto", TimeoutSeconds: 30}
		} else {
			s.logger.Error("smtpconfig.Get failed", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
	}
	hasPassword := cfg.Password != ""
	cfg.Password = ""
	s.renderAdmin(w, "smtp", map[string]any{
		"Admin":       a,
		"Session":     sess,
		"EvalBanner":  s.cfg.IsEval(),
		"DemoBanner":  s.cfg.IsDemo(),
		"Label":       s.adminLabel,
		"CSRF":        sess.CSRFToken,
		"Config":      cfg,
		"Configured":  configured,
		"HasPassword": hasPassword,
		"SenderName":  s.sender.Name(),
		"OK":          querySlug(r, "ok"),
		"Error":       querySlug(r, "err"),
		"Details":     r.URL.Query().Get("details"),
	})
}

func (s *Server) handleAdminSMTPSave(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if s.smtpConfig == nil {
		http.Error(w, "smtp config not wired", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/smtp?err=demo_readonly", http.StatusSeeOther)
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	timeout, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("timeout_seconds")))
	in := smtpconfig.UpdateInputs{
		Host:           strings.TrimSpace(r.FormValue("host")),
		Port:           port,
		Username:       strings.TrimSpace(r.FormValue("username")),
		Password:       r.FormValue("password"),
		KeepPassword:   r.FormValue("keep_password") == "on",
		FromAddr:       strings.TrimSpace(r.FormValue("from_addr")),
		TLSMode:        strings.TrimSpace(r.FormValue("tls_mode")),
		ServerName:     strings.TrimSpace(r.FormValue("server_name")),
		InsecureTLS:    r.FormValue("insecure_tls") == "on",
		TimeoutSeconds: timeout,
	}
	if err := s.smtpConfig.Update(r.Context(), in, &a.ID); err != nil {
		s.logger.Error("smtpconfig.Update failed", "err", err)
		http.Redirect(w, r,
			"/admin/smtp?err=internal&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	if err := s.RebuildSMTPSender(r.Context()); err != nil {
		s.logger.Error("RebuildSMTPSender failed", "err", err)
		s.auditAppend(r.Context(), "smtp.save_failed", a.Email, in.Host, map[string]any{
			"error": err.Error(),
		})
		http.Redirect(w, r,
			"/admin/smtp?err=relay_invalid&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "smtp.updated", a.Email, in.Host, map[string]any{
		"port": in.Port, "tls": in.TLSMode,
	})
	http.Redirect(w, r, "/admin/smtp?ok=saved", http.StatusSeeOther)
}

func (s *Server) handleAdminSMTPClear(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.IsDemo() {
		http.Redirect(w, r, "/admin/smtp?err=demo_readonly", http.StatusSeeOther)
		return
	}
	if err := s.smtpConfig.Update(r.Context(), smtpconfig.UpdateInputs{}, &a.ID); err != nil {
		http.Redirect(w, r, "/admin/smtp?err=internal", http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "smtp.cleared", a.Email, "", nil)
	http.Redirect(w, r, "/admin/smtp?ok=cleared", http.StatusSeeOther)
}

func (s *Server) handleAdminSMTPTest(w http.ResponseWriter, r *http.Request) {
	a, _, _ := adminFromCtx(r)
	if err := r.ParseForm(); err != nil || !s.checkSessionCSRF(r) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	to := strings.TrimSpace(r.FormValue("test_to"))
	if to == "" {
		http.Redirect(w, r, "/admin/smtp?err=test_no_recipient", http.StatusSeeOther)
		return
	}
	msg, err := mail.Assemble(mail.AssembleInputs{
		To:             to,
		InstanceDomain: s.cfg.InstanceDomain,
		Subject:        "SealKeeper SMTP test",
		Text:           "If you can read this, the SealKeeper relay configuration is working.\n\n— SealKeeper admin SMTP test",
		HTML:           "<p>If you can read this, the SealKeeper relay configuration is working.</p><p style=\"color:#7A7670;font-size:0.875rem\">— SealKeeper admin SMTP test</p>",
	})
	if err != nil {
		http.Redirect(w, r,
			"/admin/smtp?err=test_assemble&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.sender.Send(ctx, msg); err != nil {
		s.logger.Warn("smtp test failed", "to", to, "err", err)
		s.auditAppend(r.Context(), "smtp.test_failed", a.Email, to, map[string]any{
			"transport": s.sender.Name(),
			"error":     err.Error(),
		})
		http.Redirect(w, r,
			"/admin/smtp?err=test_failed&details="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	s.auditAppend(r.Context(), "smtp.test_sent", a.Email, to, map[string]any{
		"transport": s.sender.Name(),
	})
	http.Redirect(w, r, "/admin/smtp?ok=test_sent", http.StatusSeeOther)
}

const adminSMTPTpl = `{{define "smtp.html"}}{{template "header" .}}
<main>
<h2>SMTP relay</h2>
{{ if .Error }}<div class="err" data-testid="error">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}
{{ if .OK }}<div style="background:#dcfce7;color:#166534;padding:0.5rem 1rem;border-radius:4px;margin-bottom:1rem">{{ .OK }}</div>{{ end }}

<p>Active sender: <code data-testid="sender-name">{{ .SenderName }}</code>{{ if not .Configured }} <em>(env-wired — no DB override saved yet)</em>{{ end }}.</p>

<form method="POST" action="/admin/smtp/save" data-testid="smtp-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="host">Host</label>
  <input id="host" name="host" type="text" value="{{ .Config.Host }}" placeholder="smtp.example.eu" autocomplete="off">

  <label for="port">Port</label>
  <input id="port" name="port" type="number" min="1" max="65535" value="{{ if .Config.Port }}{{ .Config.Port }}{{ else }}587{{ end }}">

  <label for="username">Username</label>
  <input id="username" name="username" type="text" value="{{ .Config.Username }}" autocomplete="off">

  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" placeholder="{{ if .HasPassword }}(unchanged){{ else }}(none){{ end }}">
  {{ if .HasPassword }}
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.5rem">
    <input type="checkbox" name="keep_password" checked> Keep current password
  </label>
  {{ end }}

  <label for="from_addr">From address</label>
  <input id="from_addr" name="from_addr" type="email" value="{{ .Config.FromAddr }}" placeholder="seals@example.eu">

  <label for="tls_mode">TLS mode</label>
  <select id="tls_mode" name="tls_mode">
    <option value="auto" {{ if eq .Config.TLSMode "auto" }}selected{{ end }}>auto — STARTTLS required (plaintext only to a loopback relay)</option>
    <option value="starttls" {{ if eq .Config.TLSMode "starttls" }}selected{{ end }}>starttls — require STARTTLS</option>
    <option value="implicit" {{ if eq .Config.TLSMode "implicit" }}selected{{ end }}>implicit — TLS at TCP layer (e.g. :465)</option>
    <option value="disable" {{ if eq .Config.TLSMode "disable" }}selected{{ end }}>disable — plaintext (lab / capture only)</option>
  </select>

  <label for="server_name">TLS server name (optional override of SNI / verify hostname)</label>
  <input id="server_name" name="server_name" type="text" value="{{ .Config.ServerName }}" autocomplete="off">

  <label for="timeout_seconds">Timeout (seconds)</label>
  <input id="timeout_seconds" name="timeout_seconds" type="number" min="1" max="120" value="{{ if .Config.TimeoutSeconds }}{{ .Config.TimeoutSeconds }}{{ else }}30{{ end }}">

  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="insecure_tls" {{ if .Config.InsecureTLS }}checked{{ end }}> Accept any TLS certificate (only for relays with private CA)
  </label>

  <p style="margin-top:1rem"><button type="submit">Save and rebuild sender</button></p>
</form>

<h3 style="margin-top:2rem">Send a test message</h3>
<p style="color:var(--stone); font-size:0.875rem">Uses the currently active sender — save first if you have just edited the form. In eval / demo mode the test mail lands in <a href="/admin/captured-mail">Captured mail</a> rather than going to the relay.</p>
<form method="POST" action="/admin/smtp/test" style="display:flex;gap:0.5rem;align-items:flex-end;flex-wrap:wrap">
  <div style="flex:1;min-width:18rem">
    <label for="test_to">Recipient</label>
    <input id="test_to" name="test_to" type="email" required placeholder="you@example.eu">
  </div>
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <button type="submit" class="secondary">Send test</button>
</form>

{{ if .Configured }}
<h3 style="margin-top:2rem">Clear the override</h3>
<p style="color:var(--stone); font-size:0.875rem">Removes the DB row and brings back the env-wired sender. Useful when migrating from compose env vars to admin-managed config (or vice versa).</p>
<form method="POST" action="/admin/smtp/clear">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <button type="submit" class="secondary" style="color:#991b1b;border-color:#991b1b">Clear SMTP override</button>
</form>
{{ end }}
</main>
{{template "footer" .}}{{end}}
`

const adminPolicyEditTpl = `{{define "policy_edit.html"}}{{template "header" .}}
<main>
<h2>Edit policy — {{ .Policy.Name }}</h2>
<p><a href="/admin/policies">← back to policies</a></p>
{{ if .Error }}<div class="err">{{ .Error }}{{ if .Details }} — <code>{{ .Details }}</code>{{ end }}</div>{{ end }}

<form method="POST" action="/admin/policies/{{ .Policy.ID }}/save" data-testid="edit-policy-form">
  <input type="hidden" name="csrf_token" value="{{ .CSRF }}">
  <label for="domain_id">Domain</label>
  <select id="domain_id" name="domain_id" required>
    {{ $current := .Policy.DomainID }}
    {{ range .Domains }}<option value="{{ .ID }}" {{ if eq .ID $current }}selected{{ end }}>{{ .Name }}</option>{{ end }}
  </select>
  <label for="anssi_level">ANSSI level</label>
  <select id="anssi_level" name="anssi_level" required>
    <option value="B1" {{ if eq (printf "%s" .Policy.ANSSILevel) "B1" }}selected{{ end }}>B1 — default (every user not elevated)</option>
    <option value="B2" {{ if eq (printf "%s" .Policy.ANSSILevel) "B2" }}selected{{ end }}>B2 — elevated managers</option>
    <option value="B3" {{ if eq (printf "%s" .Policy.ANSSILevel) "B3" }}selected{{ end }}>B3 — elevated system admins</option>
  </select>
  <label for="name">Name</label>
  <input id="name" name="name" type="text" required value="{{ .Policy.Name }}">
  <label for="generator">Generator</label>
  <select id="generator" name="generator" required>
    <option value="G1" {{ if eq (printf "%s" .Policy.Generator) "G1" }}selected{{ end }}>G1 — citation + transforms (B1 target)</option>
    <option value="G2" {{ if eq (printf "%s" .Policy.Generator) "G2" }}selected{{ end }}>G2 — Diceware (B2 target)</option>
    <option value="G3" {{ if eq (printf "%s" .Policy.Generator) "G3" }}selected{{ end }}>G3 — random alphanumeric (B3 target)</option>
  </select>
  <label for="params_json">Parameters (JSON)</label>
  <textarea id="params_json" name="params_json" rows="10" style="width:100%;font-family:var(--font-mono);padding:0.5rem">{{ .ParamsJSON }}</textarea>
  <small style="display:block;color:var(--stone);margin-top:0.25rem">PolicyDescriptor parameters per module A. Saved as-is (validated for JSON-ness).</small>

  <fieldset id="entropy-preview" data-testid="entropy-preview"
    style="margin-top:1rem;padding:0.75rem 1rem;border:1px solid var(--rule);border-radius:2px;background:var(--bg-elev)">
    <legend style="padding:0 0.5rem;font-weight:600">Entropy preview</legend>
    <p style="margin:0.25rem 0;font-family:var(--font-mono)">
      min: <strong data-testid="entropy-min">—</strong> bits
      &nbsp;·&nbsp; expected: <strong data-testid="entropy-expected">—</strong> bits
      &nbsp;·&nbsp; max: <strong data-testid="entropy-max">—</strong> bits
    </p>
    <p style="margin:0.5rem 0">
      <span data-testid="entropy-badge-B1" class="ent-badge">B1 ≥ 50</span>
      <span data-testid="entropy-badge-B2" class="ent-badge">B2 ≥ 80</span>
      <span data-testid="entropy-badge-B3" class="ent-badge">B3 ≥ 100</span>
    </p>
    <details style="margin:0.4rem 0 0">
      <summary style="cursor:pointer;color:var(--stone);font-size:0.85rem">Breakdown — how the bits add up</summary>
      <table data-testid="entropy-breakdown" style="margin-top:0.4rem;font-size:0.85rem">
        <thead><tr><th style="text-align:left">Component</th><th style="text-align:right">bits</th></tr></thead>
        <tbody></tbody>
      </table>
    </details>
    <p data-testid="entropy-mismatch" style="margin:0.4rem 0 0;color:var(--cardinal);font-size:0.85rem;display:none"></p>
    <p data-testid="entropy-warning" style="margin:0.25rem 0 0;color:var(--cardinal);font-size:0.875rem;display:none"></p>
    <p data-testid="entropy-status" style="margin:0.25rem 0 0;color:var(--stone);font-size:0.875rem">Loading generator bundle…</p>
  </fieldset>
  <style>
    .ent-badge { display:inline-block; padding:0.15rem 0.5rem; margin-right:0.35rem; border-radius:3px; font-size:0.85rem; border:1px solid transparent }
    .ent-badge.met { background:#dcfce7; color:#166534; border-color:#86efac }
    .ent-badge.miss { background:#fee2e2; color:#991b1b; border-color:#fca5a5 }
  </style>

  <label for="proposal_count">Proposals shown</label>
  <input id="proposal_count" name="proposal_count" type="number" value="{{ .Policy.ProposalCount }}" min="1" max="20">
  <label for="regenerate_limit">Re-generate limit</label>
  <input id="regenerate_limit" name="regenerate_limit" type="number" value="{{ .Policy.RegenerateLimit }}" min="0" max="10">
  <label for="session_ttl_seconds">Session TTL (seconds)</label>
  <input id="session_ttl_seconds" name="session_ttl_seconds" type="number" value="{{ .Policy.SessionTTLSeconds }}" min="60" max="86400">
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.75rem">
    <input type="checkbox" name="notify_on_consult" {{ if .Policy.NotifyOnConsult }}checked{{ end }}> Email notification post-consultation
  </label><br>
  <label style="font-weight:400;display:inline-flex;align-items:center;gap:0.5rem;margin-top:0.25rem">
    <input type="checkbox" name="active" {{ if .Policy.Active }}checked{{ end }}> Active
  </label>
  <p style="margin-top:1rem"><button type="submit">Save changes</button></p>
</form>

<script src="/static/sealkeeper-generation.umd.js" defer></script>
<script nonce="{{ $.CSPNonce }}">
(function () {
  var form = document.querySelector('[data-testid="edit-policy-form"]');
  var preview = document.getElementById('entropy-preview');
  if (!form || !preview) return;

  var status = preview.querySelector('[data-testid="entropy-status"]');
  var warn = preview.querySelector('[data-testid="entropy-warning"]');
  var els = {
    min: preview.querySelector('[data-testid="entropy-min"]'),
    expected: preview.querySelector('[data-testid="entropy-expected"]'),
    max: preview.querySelector('[data-testid="entropy-max"]'),
    B1: preview.querySelector('[data-testid="entropy-badge-B1"]'),
    B2: preview.querySelector('[data-testid="entropy-badge-B2"]'),
    B3: preview.querySelector('[data-testid="entropy-badge-B3"]'),
  };
  var generatorSel = form.querySelector('#generator');
  var paramsTA = form.querySelector('#params_json');
  var anssiSel = form.querySelector('#anssi_level');
  var breakdownBody = preview.querySelector('[data-testid="entropy-breakdown"] tbody');
  var mismatch = preview.querySelector('[data-testid="entropy-mismatch"]');

  function paramsMismatch(gen, params) {
    if (!params || typeof params !== 'object') return '';
    var hasWords = typeof params.numberOfWords === 'number' && params.numberOfWords > 0;
    var hasLibrary = Array.isArray(params.library) && params.library.length > 0;
    var hasLength = typeof params.length === 'number' && params.length > 0;
    if (gen === 'G1' && hasWords) return 'numberOfWords is ignored by G1 (one citation only). Switch to G2 if you want N independent word picks.';
    if ((gen === 'G1' || gen === 'G2') && !hasLibrary) return gen + ' needs an inline "library" array; without it the reveal page refuses to generate.';
    if (gen === 'G3' && (hasWords || hasLibrary)) return 'G3 ignores library / numberOfWords (random alphanumeric draw); only length (and excludeAmbiguous) matter.';
    if (gen === 'G3' && !hasLength) return 'G3 expects a "length" parameter.';
    return '';
  }

  function calc() {
    var fn = window.SealKeeper && window.SealKeeper.Generation && window.SealKeeper.Generation.calculateEntropy;
    if (!fn) { status.textContent = 'Generator bundle not loaded — entropy preview unavailable.'; return; }
    var parsed;
    try { parsed = paramsTA.value.trim() ? JSON.parse(paramsTA.value) : {}; }
    catch (e) {
      status.textContent = 'Parameters JSON invalid: ' + e.message;
      els.min.textContent = els.expected.textContent = els.max.textContent = '—';
      [els.B1, els.B2, els.B3].forEach(function (b) { b.className = 'ent-badge'; });
      warn.style.display = 'none';
      mismatch.style.display = 'none';
      if (breakdownBody) breakdownBody.innerHTML = '';
      return;
    }
    var generator = generatorSel.value;
    var policy = { generator: generator, parameters: parsed };
    var report;
    try { report = fn(policy); }
    catch (e) {
      status.textContent = 'Cannot compute: ' + e.message;
      els.min.textContent = els.expected.textContent = els.max.textContent = '—';
      [els.B1, els.B2, els.B3].forEach(function (b) { b.className = 'ent-badge'; });
      warn.style.display = 'none';
      mismatch.style.display = 'none';
      if (breakdownBody) breakdownBody.innerHTML = '';
      return;
    }
    status.textContent = 'Live preview · same calculator the user bundle uses.';
    els.min.textContent = report.minBits.toFixed(1);
    els.expected.textContent = report.expectedBits.toFixed(1);
    els.max.textContent = report.maxBits.toFixed(1);
    if (breakdownBody) {
      breakdownBody.innerHTML = (report.breakdown || []).map(function (b) {
        return '<tr><td><code>' + b.component + '</code></td><td style="text-align:right;font-family:var(--font-mono,monospace)">' +
          b.bits.toFixed(1) + '</td></tr>';
      }).join('');
    }
    var levels = report.anssiLevels || {};
    [['B1', 50], ['B2', 80], ['B3', 100]].forEach(function (pair) {
      var key = pair[0]; var met = levels[key];
      els[key].className = 'ent-badge ' + (met ? 'met' : 'miss');
      els[key].textContent = (met ? '✓ ' : '✗ ') + key + ' ≥ ' + pair[1];
    });
    var target = anssiSel.value;
    var thresholds = { B1: 50, B2: 80, B3: 100 };
    if (target in thresholds && report.expectedBits < thresholds[target]) {
      warn.style.display = '';
      warn.textContent = 'Expected entropy is below the configured ' + target +
        ' threshold (' + thresholds[target] + ' bits). You can save anyway — SealKeeper advises, the admin decides.';
    } else {
      warn.style.display = 'none';
    }
    var msg = paramsMismatch(generator, parsed);
    if (msg) { mismatch.style.display = ''; mismatch.textContent = '⚠ ' + msg; }
    else { mismatch.style.display = 'none'; }
  }

  var timer = null;
  function schedule() { if (timer) clearTimeout(timer); timer = setTimeout(calc, 120); }
  form.addEventListener('input', schedule);
  form.addEventListener('change', schedule);
  function tryFirst(n) {
    if (window.SealKeeper && window.SealKeeper.Generation) { calc(); return; }
    if (n <= 0) { status.textContent = 'Generator bundle did not load.'; return; }
    setTimeout(function () { tryFirst(n - 1); }, 100);
  }
  tryFirst(20);
})();
</script>
</main>
{{template "footer" .}}{{end}}
`

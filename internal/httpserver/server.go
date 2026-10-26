// Package httpserver wires the public HTTP surface for SealKeeper.
//
// Routes wired in this skeleton:
//
//	GET  /healthz                 — liveness, no dependencies
//	GET  /readyz                  — readiness aggregate (DB ping etc.)
//	GET  /metrics                 — Prometheus exposition (optional bearer)
//	GET  /version                 — build metadata
//	GET  /                        — landing page (HTML stub)
//	POST /api/v1/request          — issue a reveal token + capture/send mail
//	GET  /api/v1/policy           — public default policy (?token= refused)
//	POST /api/v1/policy           — single-use consumption, token in the
//	                                JSON body, never the URL (FR-B.36)
//	GET  /reveal/{token}          — reveal page HTML (loads UMD bundle)
//	GET  /static/*                — JS bundle + assets (config.WebDir)
//	GET  /__captured_mail         — eval mail queue; demo: caller's own mail
package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/integrations"
	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailcapture"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/policy"
	"github.com/sched75/sealkeeper/internal/ratelimit"
	"github.com/sched75/sealkeeper/internal/readiness"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
	"github.com/sched75/sealkeeper/internal/tokens"
	"github.com/sched75/sealkeeper/internal/version"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

// pseudonymKey derives the audit pseudonymisation key from the master
// secret, domain-separated from every other use of it.
func pseudonymKey(masterSecret string) []byte {
	sum := sha256.Sum256([]byte("sealkeeper-pseudonym:" + masterSecret))
	return sum[:]
}

// ceremonyKey derives the WebAuthn ceremony MAC key from the master
// secret, domain-separated from every other use of it.
func ceremonyKey(masterSecret string) []byte {
	sum := sha256.Sum256([]byte("sealkeeper-webauthn-ceremony:" + masterSecret))
	return sum[:]
}

// adminLoginPerIPWindow is the number of admin login attempts one client IP
// may make per 15 minutes.
const adminLoginPerIPWindow = 20

// tokenLookupPerIPWindow is the number of reveal-token lookups (GET
// /reveal/{token} and /api/v1/policy?token=) one client IP may make per 15
// minutes. Both answer unknown / expired / consumed differently, so they
// are a token-state oracle; an honest reveal costs two lookups.
const tokenLookupPerIPWindow = 60

// Server is the HTTP service.
type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	readyz   *readiness.Set
	mail     *mailcapture.Store
	tokens   *tokens.Repo // optional — nil when storage is unavailable
	audit    *audit.Repo  // optional — nil when storage is unavailable
	limiter  ratelimit.Composite
	reqCount *prometheus.CounterVec
	reqDur   *prometheus.HistogramVec
	rateHits *prometheus.CounterVec
	registry *prometheus.Registry

	revealTpl  *htmltemplate.Template
	landingTpl *htmltemplate.Template

	adminRepo  *admin.Repo
	adminLabel string
	adminTpl   *htmltemplate.Template

	domains      *domains.Repo
	policies     *policies.Repo
	elevations   *elevations.Repo
	libraries    *libraries.Repo
	mailTpls     *mailtemplates.Repo
	integrations *integrations.Repo
	dispatcher   *integrations.Dispatcher
	branding     *branding.Repo
	webauthn     *webauthn.Repo
	smtpConfig   *smtpconfig.Repo
	loginPending *loginPendingStore

	// loginLimiter caps POST /admin/login per client IP. The per-account
	// lockout alone lets one IP spray many accounts, and lock them all.
	loginLimiter *ratelimit.Limiter

	// tokenLimiter caps reveal-token lookups per client IP (see
	// tokenLookupPerIPWindow).
	tokenLimiter *ratelimit.Limiter

	// pseudonymKey keys hashShort (derived from the master secret).
	pseudonymKey []byte

	// ceremonyKey authenticates the WebAuthn ceremony state the browser
	// carries between /begin and /finish (see sealCeremony).
	ceremonyKey []byte

	// trustedProxies gates X-Forwarded-For (FR-H.42). Empty = never trust.
	trustedProxies []netip.Prefix

	// Constant-latency POST /api/v1/request (FR-B.13, see requestmail.go).
	requestFloor time.Duration
	mailSlots    chan struct{}
	mailQueue    chan struct{}
	mailWG       sync.WaitGroup

	// sender is never nil — capture in eval, noop otherwise. /admin/smtp
	// swaps it while requests read it: go through currentSender /
	// storeSender. smtpMu serialises RebuildSMTPSender so the last
	// rebuild always installs the latest saved relay.
	sender atomic.Pointer[senderRef]
	smtpMu sync.Mutex
}

// New builds an HTTP server with the given configuration.
func New(cfg config.Config, logger *slog.Logger) *Server {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	reqCount := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sealkeeper_requests_total",
		Help: "Total HTTP requests handled, partitioned by route and status.",
	}, []string{"route", "status"})
	reqDur := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sealkeeper_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
	rateHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sealkeeper_rate_limit_hits_total",
		Help: "Number of rate-limited public requests (POST /api/v1/request by email/ip, reveal-token lookups by token_lookup).",
	}, []string{"dimension"})
	reg.MustRegister(reqCount, reqDur, rateHits)

	// FR-H.79: a public demo enforces aggressive limits (1 / IP / hour)
	// regardless of what the operator put in config — they're load
	// protection AND a hint that the surface is hostile.
	ipLimit := cfg.RateLimitIPPerHour
	emailLimit := cfg.RateLimitEmailPerHour
	if cfg.IsDemo() {
		ipLimit = 1
		emailLimit = 1
	}
	limiter := ratelimit.Composite{
		Email: ratelimit.New(emailLimit, time.Hour),
		IP:    ratelimit.New(ipLimit, time.Hour),
	}

	mailStore := mailcapture.NewStore(100)
	// Default sender: in eval mode mails are captured for /__captured_mail;
	// in production with no SMTP wired we fall back to a no-op (the
	// SetSender call from main.go will replace this when SMTP is configured).
	// FR-H.79: demo mode forces capture too — real SMTP would let a
	// visitor exfiltrate links to arbitrary inboxes.
	var defaultSender mailer.Sender = mailer.NopSender{}
	if cfg.IsEval() || cfg.IsDemo() {
		defaultSender = &mailer.CaptureSender{Store: mailStore}
	}

	// config.Load already rejected malformed entries; a Config built by
	// hand (tests) with a bad CIDR degrades to "trust nobody".
	trusted, err := cfg.TrustedProxyPrefixes()
	if err != nil {
		logger.Warn("ignoring invalid SK_TRUSTED_PROXY_CIDRS; X-Forwarded-For will not be trusted", "err", err)
		trusted = nil
	}

	s := &Server{
		trustedProxies: trusted,
		pseudonymKey:   pseudonymKey(cfg.MasterSecret),
		ceremonyKey:    ceremonyKey(cfg.MasterSecret),
		loginLimiter:   ratelimit.New(adminLoginPerIPWindow, 15*time.Minute),
		tokenLimiter:   ratelimit.New(tokenLookupPerIPWindow, 15*time.Minute),
		cfg:            cfg,
		logger:         logger,
		readyz:         readiness.New(),
		mail:           mailStore,
		limiter:        limiter,
		reqCount:       reqCount,
		reqDur:         reqDur,
		rateHits:       rateHits,
		registry:       reg,
		revealTpl:      htmltemplate.Must(htmltemplate.New("reveal").Parse(revealHTML)),
		landingTpl:     htmltemplate.Must(htmltemplate.New("landing").Parse(landingHTML)),
		adminLabel:     cfg.InstanceDomain,
		adminTpl:       adminTpls,
		loginPending:   newLoginPendingStore(5 * time.Minute),
		requestFloor:   requestLatencyFloor,
		mailSlots:      make(chan struct{}, mailWorkers),
		mailQueue:      make(chan struct{}, mailQueueDepth),
	}
	s.storeSender(defaultSender)
	return s
}

// senderRef boxes the mailer.Sender interface for atomic.Pointer.
type senderRef struct{ mailer.Sender }

// currentSender returns the active mail sender. Callers that use it more
// than once (Send then Name) take one snapshot so a concurrent swap
// cannot split them across two transports.
func (s *Server) currentSender() mailer.Sender { return s.sender.Load().Sender }

func (s *Server) storeSender(sender mailer.Sender) { s.sender.Store(&senderRef{sender}) }

// MailStore returns the underlying mail capture store (eval mode).
func (s *Server) MailStore() *mailcapture.Store { return s.mail }

// Readiness returns the underlying readiness set.
func (s *Server) Readiness() *readiness.Set { return s.readyz }

// SetTokens binds the token repository. When nil, /api/v1/request returns a
// 503 — useful for tests that exercise the static surface only.
func (s *Server) SetTokens(repo *tokens.Repo) { s.tokens = repo }

// SetAudit binds the audit log writer. When nil, audit events are dropped
// (logged via slog instead) — useful for skeleton tests.
func (s *Server) SetAudit(repo *audit.Repo) { s.audit = repo }

// SetSender overrides the mail sender. When called with a CaptureSender that
// shares the server's MailStore the /__captured_mail endpoint stays in sync.
// FR-H.79: a public demo refuses any real-SMTP override — main.go calls
// this with the configured SMTP sender after wiring, and we silently keep
// the capture sender in place.
func (s *Server) SetSender(sender mailer.Sender) {
	if sender == nil {
		return
	}
	if s.cfg.IsDemo() {
		if _, ok := sender.(*mailer.CaptureSender); !ok {
			s.logger.Warn("ignoring SetSender call in demo mode — capture sender stays active")
			return
		}
	}
	s.storeSender(sender)
}

// SetDomains binds the allowlist repo. When nil, every domain is accepted —
// matching the zero-config eval behaviour.
func (s *Server) SetDomains(repo *domains.Repo) { s.domains = repo }

// SetPolicies binds the policies + elevations repos used to resolve a
// request to a concrete PolicyDescriptor. When both repos are nil the
// server keeps returning policy.Default() — handy for the zero-config eval
// pitch and the public smoke tests.
func (s *Server) SetPolicies(p *policies.Repo, e *elevations.Repo) {
	s.policies = p
	s.elevations = e
}

// SetLibraries binds the libraries repo. /admin/libraries returns 503 when
// unset.
func (s *Server) SetLibraries(repo *libraries.Repo) { s.libraries = repo }

// SetMailTemplates binds the editable mail-template repo. When nil, the
// request handler falls back to the legacy mail.BuildReveal path with its
// hardcoded French template.
func (s *Server) SetMailTemplates(repo *mailtemplates.Repo) { s.mailTpls = repo }

// SetIntegrations binds the outbound-sink repo + dispatcher. The
// dispatcher is responsible for fanning audit events out to enabled
// integrations; auditAppend pushes to it after a successful audit write.
func (s *Server) SetIntegrations(repo *integrations.Repo, disp *integrations.Dispatcher) {
	s.integrations = repo
	s.dispatcher = disp
	if disp != nil && s.registry != nil {
		// Delivered / failed / dropped-per-lane counters (SK-19).
		_ = s.registry.Register(disp)
	}
}

// SetBranding binds the instance-identity repo. When nil the public
// surface falls back to the SealKeeper heraldic defaults (cardinal
// red + gold accents on parchment cream — see /design).
func (s *Server) SetBranding(repo *branding.Repo) { s.branding = repo }

// SetWebauthn binds the WebAuthn enrollment repo. When nil the
// /admin/security page returns 503 — the rest of the admin surface keeps
// working so an operator without WebAuthn config can still manage the
// instance.
func (s *Server) SetWebauthn(repo *webauthn.Repo) { s.webauthn = repo }

// SetSMTPConfig binds the DB-backed SMTP override repo. When non-nil
// the server reads from it at boot and on every save from
// /admin/smtp, swapping the active sender if the row points at a
// valid relay.
func (s *Server) SetSMTPConfig(repo *smtpconfig.Repo) { s.smtpConfig = repo }

// RebuildSMTPSender refreshes the active mail sender from the DB
// override. When the override row is empty (no host saved) the
// existing env-wired sender stays put. Demo mode short-circuits to
// keep the capture sender pinned regardless of what's saved.
func (s *Server) RebuildSMTPSender(ctx context.Context) error {
	if s.smtpConfig == nil {
		return nil
	}
	if s.cfg.IsDemo() {
		return nil
	}
	s.smtpMu.Lock()
	defer s.smtpMu.Unlock()
	cfg, err := s.smtpConfig.Get(ctx)
	if errors.Is(err, smtpconfig.ErrNotConfigured) {
		return nil
	}
	if err != nil {
		return err
	}
	mc := mailer.SMTPConfig{
		Host:               cfg.Host,
		Port:               cfg.Port,
		Username:           cfg.Username,
		Password:           cfg.Password,
		FromAddress:        cfg.FromAddr,
		TLS:                mailer.TLSMode(cfg.TLSMode),
		Timeout:            time.Duration(cfg.TimeoutSeconds) * time.Second,
		InsecureSkipVerify: cfg.InsecureTLS,
		ServerName:         cfg.ServerName,
	}
	sender, err := mailer.NewSMTPSender(mc)
	if err != nil {
		return err
	}
	// Bypass the SetSender guard against non-capture senders in demo
	// mode by short-circuiting above; here we know the mode is not
	// demo so direct assignment is fine.
	s.storeSender(sender)
	return nil
}

// resolveBranding returns the current branding row. Used by every
// handler that renders for the public flow; falls back to a hardcoded
// sane default when the repo is nil or the read fails, so the request
// pipeline never has to error out for a missing branding row.
func (s *Server) resolveBranding(ctx context.Context) branding.Branding {
	def := branding.Branding{
		InstanceName:   "SealKeeper",
		PrimaryColor:   "#7A1F2B", // cardinal — buttons, badges
		SecondaryColor: "#C9A961", // gold — banner, hover accents
		TertiaryColor:  "#1A1814", // ink — display text
	}
	if s.branding == nil {
		return def
	}
	row, err := s.branding.Get(ctx)
	if err != nil {
		s.logger.Warn("branding.Get failed; falling back to defaults", "err", err)
		return def
	}
	return row
}

// Limiter exposes the composite limiter so callers can pre-warm it or read
// its current state (operator endpoints in a future module).
func (s *Server) Limiter() ratelimit.Composite { return s.limiter }

// Router builds the chi router with all routes wired.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.securityHeaders)
	// No middleware.RealIP: it trusts X-Forwarded-For / X-Real-IP from any
	// peer (GO-2026-5774/5775/5777). Client IPs come from s.clientIP, which
	// honours forwarding headers only from SK_TRUSTED_PROXY_CIDRS.
	r.Use(s.instrumentation)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealthz)
	r.Method(http.MethodGet, "/readyz", s.readyz.Handler(2*time.Second))
	r.Method(http.MethodGet, "/metrics", s.metricsHandler())
	r.Get("/version", s.handleVersion)
	r.Get("/", s.handleRoot)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/policy", s.handlePolicy)
		// Cross-origin pages must not mint reveal links from their
		// visitors' browsers (distributed rate-limit bypass, mail bombing),
		// nor burn someone else's token.
		r.With(sameOriginPOST).Post("/policy", s.handlePolicyConsume)
		r.With(sameOriginPOST).Post("/request", s.handleRequest)
	})

	r.Get("/reveal/{token}", s.handleRevealPage)

	if s.cfg.WebDir != "" {
		fs := http.FileServer(staticFS{dir: http.Dir(s.cfg.WebDir)})
		r.Handle("/static/*", http.StripPrefix("/static/", fs))
	}

	// /__captured_mail is the in-memory mail viewer (FR-H.17 / FR-H.79 —
	// capture-only SMTP). Eval mode shows the whole queue; a public demo
	// only the caller's own mail (see demo.go). Never in production.
	switch {
	case s.cfg.IsDemo():
		r.Method(http.MethodGet, "/__captured_mail", s.mail.ScopedHandler(s.demoCaptureOwner))
	case s.cfg.IsEval():
		r.Method(http.MethodGet, "/__captured_mail", s.mail.Handler())
	}

	// Branding logo — public asset, no auth required. Cached briefly by
	// the browser; the admin save handler invalidates by virtue of the
	// updated_at timestamp acting as an ETag-like value when we serve.
	r.Get("/static/branding/logo", s.handleBrandingLogo)

	if s.adminRepo != nil {
		s.registerAdminRoutes(r)
	}

	return r
}

// handleBrandingLogo streams the current branding logo. 404 when no logo
// is uploaded yet — the public template hides the <img> element in that
// case, so visitors never see a broken image icon.
func (s *Server) handleBrandingLogo(w http.ResponseWriter, r *http.Request) {
	if s.branding == nil {
		http.NotFound(w, r)
		return
	}
	bytes, mime, err := s.branding.Logo(r.Context())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// An SVG opened directly is a same-origin document: sandbox it so any
	// script inside never runs (embedded via <img> it never does anyway).
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox")
	w.Header().Set("Content-Disposition", `inline; filename="logo"`)
	_, _ = w.Write(bytes)
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Sweep expired limiter keys; without it every e-mail / IP ever seen
	// stays in memory for the life of the process.
	stopJanitors := make(chan struct{})
	defer close(stopJanitors)
	for _, l := range []*ratelimit.Limiter{s.limiter.Email, s.limiter.IP, s.loginLimiter, s.tokenLimiter} {
		if l != nil {
			go l.RunJanitor(stopJanitors, 5*time.Minute)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("http server starting", "addr", s.cfg.Listen, "mode", string(s.cfg.Mode))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.logger.Info("http server shutting down")
		err := srv.Shutdown(shutdownCtx)
		s.WaitMail(shutdownCtx) // let queued reveal mails reach the relay
		return err
	case err := <-errCh:
		return err
	}
}

// ----- handlers -------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_date": version.BuildDate,
		"go":         version.GoVersion(),
		"mode":       string(s.cfg.Mode),
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	b := s.resolveBranding(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.landingTpl.Execute(w, map[string]any{
		"CSPNonce":   scriptNonce(w),
		"Branding":   b,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
	}); err != nil {
		s.logger.Error("landing template render failed", "err", err)
	}
}

// maxRequestBodyBytes bounds POST /api/v1/request bodies.
const maxRequestBodyBytes = 4 << 10

// requestPayload is the POST /api/v1/request body. Legacy "domain" and
// "subject" fields are ignored: the domain is derived server-side from the
// normalised email so a requester cannot forge what operators see in the
// audit log, the SIEM feed or request_tokens.domain.
type requestPayload struct {
	Email string `json:"email"`
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// JSON only: text/plain, form and multipart bodies are CORS "simple
	// requests" any website can fire without a preflight. Like a malformed
	// payload, this reveals nothing about the allowlist.
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, `{"error":"unsupported_media_type"}`, http.StatusUnsupportedMediaType)
		return
	}
	start := time.Now()
	captureOwner := s.demoCaptureHandle(w, r)

	// FR-B.7 invariant — every code path below returns the SAME 202 body,
	// after the same latency floor (FR-B.13, see requestmail.go).
	// Failure information stays in the audit log, never in the response.
	acceptedResp := func(extra map[string]string) {
		s.padRequestLatency(r.Context(), start)
		body := map[string]string{"status": "accepted"}
		for k, v := range extra {
			body[k] = v
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(body)
	}

	// The payload is three short strings; cap it so an attacker can't make
	// us buffer, hash and audit-log megabytes per request.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var p requestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		// Malformed payload is the one case we DO surface — it cannot leak
		// allowlist info and helps integrators debug client code.
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
		return
	}
	if p.Email == "" {
		http.Error(w, `{"error":"email_required"}`, http.StatusBadRequest)
		return
	}
	// Bare addr-spec only: display names / comments are how CR/LF reached
	// the To: header. A syntax error reveals nothing about the allowlist.
	email, err := mail.NormalizeAddress(p.Email)
	if err != nil {
		http.Error(w, `{"error":"invalid_email"}`, http.StatusBadRequest)
		return
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	ip := s.clientIP(r)
	ipHash := s.hashShort(ip)
	uaHash := s.hashShort(r.UserAgent())

	// FR-B.11..13 — apply rate limits BEFORE issuing anything. The hit is
	// observable only via the audit log + Prometheus counter.
	decision := s.limiter.Check(rateLimitKey(email), rateLimitIPKey(ip))
	if !decision.Allowed {
		s.rateHits.WithLabelValues(decision.Reason).Inc()
		s.auditAppend(r.Context(), audit.EventRateLimited, email, decision.Reason, map[string]any{
			"ip_hash":              ipHash,
			"ua_hash":              uaHash,
			"limit_email_per_hour": s.cfg.RateLimitEmailPerHour,
			"limit_ip_per_hour":    s.cfg.RateLimitIPPerHour,
		})
		s.logger.Info("rate-limited request silently dropped",
			"email", email, "dimension", decision.Reason,
		)
		acceptedResp(nil) // identical response — FR-B.13
		return
	}

	// FR-C.20..23 — consult the domain allowlist when it has any entries.
	// An empty table keeps the zero-config eval flow open. A denied domain
	// is FR-B.9-silent: same response, audit log carries the truth.
	emailDomain := ""
	if at := strings.LastIndex(email, "@"); at > 0 && at+1 < len(email) {
		emailDomain = email[at+1:]
	}
	if s.domains != nil {
		ok, err := s.domains.Allows(r.Context(), emailDomain)
		if err != nil {
			s.logger.Error("domains.Allows failed", "err", err)
			// Fail-safe: deny silently so a database hiccup can't open the gate.
			acceptedResp(nil)
			return
		}
		if !ok {
			s.auditAppend(r.Context(), "request.domain_blocked", email, emailDomain, map[string]any{
				"ip_hash": ipHash,
				"ua_hash": uaHash,
			})
			s.logger.Info("domain not in allowlist — silent drop",
				"email", email, "domain", emailDomain,
			)
			acceptedResp(nil) // FR-B.13
			return
		}
	}

	// FR-C.27..28 — resolve a policy NOW so we never mint a token that
	// nobody can consume. The resolution honours the elevation lists and
	// the per-(domain, level) policy mapping.
	//
	// Zero-config fallback: when no policies are configured, skip the gate
	// entirely and let handlePolicy serve the built-in Default. The moment
	// the admin adds a row the gate activates.
	if s.policies != nil {
		count, err := s.policies.Count(r.Context())
		if err != nil {
			s.logger.Error("policies.Count failed", "err", err)
			acceptedResp(nil)
			return
		}
		if count > 0 {
			if _, err := s.policies.Resolve(r.Context(), email); errors.Is(err, policies.ErrNoPolicy) {
				s.auditAppend(r.Context(), "request.policy_not_found", email, "", map[string]any{
					"ip_hash": ipHash,
					"ua_hash": uaHash,
				})
				s.logger.Info("no policy resolved for email — silent drop", "email", email)
				acceptedResp(nil) // FR-B.13
				return
			} else if err != nil {
				s.logger.Error("policies.Resolve failed", "err", err)
				acceptedResp(nil) // fail-safe deny
				return
			}
		}
	}

	tok, err := s.tokens.Issue(r.Context(), tokens.IssueOptions{
		Email:  email,
		Domain: emailDomain,
		IPHash: ipHash,
		UAHash: uaHash,
		TTL:    tokens.DefaultTTL,
	})
	if err != nil {
		s.logger.Error("tokens.Issue failed", "err", err)
		s.auditAppend(r.Context(), "request.issue_failed", email, "", map[string]any{
			"error": err.Error(),
		})
		// Still return 202 — anti-enumeration. The audit log carries the
		// truth for operators.
		acceptedResp(nil)
		return
	}

	revealURL := strings.TrimRight(s.cfg.BaseURL, "/") + "/reveal/" + tok.Token
	lang := mailtemplates.PickLanguage(r.Header.Get("Accept-Language"))
	brand := s.resolveBranding(r.Context())

	var (
		msg mail.Message
	)
	if s.mailTpls != nil {
		rendered, rerr := s.mailTpls.Render(r.Context(), mailtemplates.KindRevealLink, lang, mailtemplates.Vars{
			RevealURL:       revealURL,
			UserEmail:       tok.Email,
			ExpiresAt:       tok.ExpiresAt,
			ValidityMinutes: int(tokens.DefaultTTL / time.Minute),
			InstanceName:    brand.InstanceName,
			InstanceDomain:  s.cfg.InstanceDomain,
			ContactURL:      brand.ContactURL,
		})
		if rerr != nil {
			s.logger.Error("mailtemplates.Render failed", "err", rerr)
			acceptedResp(nil)
			return
		}
		built, aerr := mail.Assemble(mail.AssembleInputs{
			To:             tok.Email,
			InstanceDomain: s.cfg.InstanceDomain,
			Subject:        rendered.Subject,
			Text:           rendered.Text,
			HTML:           rendered.HTML,
		})
		if aerr != nil {
			s.logger.Error("mail.Assemble failed", "err", aerr)
			acceptedResp(nil)
			return
		}
		msg = built
	} else {
		built, berr := mail.BuildReveal(mail.RevealInputs{
			To:              tok.Email,
			InstanceDomain:  s.cfg.InstanceDomain,
			RevealURL:       revealURL,
			ValidityMinutes: int(tokens.DefaultTTL / time.Minute),
		})
		if berr != nil {
			s.logger.Error("mail.BuildReveal failed", "err", berr)
			acceptedResp(nil)
			return
		}
		msg = built
	}

	// The capture queue is in-memory: write to it directly so the mail is
	// tagged with its demo owner and eval mode gets the capture id back.
	// (Setting CaptureIDCallback on the shared sender raced between
	// concurrent requests.)
	// Any other sender talks to a relay: it runs in the background so the
	// relay round trip never shows in the response time (FR-B.13); a
	// failure is audited as mail.send_failed.
	sender := s.currentSender()
	captureID := ""
	if cs, ok := sender.(*mailer.CaptureSender); ok && cs.Store != nil {
		captureID = cs.Store.CaptureFor(captureOwner, msg.To, msg.Subject, msg.String())
	} else {
		s.sendRevealMail(r.Context(), sender, email, tokenRef(tok.Token), msg)
	}

	s.auditAppend(r.Context(), audit.EventTokenIssued, email, tokenRef(tok.Token), map[string]any{
		"ip_hash":   ipHash,
		"ua_hash":   uaHash,
		"domain":    tok.Domain,
		"transport": sender.Name(),
	})

	extra := map[string]string{}
	if s.cfg.IsEval() && captureID != "" {
		extra["capture"] = captureID
		extra["debug_reveal_url"] = revealURL
	}
	acceptedResp(extra)
}

// auditAppend is a fire-and-forget audit helper. Errors are logged but never
// propagated — the audit log is best-effort during the request critical path.
func (s *Server) auditAppend(ctx context.Context, event, actor, target string, details map[string]any) {
	if s.audit == nil {
		return
	}
	entry, err := s.audit.Append(ctx, event, actor, target, details)
	if err != nil {
		s.logger.Warn("audit.Append failed", "event", event, "err", err)
		return
	}
	// Fan out to enabled integrations. Non-blocking — the dispatcher
	// drops on overflow rather than slowing the request pipeline.
	if s.dispatcher != nil {
		ev := integrations.NewEvent(
			entry.SequenceNo,
			entry.EventType,
			entry.Actor,
			entry.Target,
			entry.Details,
			entry.EntryHash,
			s.cfg.InstanceDomain,
			entry.OccurredAt,
		)
		s.dispatcher.Push(ev)
	}
}

// clientIP returns the client IP for a request (FR-H.42). X-Forwarded-For
// is honoured only when the immediate peer (r.RemoteAddr) is within
// SK_TRUSTED_PROXY_CIDRS. The header is then walked right-to-left, skipping
// trusted hops: the first untrusted address is the client. Entries left of
// it are client-controlled and never read — taking the leftmost entry would
// let any caller rotate a fake XFF to dodge the per-IP rate limit (FR-B.12).
func (s *Server) clientIP(r *http.Request) string {
	peer := remoteHost(r.RemoteAddr)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !s.isTrustedProxy(peerAddr) {
		return peer
	}
	client := peerAddr
	hops := r.Header.Values("X-Forwarded-For")
	for i := len(hops) - 1; i >= 0; i-- {
		parts := strings.Split(hops[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				// Malformed hop: stop at the last address we could vouch for.
				return client.String()
			}
			client = hop.Unmap()
			if !s.isTrustedProxy(client) {
				return client.String()
			}
		}
	}
	return client.String()
}

// rateLimitIPv6Prefix is the IPv6 block one client is assumed to control:
// a /64 is the usual end-site allocation, so keying on the /128 would let
// a caller rotate source addresses past every per-IP limit (FR-B.12).
const rateLimitIPv6Prefix = 64

// rateLimitIPKey maps a client IP to its per-IP limiter key: IPv4 (and
// IPv4-mapped IPv6) addresses as-is, native IPv6 folded to its /64.
func rateLimitIPKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr.WithZone(""), rateLimitIPv6Prefix).Masked().String()
}

func (s *Server) isTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range s.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteHost strips the port from r.RemoteAddr ("host:port", "[v6]:port").
func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// maxPolicyBodyBytes caps the POST /api/v1/policy body: one 43-char token
// plus JSON framing.
const maxPolicyBodyBytes = 1 << 10

// handlePolicy serves GET /api/v1/policy: the default policy descriptor
// (for documentation / Swagger). A ?token=… is refused, never consumed:
// URLs end up in proxy, ingress and SIEM access logs, where a live token
// is a bearer credential anyone reading them could use first. Tokens are
// consumed by POST only (handlePolicyConsume).
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("token") {
		writeJSONError(w, http.StatusBadRequest, "token_in_query",
			"Reveal tokens are not accepted in the URL. POST {\"token\":\"…\"} to /api/v1/policy.")
		return
	}
	policy.Handler().ServeHTTP(w, r)
}

// handlePolicyConsume serves POST /api/v1/policy with a JSON body
// {"token":"…"}: the token is consumed atomically and the resolved policy
// is returned (FR-B.36). The body keeps the token out of every access log.
func (s *Server) handlePolicyConsume(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"Send the token as application/json.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)
	var p struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_payload", "Expected {\"token\":\"…\"}.")
		return
	}
	tokenParam := strings.TrimSpace(p.Token)
	if tokenParam == "" {
		writeJSONError(w, http.StatusBadRequest, "token_required", "Missing reveal token.")
		return
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	ip := s.clientIP(r)
	// Before any lookup: a refused fetch must neither probe nor burn a token.
	if !s.allowTokenLookup(w, ip) {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited",
			"Too many attempts from your network. Try again in a few minutes.")
		return
	}
	ipHash := s.hashShort(ip)
	uaHash := s.hashShort(r.UserAgent())

	// Resolve the policy BEFORE burning the token: if it can't be resolved
	// (DB error, policy disabled or deleted during the TTL) the user keeps a
	// working link instead of silently getting the weaker built-in default.
	var resolved map[string]any
	if pending, err := s.tokens.Get(r.Context(), tokenParam); err == nil {
		resolved, err = s.resolvedPolicy(r.Context(), pending.Email)
		if err != nil {
			s.logger.Error("policy resolution failed; token left unconsumed", "err", err)
			writeJSONError(w, http.StatusServiceUnavailable, "policy_unavailable",
				"Your password policy is temporarily unavailable. Try the link again later.")
			return
		}
	}
	tok, err := s.tokens.Consume(r.Context(), tokenParam, ipHash, uaHash)
	switch {
	case errors.Is(err, tokens.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "token_not_found", "Unknown reveal token.")
		return
	case errors.Is(err, tokens.ErrExpired):
		writeJSONError(w, http.StatusGone, "token_expired", "Reveal link expired. Request a new one.")
		return
	case errors.Is(err, tokens.ErrConsumed):
		writeJSONError(w, http.StatusGone, "token_consumed", "Link already used. Request a new one if needed.")
		return
	case err != nil:
		s.logger.Error("tokens.Consume failed", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	if resolved == nil {
		// Only reachable if Get failed transiently but Consume succeeded.
		if resolved, err = s.resolvedPolicy(r.Context(), tok.Email); err != nil {
			s.logger.Error("policy resolution failed after consume", "err", err)
			writeJSONError(w, http.StatusServiceUnavailable, "policy_unavailable",
				"Your password policy is temporarily unavailable. Request a new link.")
			return
		}
	}
	s.auditAppend(r.Context(), audit.EventTokenConsumed, tok.Email, tokenRef(tok.Token), map[string]any{
		"ip_hash": ipHash,
		"ua_hash": uaHash,
		"domain":  tok.Domain,
	})

	// FR-B.39..41 — optional post-consultation notification. It goes out
	// on the same bounded background workers as the reveal mails: the
	// policy roundtrip must not wait on SMTP, and Shutdown (WaitMail)
	// drains it instead of dropping it. Every request-scoped value is
	// snapshotted first so the worker never reads a cancelled r.Context().
	if s.shouldNotifyPostConsult(r.Context(), tok.Email) {
		s.queuePostConsult(r.Context(), postConsultMail{
			token:    tok.Token,
			email:    tok.Email,
			lang:     mailtemplates.PickLanguage(r.Header.Get("Accept-Language")),
			brand:    s.resolveBranding(r.Context()),
			consumed: time.Now().UTC(),
			// FR-B.40: the owner needs the IP and browser themselves to
			// recognise the access — the keyed hashes kept in the audit
			// log mean nothing to them. These go into the mail only and
			// are never stored.
			ip: s.clientIP(r),
			ua: mailDisplayText(r.UserAgent(), maxMailUALen),
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy":     resolved,
		"expires_at": tok.ExpiresAt.Format(time.RFC3339),
		"issued_at":  tok.IssuedAt.Format(time.RFC3339),
	})
}

// shouldNotifyPostConsult resolves the policy for the consultation's
// owner and returns its NotifyOnConsult flag. Returns false on any error
// or when the policies layer is not wired (zero-config eval).
func (s *Server) shouldNotifyPostConsult(ctx context.Context, email string) bool {
	if s.policies == nil || s.mailTpls == nil {
		return false
	}
	pol, err := s.policies.Resolve(ctx, email)
	if err != nil {
		return false
	}
	return pol.NotifyOnConsult
}

// postConsultMail is the snapshot the goroutine reads. Everything here is
// computed inside the handler so the dispatcher can't touch a
// request-scoped context after it has been cancelled.
type postConsultMail struct {
	token    string
	email    string
	lang     string
	brand    branding.Branding
	consumed time.Time
	ip       string
	ua       string
}

// maxMailUALen caps the User-Agent quoted in the post-consultation mail.
const maxMailUALen = 200

// mailDisplayText makes caller-controlled text safe to quote in a mail
// body: control characters are dropped and the result is capped at max
// runes.
func mailDisplayText(v string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, c := range v {
		if unicode.IsControl(c) {
			continue
		}
		if n == maxRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(c)
		n++
	}
	return b.String()
}

// queuePostConsult hands m to a background mail worker tracked by
// mailWG, so Shutdown waits for it. When every worker is busy the mail
// is dropped and audited rather than delaying the policy response.
func (s *Server) queuePostConsult(ctx context.Context, m postConsultMail) {
	select {
	case s.mailSlots <- struct{}{}:
	default:
		s.logger.Error("mail queue full — post-consultation mail dropped")
		s.auditAppend(ctx, "mail.post_consult_failed", m.email, tokenRef(m.token), map[string]any{
			"stage": "queue",
			"error": "mail queue full",
		})
		return
	}
	s.mailWG.Add(1)
	// Detached from the request context on purpose: the response is
	// written before the relay answers.
	// #nosec G118 -- bounded by mailSlots, drained by WaitMail
	go func() {
		defer s.mailWG.Done()
		defer func() { <-s.mailSlots }()
		s.dispatchPostConsult(m)
	}()
}

// dispatchPostConsult renders the post_consultation template and sends
// it. Failures are logged + audited but never surface to the requester —
// the consultation itself has already succeeded. Background context with
// a generous timeout: SMTP can be slow, and we'd rather wait than drop
// the audit-trail mail.
func (s *Server) dispatchPostConsult(m postConsultMail) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rendered, err := s.mailTpls.Render(ctx, mailtemplates.KindPostConsultation, m.lang, mailtemplates.Vars{
		UserEmail:          m.email,
		InstanceName:       m.brand.InstanceName,
		InstanceDomain:     s.cfg.InstanceDomain,
		ContactURL:         m.brand.ContactURL,
		ConsultedAt:        m.consumed.Format(time.RFC3339),
		ConsultedIP:        m.ip,
		ConsultedUserAgent: m.ua,
	})
	if err != nil {
		s.logger.Error("post-consultation render failed", "err", err)
		s.auditAppend(ctx, "mail.post_consult_failed", m.email, tokenRef(m.token), map[string]any{
			"stage": "render",
			"error": err.Error(),
		})
		return
	}
	msg, err := mail.Assemble(mail.AssembleInputs{
		To:             m.email,
		InstanceDomain: s.cfg.InstanceDomain,
		Subject:        rendered.Subject,
		Text:           rendered.Text,
		HTML:           rendered.HTML,
	})
	if err != nil {
		s.logger.Error("post-consultation assemble failed", "err", err)
		s.auditAppend(ctx, "mail.post_consult_failed", m.email, tokenRef(m.token), map[string]any{
			"stage": "assemble",
			"error": err.Error(),
		})
		return
	}
	sender := s.currentSender()
	if err := sender.Send(ctx, msg); err != nil {
		s.logger.Error("post-consultation send failed", "transport", sender.Name(), "err", err)
		s.auditAppend(ctx, "mail.post_consult_failed", m.email, tokenRef(m.token), map[string]any{
			"stage":     "send",
			"transport": sender.Name(),
			"error":     err.Error(),
		})
		return
	}
	s.auditAppend(ctx, "mail.post_consult_sent", m.email, tokenRef(m.token), map[string]any{
		"transport": sender.Name(),
	})
}

// resolvedPolicy returns the PolicyDescriptor for `email`. Falls back to the
// built-in default when no policy is configured yet (zero-config eval).
// The shape mirrors module A's PolicyDescriptor so the JS bundle in the
// reveal page can consume it without translation.
//
// The built-in default only applies to a zero-config instance (no policy
// rows at all). Once an operator has configured policies, "none applies"
// or any error is returned as an error — never a silent downgrade.
func (s *Server) resolvedPolicy(ctx context.Context, email string) (map[string]any, error) {
	if s.policies == nil {
		return policyDefaultMap(), nil
	}
	row, err := s.policies.Resolve(ctx, email)
	if errors.Is(err, policies.ErrNoPolicy) {
		n, cerr := s.policies.Count(ctx)
		if cerr != nil {
			return nil, cerr
		}
		if n == 0 {
			return policyDefaultMap(), nil
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	// A row the reveal bundle would refuse (saved before the editor checked
	// it, or edited in the DB) must not cost the user their link.
	if err := policies.ValidateForReveal(row); err != nil {
		return nil, fmt.Errorf("policy %d: %w", row.ID, err)
	}
	out := map[string]any{
		"id":              row.ID,
		"domain":          row.DomainName,
		"anssiLevel":      string(row.ANSSILevel),
		"generator":       string(row.Generator),
		"proposalCount":   row.ProposalCount,
		"regenerateLimit": row.RegenerateLimit,
		"sessionTTLSec":   row.SessionTTLSeconds,
		"notifyOnConsult": row.NotifyOnConsult,
	}
	// `parameters` is admin-supplied JSON — preserve it as-is.
	// A corrupt blob is an error, not "no parameters": empty parameters
	// would make the generator fall back to weaker defaults.
	out["parameters"] = map[string]any{}
	if len(row.Params) > 0 {
		var params any
		if err := json.Unmarshal(row.Params, &params); err != nil {
			return nil, fmt.Errorf("policy %d: invalid parameters JSON: %w", row.ID, err)
		}
		out["parameters"] = params
	}
	return out, nil
}

func policyDefaultMap() map[string]any {
	def := policy.Default()
	return map[string]any{
		"version":          def.Version,
		"generators":       def.Generators,
		"min_entropy_bits": def.MinEntropy,
		"length":           def.Length,
		"levels":           def.Levels,
		"transforms":       def.Transforms,
		"updated_at":       def.UpdatedAt,
	}
}

// handleRevealPage serves the reveal HTML. The token is NOT consumed here —
// the user has to click "Décoder" first (FR-B.22). Token validity is
// previewed via tokens.Get so a clearly-expired link can show a polite
// "expired" page instead of revealing nothing.
func (s *Server) handleRevealPage(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	state := "ready"
	status := http.StatusOK
	if !s.allowTokenLookup(w, s.clientIP(r)) {
		state, status = "rate_limited", http.StatusTooManyRequests
	} else if s.tokens != nil {
		if tok, err := s.tokens.Get(r.Context(), token); err == nil {
			if tok.ConsumedAt != nil {
				state = "consumed"
			} else if !time.Now().Before(tok.ExpiresAt) {
				state = "expired"
			}
		} else if errors.Is(err, tokens.ErrNotFound) {
			state = "unknown"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	data := map[string]any{
		"CSPNonce":   scriptNonce(w),
		"Token":      token,
		"State":      state,
		"EvalBanner": s.cfg.IsEval(),
		"DemoBanner": s.cfg.IsDemo(),
		"Branding":   s.resolveBranding(r.Context()),
	}
	w.WriteHeader(status)
	_ = s.revealTpl.Execute(w, data)
}

// allowTokenLookup charges one reveal-token lookup to ip and reports
// whether it is under the cap; when it is not, Retry-After is set.
func (s *Server) allowTokenLookup(w http.ResponseWriter, ip string) bool {
	if s.tokenLimiter == nil || s.tokenLimiter.Allow(ip) {
		return true
	}
	s.rateHits.WithLabelValues("token_lookup").Inc()
	_, _, resetAt := s.tokenLimiter.Inspect(ip)
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(time.Until(resetAt).Seconds())))))
	return false
}

func (s *Server) metricsHandler() http.Handler {
	base := promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{Registry: s.registry})
	if s.cfg.MetricsToken == "" {
		return base
	}
	expected := "Bearer " + s.cfg.MetricsToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		base.ServeHTTP(w, r)
	})
}

// ----- helpers --------------------------------------------------------------

// hashShort pseudonymises an IP or User-Agent for the audit log. It is an
// HMAC keyed from the master secret: the unkeyed, truncated SHA-256 it
// replaced was reversible by brute force over the IPv4 space in minutes,
// so the "pseudonymised" IPs were personal data in clear (FR-I).
func (s *Server) hashShort(v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, s.pseudonymKey)
	_, _ = m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// tokenRef identifies a reveal token in the audit log and SIEM feeds
// without disclosing it. The raw token is a bearer credential: anyone
// reading audit_log or a SIEM index could open, or burn, a live link.
func tokenRef(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("sealkeeper-token-ref:" + token))
	return "tok:" + hex.EncodeToString(sum[:8])
}

func writeJSONError(w http.ResponseWriter, code int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  slug,
		"status": code,
		"detail": detail,
	})
}

// ----- middleware -----------------------------------------------------------

func (s *Server) instrumentation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		// Unmatched paths share one label: using r.URL.Path let anyone
		// mint a new time series per request (unauthenticated memory DoS,
		// attacker text in every scrape).
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		s.reqDur.WithLabelValues(route).Observe(time.Since(start).Seconds())
		s.reqCount.WithLabelValues(route, statusBucket(ww.Status())).Inc()
	})
}

func statusBucket(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

// ----- reveal page template -------------------------------------------------
//
// Session semantics (FR-B.27..32). The session starts when the token is
// consumed and lasts the policy's sessionTTLSec; the page then drops the
// proposals and purges the clipboard. Regeneration is bounded by
// regenerateLimit. Both are enforced in the page only: generation is
// client-side, so after the consume there is no server round trip left to
// gate, and a caller holding the policy can run the public generator at
// will — which yields no access. The server-side guarantees are the
// single-use link (atomic consume) and the audit trail. For the same
// reason the user_sessions table (migration 0002) is not written: nothing
// would ever read a row back.
//
// Secret hygiene: no-store (no disk cache; most browsers then skip the
// back/forward cache too), translate="no" on the passwords (no page
// translation round trip), and pagehide clears the DOM and the clipboard.
// There is no form field, so browser autofill never sees a password.

const revealHTML = `<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .Branding.InstanceName }} — Reveal</title>
<link rel="preconnect" href="https://fonts.bunny.net" crossorigin>
<link rel="stylesheet" href="https://fonts.bunny.net/css?family=cormorant-garamond:600,700|inter:400,500,600|jetbrains-mono:400,500&display=swap">
<style>
  :root {
    color-scheme: light dark;
    --sk-primary:   {{ .Branding.PrimaryColor }};
    --sk-secondary: {{ .Branding.SecondaryColor }};
    --sk-tertiary:  {{ .Branding.TertiaryColor }};
    --cream:        #F4EFE6;
    --cream-deep:   #ECE5D5;
    --bg-elev:      #FBF7EE;
    --ink:          #1A1814;
    --stone:        #7A7670;
    --rule:         rgba(26, 24, 20, 0.12);
    --font-display: "Cormorant Garamond", "EB Garamond", Georgia, serif;
    --font-body:    "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    --font-mono:    "JetBrains Mono", "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  body {
    margin: 0; padding: 2rem 1rem; background: var(--cream); color: var(--ink);
    font-family: var(--font-body); font-size: 16px; line-height: 1.55;
  }
  main { max-width: 42rem; margin: 0 auto; }
  header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
  header img { max-height: 56px; }
  h1, h2 { font-family: var(--font-display); font-weight: 600; letter-spacing: -0.01em; color: var(--sk-tertiary); margin: 0; }
  h1 { font-size: 2rem; }
  .banner { background: var(--sk-secondary); color: #111; padding: 0.6rem 1rem; font-size: 0.9rem; }
  .banner.demo { background: #7A1F2B; color: var(--cream); }
  .card { background: var(--bg-elev); border: 1px solid var(--rule); border-radius: 2px; padding: 1rem; margin: 0.75rem 0; }
  .pwd { font-family: var(--font-mono); font-size: 1.15rem; word-break: break-all; color: var(--ink); }
  .badge { display: inline-block; padding: 0.1rem 0.55rem; border-radius: 999px; background: var(--sk-primary); color: var(--cream); font-size: 0.78rem; font-weight: 500; letter-spacing: 0.02em; }
  button {
    font-family: var(--font-body); font-weight: 500;
    padding: 0.55rem 1.1rem; border-radius: 2px;
    border: 1px solid var(--sk-primary); background: var(--sk-primary); color: var(--cream); cursor: pointer;
  }
  button:hover { filter: brightness(0.92); }
  button.secondary { background: transparent; color: var(--sk-primary); }
  .err { color: #7A1F2B; }
  .gauge { height: 6px; background: var(--cream-deep); border-radius: 3px; overflow: hidden; margin-top: 0.5rem; }
  .gauge > div { height: 100%; background: linear-gradient(90deg, #B23A48 0%, var(--sk-secondary) 50%, #2A6F4F 100%); }
</style>
</head>
<body><main>
{{ if .EvalBanner }}<div class="banner">⚠ Evaluation mode — not for production</div>{{ end }}
{{ if .DemoBanner }}<div class="banner demo" data-testid="demo-banner">⚠ Public demo — all data is public and purged daily</div>{{ end }}
<header>
  {{ if .Branding.HasLogo }}<img src="/static/branding/logo" alt="{{ .Branding.InstanceName }} logo">{{ end }}
  <h1>{{ .Branding.InstanceName }}</h1>
</header>

{{ if eq .State "rate_limited" }}
  <p class="err">Too many attempts from your network. Try again in a few minutes.</p>
{{ else if eq .State "expired" }}
  <p class="err">This reveal link has expired. Please request a new one.</p>
{{ else if eq .State "consumed" }}
  <p class="err">This reveal link has already been used. Request a new one if necessary.</p>
{{ else if eq .State "unknown" }}
  <p class="err">Unknown reveal link. Please request a new one.</p>
{{ else }}
  <p>Click the button below to reveal your password proposals. The link is single-use; once consumed it can no longer be re-opened.</p>
  <p id="decode-row"><button id="decode-btn" type="button">Décoder</button></p>
  <p id="countdown" data-testid="countdown" aria-live="polite" hidden></p>
  <div id="proposals" data-testid="proposals" hidden></div>
  <p id="regen-row" hidden><button id="regen-btn" type="button" class="secondary">Nouvelles propositions</button></p>
  <p id="clip-note" hidden><small>Le presse-papier est vidé 30 s après la copie et à la fermeture de la page.</small></p>
  <p id="expired" data-testid="expired" class="err" hidden>Session expirée. Les propositions ont été effacées ; demandez un nouveau lien si nécessaire.</p>
  <p id="error" class="err" hidden></p>
  <script src="/static/sealkeeper-generation.umd.js"></script>
  <script nonce="{{ $.CSPNonce }}">
    // Session rules (FR-B.27..32) live in the bundle (web/src/reveal.js),
    // which also documents what the server can and cannot enforce once
    // generation runs in the browser.
    const token = {{ .Token }};
    const G = window.SealKeeper.Generation;
    const R = window.SealKeeper.Reveal;
    const $ = (id) => document.getElementById(id);
    const btn = $('decode-btn'), out = $('proposals'), errEl = $('error');
    const countdown = $('countdown'), regenRow = $('regen-row'), regenBtn = $('regen-btn');
    const guard = R.createClipboardGuard({ clipboard: navigator.clipboard, permissions: navigator.permissions });
    let session = null, descriptor = null, ticker = null, closed = false;

    function card(p) {
      const c = document.createElement('div');
      c.className = 'card';
      c.dataset.testid = 'proposal';
      const pwd = document.createElement('div');
      pwd.className = 'pwd notranslate';
      pwd.dataset.testid = 'password';
      pwd.setAttribute('translate', 'no'); // never sent to a page-translation service
      pwd.textContent = p.password;
      const meta = document.createElement('div');
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.dataset.testid = 'anssi';
      badge.textContent = p.anssiLevel;
      const bits = document.createElement('small');
      bits.textContent = ' ' + p.entropyBits.toFixed(1) + ' bits';
      meta.append(badge, bits);
      const gauge = document.createElement('div');
      gauge.className = 'gauge';
      const fill = document.createElement('div');
      fill.style.width = Math.min(100, p.entropyBits) + '%';
      gauge.append(fill);
      const row = document.createElement('p');
      row.style.marginTop = '0.5rem';
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'secondary';
      copy.textContent = 'Copier';
      copy.addEventListener('click', async () => {
        if (closed || session.expired()) return close();
        try {
          await guard.copy(p.password);
          copy.textContent = 'Copié'; // FR-B.31
        } catch (e) {
          copy.textContent = 'Copie impossible';
        }
        setTimeout(() => { copy.textContent = 'Copier'; }, 2000);
      });
      row.append(copy);
      c.append(pwd, meta, gauge, row);
      return c;
    }

    function show(proposals) {
      out.replaceChildren(...proposals.map(card));
      out.hidden = false;
      const left = G.regenerationsLeft(descriptor);
      if (regenRow.hidden && left > 0 && !closed) regenRow.hidden = false; // never shown for a limit of 0
      regenBtn.disabled = left === 0;
      regenBtn.textContent = 'Nouvelles propositions (' + left + ')';
    }

    function tick() {
      if (!session || closed) return;
      if (session.expired()) return close();
      const label = 'Temps restant : ' + session.label();
      if (countdown.textContent !== label) countdown.textContent = label;
    }

    // close ends the session (TTL reached or page left): the proposals
    // leave the DOM and the clipboard is purged.
    function close() {
      if (closed) return;
      closed = true;
      clearInterval(ticker);
      void guard.purge();
      out.replaceChildren();
      out.hidden = true;
      regenRow.hidden = true;
      countdown.hidden = true;
      $('clip-note').hidden = true;
      $('expired').hidden = false;
    }

    btn.addEventListener('click', async () => {
      btn.disabled = true; btn.textContent = '…';
      try {
        // Token in the body, never the URL: URLs land in access logs.
        const r = await fetch('/api/v1/policy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token }),
          cache: 'no-store',
        });
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          throw new Error(j.detail || ('HTTP ' + r.status));
        }
        const body = await r.json();
        const policy = body.policy ? body.policy : body;
        // The session starts when the token is consumed (FR-B.29).
        session = R.createRevealSession({ ttlSec: R.sessionTTLSec(policy) });
        // Honour the operator's generator, proposal count and parameters.
        descriptor = G.descriptorFromPolicy(policy);
        const proposals = await G.generate(descriptor);
        if (closed) return;
        $('decode-row').hidden = true;
        countdown.hidden = false;
        $('clip-note').hidden = false;
        show(proposals);
        tick();
        ticker = setInterval(tick, 1000);
      } catch (e) {
        errEl.hidden = false;
        errEl.textContent = e.message || String(e);
      }
    });

    regenBtn.addEventListener('click', async () => {
      if (closed || session.expired()) return close();
      try {
        show(await G.regenerate(descriptor)); // bounded by regenerateLimit (FR-B.27)
      } catch (e) {
        regenBtn.disabled = true;
      }
    });

    // Timers are throttled in background tabs: catch up on return, and
    // retry a clipboard purge the unfocused document could not write.
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') { tick(); void guard.resume(); }
    });
    window.addEventListener('focus', () => { tick(); void guard.resume(); });
    // Leaving the page ends the session, so a back/forward-cache snapshot
    // never holds the proposals.
    window.addEventListener('pagehide', () => { if (session) close(); });
  </script>
{{ end }}
</main></body></html>`

// ----- landing page template -----------------------------------------------

const landingHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .Branding.InstanceName }}</title>
<link rel="preconnect" href="https://fonts.bunny.net" crossorigin>
<link rel="stylesheet" href="https://fonts.bunny.net/css?family=cormorant-garamond:600,700|inter:400,500,600|jetbrains-mono:400&display=swap">
<style>
  :root {
    color-scheme: light dark;
    --sk-primary:   {{ .Branding.PrimaryColor }};
    --sk-secondary: {{ .Branding.SecondaryColor }};
    --sk-tertiary:  {{ .Branding.TertiaryColor }};
    --cream:        #F4EFE6;
    --cream-deep:   #ECE5D5;
    --bg-elev:      #FBF7EE;
    --ink:          #1A1814;
    --stone:        #7A7670;
    --rule:         rgba(26, 24, 20, 0.12);
    --font-display: "Cormorant Garamond", "EB Garamond", Georgia, serif;
    --font-body:    "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  }
  body {
    margin: 0; background: var(--cream); color: var(--ink);
    font-family: var(--font-body); font-size: 16px; line-height: 1.55;
  }
  .banner { background: var(--sk-secondary); color: #111; padding: 0.6rem 1rem; font-size: 0.9rem; }
  .banner.demo { background: #7A1F2B; color: var(--cream); }
  main { max-width: 42rem; margin: 3rem auto; padding: 0 1rem; }
  header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.75rem; padding-bottom: 1rem; border-bottom: 1px solid var(--rule); }
  header img { max-height: 56px; }
  h1 { font-family: var(--font-display); font-weight: 600; color: var(--sk-tertiary); margin: 0; font-size: 2.2rem; letter-spacing: -0.01em; }
  p { margin: 0.85rem 0; }
  form { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem; margin-top: 1.25rem; }
  label { font-weight: 500; }
  button {
    font-family: var(--font-body); font-weight: 500;
    padding: 0.55rem 1.1rem; border-radius: 2px;
    border: 1px solid var(--sk-primary); background: var(--sk-primary); color: var(--cream);
    cursor: pointer;
  }
  button:hover { filter: brightness(0.92); }
  input[type=email] {
    padding: 0.5rem 0.65rem; border: 1px solid var(--rule); border-radius: 2px; background: var(--bg-elev);
    font-family: inherit; color: inherit; min-width: 16rem;
  }
  input[type=email]:focus { outline: 2px solid var(--sk-secondary); outline-offset: 1px; }
  details summary { cursor: pointer; color: var(--stone); }
  details a { color: var(--sk-primary); }
  footer { margin-top: 4rem; font-size: 0.78rem; color: var(--stone); text-align: center; border-top: 1px solid var(--rule); padding-top: 1.25rem; }
  footer a { color: inherit; }
</style>
</head>
<body>
{{ if .EvalBanner }}<div class="banner">⚠ Evaluation mode — not for production</div>{{ end }}
{{ if .DemoBanner }}<div class="banner demo" data-testid="demo-banner">⚠ Public demo — all data is public and purged daily</div>{{ end }}
<main>
  <header>
    {{ if .Branding.HasLogo }}<img src="/static/branding/logo" alt="{{ .Branding.InstanceName }} logo">{{ end }}
    <h1>{{ .Branding.InstanceName }}</h1>
  </header>
  <p>Request a password by emailing yourself a one-shot reveal link.</p>
  <form id="request-form" method="POST" action="/api/v1/request">
    <label for="email">Your professional email</label>
    <input id="email" type="email" name="email" required autocomplete="off">
    <button type="submit">Generate a password</button>
  </form>
  <p id="ack" style="margin-top:1rem;color:var(--stone)"></p>
  <details style="margin-top:2.5rem"><summary>Operator endpoints</summary>
  <ul>
    <li><a href="/healthz">/healthz</a></li>
    <li><a href="/readyz">/readyz</a></li>
    <li><a href="/metrics">/metrics</a></li>
    <li><a href="/api/v1/policy">/api/v1/policy</a></li>
    <li><a href="/version">/version</a></li>
  </ul></details>
  <footer>
    Powered by SealKeeper · open source · AGPL v3
    {{ if .Branding.ContactURL }}<br><a href="{{ .Branding.ContactURL }}">{{ .Branding.ContactURL }}</a>{{ end }}
  </footer>
</main>
<script nonce="{{ $.CSPNonce }}">
async function submitRequest(ev){
  ev.preventDefault();
  const email = ev.target.email.value;
  await fetch('/api/v1/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email})});
  document.getElementById('ack').textContent = 'If this address is authorised, an email is on its way. Check your inbox.';
  return false;
}
document.getElementById('request-form').addEventListener('submit', submitRequest);
</script>
</body></html>`

// isJSONContentType reports whether a Content-Type header names
// application/json (parameters such as charset are allowed).
func isJSONContentType(v string) bool {
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && mt == "application/json"
}

// rateLimitKey folds sub-addressing ("user+tag@example.org") so the per-email
// cap cannot be dodged — nor a victim's inbox flooded — by varying the tag.
func rateLimitKey(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return email
	}
	local, domain := email[:at], email[at:]
	if plus := strings.IndexByte(local, '+'); plus > 0 {
		local = local[:plus]
	}
	return local + domain
}

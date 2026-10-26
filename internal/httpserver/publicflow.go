package httpserver

// Step helpers for the two public token handlers in server.go:
// handleRequest (POST /api/v1/request) and handlePolicyConsume
// (POST /api/v1/policy). They exist only to keep those handlers readable;
// the order of side effects is the handlers' contract and is preserved
// call for call.

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/audit"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/mail"
	"github.com/sched75/sealkeeper/internal/mailer"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/tokens"
)

// publicRequest carries the normalised, request-scoped values of one
// POST /api/v1/request once its payload has been accepted.
type publicRequest struct {
	email  string
	domain string
	ip     string
	ipHash string
	uaHash string
}

// writeAcceptedResponse writes the single FR-B.7 / FR-B.13 response every
// outcome of handleRequest shares: the latency floor, then 202 with
// {"status":"accepted"} plus the optional eval-mode extras.
func (s *Server) writeAcceptedResponse(w http.ResponseWriter, r *http.Request, start time.Time, extra map[string]string) {
	s.padRequestLatency(r.Context(), start)
	body := map[string]string{"status": "accepted"}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(body)
}

// readRequestEmail decodes the bounded request payload and returns the
// normalised email. On failure it has already written the (allowlist-
// neutral) 4xx/503 and returns ok=false.
func (s *Server) readRequestEmail(w http.ResponseWriter, r *http.Request) (string, bool) {
	// The payload is three short strings; cap it so an attacker can't make
	// us buffer, hash and audit-log megabytes per request.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var p requestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		// Malformed payload is the one case we DO surface — it cannot leak
		// allowlist info and helps integrators debug client code.
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
		return "", false
	}
	if p.Email == "" {
		http.Error(w, `{"error":"email_required"}`, http.StatusBadRequest)
		return "", false
	}
	// Bare addr-spec only: display names / comments are how CR/LF reached
	// the To: header. A syntax error reveals nothing about the allowlist.
	email, err := mail.NormalizeAddress(p.Email)
	if err != nil {
		http.Error(w, `{"error":"invalid_email"}`, http.StatusBadRequest)
		return "", false
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return "", false
	}
	return email, true
}

// newPublicRequest derives the client fingerprint and the email's domain.
// The domain is derived server-side so a requester cannot forge it.
func (s *Server) newPublicRequest(r *http.Request, email string) publicRequest {
	ip := s.clientIP(r)
	pr := publicRequest{
		email:  email,
		ip:     ip,
		ipHash: s.hashShort(ip),
		uaHash: s.hashShort(r.UserAgent()),
	}
	if at := strings.LastIndex(email, "@"); at > 0 && at+1 < len(email) {
		pr.domain = email[at+1:]
	}
	return pr
}

// admitRequest runs the gates in their fixed order — rate limit, domain
// allowlist, policy resolution — and stops at the first refusal. A false
// return means "answer the identical 202 and issue nothing".
func (s *Server) admitRequest(ctx context.Context, pr publicRequest) bool {
	return s.requestRateGate(ctx, pr) &&
		s.requestDomainGate(ctx, pr) &&
		s.requestPolicyGate(ctx, pr)
}

// requestRateGate — FR-B.11..13: rate limits apply BEFORE issuing
// anything. The hit is observable only via the audit log + Prometheus.
func (s *Server) requestRateGate(ctx context.Context, pr publicRequest) bool {
	decision := s.limiter.Check(rateLimitKey(pr.email), rateLimitIPKey(pr.ip))
	if decision.Allowed {
		return true
	}
	s.rateHits.WithLabelValues(decision.Reason).Inc()
	s.auditRateLimited(ctx, pr, decision.Reason)
	s.logger.Info("rate-limited request silently dropped",
		"email", pr.email, "dimension", decision.Reason,
	)
	return false
}

// requestDomainGate — FR-C.20..23: consult the domain allowlist when it is
// wired. A denied domain is FR-B.9-silent; a lookup error denies
// (fail-safe) so a database hiccup can't open the gate. An empty
// allowlist in production denies too (SK-37), audited as allowlist_empty.
func (s *Server) requestDomainGate(ctx context.Context, pr publicRequest) bool {
	if s.domains == nil {
		return true
	}
	ok, err := s.domains.Allows(ctx, pr.domain)
	reason := "not_listed"
	switch {
	case errors.Is(err, domains.ErrEmptyAllowlist):
		reason = "allowlist_empty"
	case err != nil:
		s.logger.Error("domains.Allows failed", "err", err)
		return false
	case ok:
		return true
	}
	s.auditAppend(ctx, "request.domain_blocked", pr.email, pr.domain, map[string]any{
		"ip_hash": pr.ipHash,
		"ua_hash": pr.uaHash,
		"reason":  reason,
	})
	s.logger.Info("domain not in allowlist — silent drop",
		"email", pr.email, "domain", pr.domain, "reason", reason,
	)
	return false
}

// requestPolicyGate — FR-C.27..28: resolve a policy NOW so we never mint a
// token nobody can consume. Zero-config fallback: with no policy rows the
// gate is skipped and handlePolicy serves the built-in default.
func (s *Server) requestPolicyGate(ctx context.Context, pr publicRequest) bool {
	if s.policies == nil {
		return true
	}
	count, err := s.policies.Count(ctx)
	if err != nil {
		s.logger.Error("policies.Count failed", "err", err)
		return false
	}
	if count == 0 {
		return true
	}
	_, err = s.policies.Resolve(ctx, pr.email)
	switch {
	case errors.Is(err, policies.ErrNoPolicy):
		s.auditAppend(ctx, "request.policy_not_found", pr.email, "", map[string]any{
			"ip_hash": pr.ipHash,
			"ua_hash": pr.uaHash,
		})
		s.logger.Info("no policy resolved for email — silent drop", "email", pr.email)
		return false
	case err != nil:
		s.logger.Error("policies.Resolve failed", "err", err)
		return false // fail-safe deny
	}
	return true
}

// issueRequestToken mints the reveal token. A failure is audited and
// reported as ok=false; the caller still answers the identical 202.
func (s *Server) issueRequestToken(ctx context.Context, pr publicRequest) (tokens.Token, bool) {
	tok, err := s.tokens.Issue(ctx, tokens.IssueOptions{
		Email:  pr.email,
		Domain: pr.domain,
		IPHash: pr.ipHash,
		UAHash: pr.uaHash,
		TTL:    tokens.DefaultTTL,
	})
	if err != nil {
		s.logger.Error("tokens.Issue failed", "err", err)
		s.auditAppend(ctx, "request.issue_failed", pr.email, "", map[string]any{
			"error": err.Error(),
		})
		return tokens.Token{}, false
	}
	return tok, true
}

// buildRevealMessage renders the reveal mail for tok, from the template
// store when wired, else from the built-in body. Errors are logged and
// reported as ok=false.
func (s *Server) buildRevealMessage(ctx context.Context, tok tokens.Token, revealURL string) (mail.Message, bool) {
	lang := s.mailLanguage()
	brand := s.resolveBranding(ctx)
	if s.mailTpls == nil {
		built, err := mail.BuildReveal(mail.RevealInputs{
			To:              tok.Email,
			InstanceDomain:  s.cfg.InstanceDomain,
			RevealURL:       revealURL,
			ValidityMinutes: int(tokens.DefaultTTL / time.Minute),
		})
		if err != nil {
			s.logger.Error("mail.BuildReveal failed", "err", err)
			return mail.Message{}, false
		}
		return built, true
	}
	rendered, err := s.mailTpls.Render(ctx, mailtemplates.KindRevealLink, lang, mailtemplates.Vars{
		RevealURL:       revealURL,
		UserEmail:       tok.Email,
		ExpiresAt:       tok.ExpiresAt,
		ValidityMinutes: int(tokens.DefaultTTL / time.Minute),
		InstanceName:    brand.InstanceName,
		InstanceDomain:  s.cfg.InstanceDomain,
		ContactURL:      brand.ContactURL,
	})
	if err != nil {
		s.logger.Error("mailtemplates.Render failed", "err", err)
		return mail.Message{}, false
	}
	built, err := mail.Assemble(mail.AssembleInputs{
		To:             tok.Email,
		InstanceDomain: s.cfg.InstanceDomain,
		Subject:        rendered.Subject,
		Text:           rendered.Text,
		HTML:           rendered.HTML,
	})
	if err != nil {
		s.logger.Error("mail.Assemble failed", "err", err)
		return mail.Message{}, false
	}
	return built, true
}

// deliverRevealMail hands msg to the current sender and returns that
// sender plus the capture id (capture sender only).
//
// The capture queue is in-memory: write to it directly so the mail is
// tagged with its demo owner and eval mode gets the capture id back.
// (Setting CaptureIDCallback on the shared sender raced between
// concurrent requests.) Any other sender talks to a relay: it runs in the
// background so the relay round trip never shows in the response time
// (FR-B.13); a failure is audited as mail.send_failed.
func (s *Server) deliverRevealMail(ctx context.Context, captureOwner, email string, tok tokens.Token, msg mail.Message) (mailer.Sender, string) {
	sender := s.currentSender()
	if cs, ok := sender.(*mailer.CaptureSender); ok && cs.Store != nil {
		return sender, cs.Store.CaptureFor(captureOwner, msg.To, msg.Subject, msg.String())
	}
	s.sendRevealMail(ctx, sender, email, tokenRef(tok.Token), msg)
	return sender, ""
}

// readConsumeToken decodes the bounded POST /api/v1/policy body and
// returns the trimmed token. On failure it has already written the error
// response and returns ok=false.
func (s *Server) readConsumeToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"Send the token as application/json.")
		return "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)
	var p struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_payload", "Expected {\"token\":\"…\"}.")
		return "", false
	}
	tokenParam := strings.TrimSpace(p.Token)
	if tokenParam == "" {
		writeJSONError(w, http.StatusBadRequest, "token_required", "Missing reveal token.")
		return "", false
	}
	if s.tokens == nil {
		http.Error(w, `{"error":"storage_unavailable"}`, http.StatusServiceUnavailable)
		return "", false
	}
	return tokenParam, true
}

// resolveBeforeConsume resolves the policy of a still-pending token so the
// token is never burned when its policy can't be served. An unknown /
// unreadable token yields (nil, nil): Consume then reports the real state.
func (s *Server) resolveBeforeConsume(ctx context.Context, token string) (map[string]any, error) {
	pending, err := s.tokens.Get(ctx, token)
	if err != nil {
		return nil, nil //nolint:nilerr // Consume reports the token's real state
	}
	return s.resolvedPolicy(ctx, pending.Email)
}

// writeConsumeError maps a tokens.Consume error to its response. It
// returns true when it wrote one (err != nil).
func (s *Server) writeConsumeError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, tokens.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "token_not_found", "Unknown reveal token.")
	case errors.Is(err, tokens.ErrExpired):
		writeJSONError(w, http.StatusGone, "token_expired", "Reveal link expired. Request a new one.")
	case errors.Is(err, tokens.ErrConsumed):
		writeJSONError(w, http.StatusGone, "token_consumed", "Link already used. Request a new one if needed.")
	default:
		s.logger.Error("tokens.Consume failed", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}
	return true
}

// auditTokenConsumed appends token.consumed with the tokenRef (never the
// raw token) and the served policy's fingerprint.
func (s *Server) auditTokenConsumed(ctx context.Context, tok tokens.Token, resolved map[string]any, ipHash, uaHash string) {
	consumed := map[string]any{
		"ip_hash":       ipHash,
		"ua_hash":       uaHash,
		"domain":        tok.Domain,
		"policy_sha256": descriptorSHA256(resolved),
		"policy_id":     "builtin_default",
	}
	if id, ok := resolved["id"]; ok {
		consumed["policy_id"] = id
	}
	s.auditAppend(ctx, audit.EventTokenConsumed, tok.Email, tokenRef(tok.Token), consumed)
}

// notifyPostConsult — FR-B.39..41: optional post-consultation
// notification. It goes out on the same bounded background workers as the
// reveal mails: the policy roundtrip must not wait on SMTP, and Shutdown
// (WaitMail) drains it instead of dropping it. Every request-scoped value
// is snapshotted first so the worker never reads a cancelled r.Context().
func (s *Server) notifyPostConsult(r *http.Request, tok tokens.Token) {
	if !s.shouldNotifyPostConsult(r.Context(), tok.Email) {
		return
	}
	s.queuePostConsult(r.Context(), postConsultMail{
		token: tok.Token,
		email: tok.Email,
		// The instance language, not the requester's Accept-Language:
		// whoever triggers the mail must not pick the language the owner
		// receives (social-engineering lever).
		lang:     s.mailLanguage(),
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

// Surfaces an opening attempt arrives through, recorded in its audit row.
const (
	surfacePolicyAPI  = "policy_api"
	surfaceRevealPage = "reveal_page"
)

// unknownAttemptAuditPerIPWindow caps the token.unknown_attempt rows one
// client can cause per 15 minutes. tokenLimiter already bounds the
// lookups themselves; this keeps a token-space probe from turning every
// one of them into a hash-chain row and a SIEM event.
const unknownAttemptAuditPerIPWindow = 5

// openAttemptEvents maps a refused opening to its audit event and to the
// reveal page state.
var openAttemptEvents = []struct {
	err    error
	event  string
	state  string
	capped bool // throttled by allowUnknownAttemptAudit
}{
	{tokens.ErrConsumed, audit.EventTokenReuseAttempt, "consumed", false},
	{tokens.ErrExpired, audit.EventTokenExpiredAttempt, "expired", false},
	{tokens.ErrNotFound, audit.EventTokenUnknownAttempt, "unknown", true},
}

// auditOpenAttempt — FR-B.38: every opening attempt is audit-logged,
// reuses included. A successful consume writes token.consumed; this
// records the refused ones (replayed, expired, unknown link), the first
// being the main sign a link was intercepted or forwarded. tok is the row
// tokens.Consume / Get returned with err (zero for an unknown token). It
// is a no-op for a nil or unrelated (storage) error.
func (s *Server) auditOpenAttempt(r *http.Request, surface, token string, tok tokens.Token, err error) {
	for _, m := range openAttemptEvents {
		if !errors.Is(err, m.err) {
			continue
		}
		ip := s.clientIP(r)
		if m.capped && !s.allowUnknownAttemptAudit(ip) {
			return
		}
		details := map[string]any{
			"surface": surface,
			"ip_hash": s.hashShort(ip),
			"ua_hash": s.hashShort(r.UserAgent()),
		}
		if tok.Domain != "" {
			details["domain"] = tok.Domain
		}
		s.auditAppend(r.Context(), m.event, tok.Email, tokenRef(token), details)
		return
	}
}

// allowUnknownAttemptAudit charges one token.unknown_attempt row to the
// client's rate-limit key; past the cap the probe is only counted in the
// rate-limit metric.
func (s *Server) allowUnknownAttemptAudit(ip string) bool {
	if s.probeLimiter == nil || s.probeLimiter.Allow(rateLimitIPKey(ip)) {
		return true
	}
	s.rateHits.WithLabelValues("unknown_token_audit").Inc()
	return false
}

// previewRevealToken returns the reveal page state for token without
// consuming it, and audits a refused opening (FR-B.38). A storage error
// keeps the "ready" page: the consume call reports the real state.
func (s *Server) previewRevealToken(r *http.Request, token string) string {
	if s.tokens == nil {
		return "ready"
	}
	tok, err := s.tokens.Get(r.Context(), token)
	switch {
	case err != nil:
	case tok.ConsumedAt != nil:
		err = tokens.ErrConsumed
	case !time.Now().Before(tok.ExpiresAt):
		err = tokens.ErrExpired
	default:
		return "ready"
	}
	for _, m := range openAttemptEvents {
		if errors.Is(err, m.err) {
			s.auditOpenAttempt(r, surfaceRevealPage, token, tok, err)
			return m.state
		}
	}
	return "ready"
}

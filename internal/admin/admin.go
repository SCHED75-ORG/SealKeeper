// Package admin owns the administrator accounts and the cookie-bound admin
// sessions backing the /admin console.
//
// PRD: FR-C.1..18 (auth + accounts), FR-C.6..10 (sessions + lockout).
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/totp"
)

// Tunables. Exposed as package-level vars so tests can shrink the lockout
// window without time-travelling the test process.
var (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	SessionTTL        = 8 * time.Hour
	SessionIdleTTL    = 30 * time.Minute
)

// Sentinel errors.
var (
	ErrNotFound          = errors.New("admin: not found")
	ErrInvalidCreds      = errors.New("admin: invalid credentials")
	ErrAccountLocked     = errors.New("admin: account locked")
	ErrAccountDisabled   = errors.New("admin: account disabled")
	ErrTOTPNotEnrolled   = errors.New("admin: totp not enrolled")
	ErrTOTPRequired      = errors.New("admin: totp required")
	ErrSessionExpired    = errors.New("admin: session expired")
	ErrSessionNotFound   = errors.New("admin: session not found")
	ErrAlreadyExists     = errors.New("admin: email already exists")
	ErrInvalidEmail      = errors.New("admin: invalid email")
	ErrLastActiveAdmin   = errors.New("admin: would leave zero active admins")
	ErrTOTPUnrecoverable = errors.New("admin: stored TOTP secret cannot be decrypted (master secret rotated?)")
)

// emailRe is the lenient address grammar used by the account-management
// surface — letters/digits/.+-_ on either side of a single @. The host
// part may be a bare hostname (so the seeded admin@localhost passes) or
// a full FQDN. We intentionally do not validate against the full
// RFC 5322 grammar: bcrypt + lowercase canonicalisation keep storage
// safe, and the operator surface is for trusted humans.
var emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+$`)

// Admin represents a row in the admins table that the application is
// allowed to see. Secrets (password hash, totp_secret_enc) stay inside the
// repository.
type Admin struct {
	ID                  int64
	Email               string
	ForcePasswordChange bool
	ForceTOTPEnroll     bool
	TOTPEnrolled        bool
	Disabled            bool
	LockedUntil         *time.Time
	LastLoginAt         *time.Time
}

// Session is the authenticated browsing session bound to a cookie.
type Session struct {
	Token         string
	AdminID       int64
	CSRFToken     string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

// Repo persists admins + admin_sessions. The Box is the master-key-derived
// AEAD used to wrap the TOTP secret and recovery codes at rest.
type Repo struct {
	db  *sql.DB
	box *cryptobox.Box
	now func() time.Time
	// pwContext lists instance-level strings (domain, instance name) the
	// password strength check treats as attacker-known.
	pwContext []string
}

// NewRepo binds a Repo. The cryptobox is required.
func NewRepo(db *sql.DB, box *cryptobox.Box) *Repo {
	return &Repo{db: db, box: box, now: time.Now}
}

// DB exposes the underlying *sql.DB so the admin HTTP handlers can run
// read-only queries that don't deserve their own typed helper yet (audit
// pagination, primarily).
func (r *Repo) DB() *sql.DB { return r.db }

// WithClock returns a copy of the repo using a custom clock (tests).
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// WithPasswordContext returns a copy of the repo whose password strength
// check also refuses passwords built from words (instance domain,
// instance name) an attacker can be assumed to know. The admin's own
// email is always part of that context.
func (r *Repo) WithPasswordContext(words ...string) *Repo {
	c := *r
	c.pwContext = append([]string(nil), words...)
	return &c
}

// validateNewPassword runs ValidateAdminPassword with the admin's email
// and the instance context.
func (r *Repo) validateNewPassword(ctx context.Context, adminID int64, newPassword string) error {
	inputs := append([]string(nil), r.pwContext...)
	if row, err := r.loadByID(ctx, adminID); err == nil {
		inputs = append(inputs, row.Email)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return ValidateAdminPassword(newPassword, inputs...)
}

// ----- account lifecycle ----------------------------------------------------

// Create inserts an admin with a hashed password and the
// force_password_change / force_totp_enroll bits set so the bootstrap flow
// is the same regardless of who created the account.
//
// Returns ErrInvalidEmail when the address doesn't pass the basic
// grammar check and ErrAlreadyExists when the email is already on file.
func (r *Repo) Create(ctx context.Context, email, plainPassword string) (Admin, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if plainPassword == "" {
		return Admin{}, errors.New("admin.Create: password required")
	}
	if !emailRe.MatchString(email) {
		return Admin{}, ErrInvalidEmail
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return Admin{}, fmt.Errorf("admin.Create: bcrypt: %w", err)
	}
	const q = `INSERT INTO admins
		(email, password_hash, force_password_change, force_totp_enroll, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	now := r.now().UTC()
	id, err := storage.InsertReturningID(ctx, r.db, q, email, string(hash), true, true, now, now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Admin{}, ErrAlreadyExists
		}
		return Admin{}, fmt.Errorf("admin.Create: insert: %w", err)
	}
	return Admin{
		ID:                  id,
		Email:               email,
		ForcePasswordChange: true,
		ForceTOTPEnroll:     true,
	}, nil
}

// ChangeEmail rewrites the email field of an existing admin. Lower-cases
// + trims the input. Returns ErrInvalidEmail / ErrAlreadyExists with the
// same semantics as Create.
func (r *Repo) ChangeEmail(ctx context.Context, adminID int64, newEmail string) error {
	newEmail = strings.ToLower(strings.TrimSpace(newEmail))
	if !emailRe.MatchString(newEmail) {
		return ErrInvalidEmail
	}
	now := r.now().UTC()
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET email = ?, updated_at = ? WHERE id = ?`),
		newEmail, now, adminID)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return ErrAlreadyExists
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns every admin row, ordered by id. Used by the operator
// management page; the result intentionally carries no secrets.
func (r *Repo) List(ctx context.Context) ([]Admin, error) {
	rows, err := r.db.QueryContext(ctx, adminSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Admin
	for rows.Next() {
		row, scanErr := r.scanRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, row.toAdmin())
	}
	return out, rows.Err()
}

// ActiveCount counts admins that are not soft-disabled. Used by the
// safeguards that refuse to disable or delete the last operator.
func (r *Repo) ActiveCount(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admins WHERE disabled_at IS NULL`).Scan(&n)
	return n, err
}

// SetDisabled toggles disabled_at. Disabling the last active admin is
// refused with ErrLastActiveAdmin so an operator can't lock everyone out.
// Sessions of a disabled admin are NOT revoked here — the existing
// LookupSession surface checks disabled_at on every load.
func (r *Repo) SetDisabled(ctx context.Context, adminID int64, disabled bool) error {
	if disabled {
		active, err := r.ActiveCount(ctx)
		if err != nil {
			return err
		}
		row, err := r.loadByID(ctx, adminID)
		if err != nil {
			return err
		}
		if row.DisabledAt == nil && active <= 1 {
			return ErrLastActiveAdmin
		}
	}
	now := r.now().UTC()
	var newDisabled any
	if disabled {
		newDisabled = now
	}
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET disabled_at = ?, updated_at = ? WHERE id = ?`),
		newDisabled, now, adminID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if disabled {
		// Revoke, not just suspend: re-enabling the account must not revive
		// sessions (possibly stolen ones) issued before it was disabled.
		return r.RevokeOtherSessions(ctx, adminID, "")
	}
	return nil
}

// Delete removes an admin row outright. Refuses to delete the last
// active admin (same safeguard as SetDisabled). The caller is expected
// to revoke the deleted admin's sessions afterwards — admin_sessions
// uses ON DELETE CASCADE so they vanish in the same statement.
func (r *Repo) Delete(ctx context.Context, adminID int64) error {
	row, err := r.loadByID(ctx, adminID)
	if err != nil {
		return err
	}
	if row.DisabledAt == nil {
		active, err := r.ActiveCount(ctx)
		if err != nil {
			return err
		}
		if active <= 1 {
			return ErrLastActiveAdmin
		}
	}
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `DELETE FROM admins WHERE id = ?`), adminID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Count returns the number of admins on file. Bootstrap uses this to decide
// whether to seed the default admin.
func (r *Repo) Count(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&n)
	return n, err
}

// FindByEmail returns the public view of an admin row, or ErrNotFound.
func (r *Repo) FindByEmail(ctx context.Context, email string) (Admin, error) {
	row, err := r.loadByEmail(ctx, email)
	if err != nil {
		return Admin{}, err
	}
	return row.toAdmin(), nil
}

// FindByID returns the public view of an admin row, or ErrNotFound.
func (r *Repo) FindByID(ctx context.Context, id int64) (Admin, error) {
	row, err := r.loadByID(ctx, id)
	if err != nil {
		return Admin{}, err
	}
	return row.toAdmin(), nil
}

// ----- authentication -------------------------------------------------------

// AuthResult carries the outcome of an Authenticate call.
type AuthResult struct {
	Admin               Admin
	NeedsPasswordChange bool
	NeedsTOTPEnrollment bool
	// UsedRecoveryCode is set when a recovery code replaced the TOTP code;
	// the caller should audit it (and nudge the admin to re-enrol).
	UsedRecoveryCode bool
}

// Authenticate verifies the password and TOTP code. The contract:
//   - if the account is missing or password is wrong, ErrInvalidCreds (and
//     the failure counter increments — see reserveAttempt);
//   - if the account is locked, ErrAccountLocked is returned without
//     verifying the password (constant time still — see handlers);
//   - if force_totp_enroll is true, TOTP is not checked yet; the caller
//     must drive the user into the enrollment flow (NeedsTOTPEnrollment);
//   - if TOTP is enrolled, the code is verified and a mismatch is also
//     ErrInvalidCreds — we never tell the user which factor failed.
func (r *Repo) Authenticate(ctx context.Context, email, password, totpCode string) (AuthResult, error) {
	row, err := r.loadByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		// Avoid leaking whether the account exists: spend the same bcrypt
		// work as a real comparison. The previous literal was not a valid
		// bcrypt hash, so bcrypt rejected it instantly (timing oracle).
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash(), []byte(password))
		return AuthResult{}, ErrInvalidCreds
	}
	if err != nil {
		return AuthResult{}, err
	}
	if row.DisabledAt != nil {
		return AuthResult{}, ErrAccountDisabled
	}
	if row.LockedUntil != nil {
		if r.now().Before(*row.LockedUntil) {
			return AuthResult{}, ErrAccountLocked
		}
		r.clearExpiredLock(ctx, row.ID)
	}

	// Reserve this attempt before doing any verification. The reservation
	// is a single conditional UPDATE, so however many requests race, at
	// most MaxFailedAttempts of them get to run bcrypt / TOTP per lock
	// cycle. A snapshot check followed by a later increment let a burst of
	// 100 requests evaluate ~57 guesses.
	reserved, err := r.reserveAttempt(ctx, row.ID)
	if err != nil {
		return AuthResult{}, err
	}
	if !reserved {
		r.lockIfExhausted(ctx, row.ID)
		return AuthResult{}, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password)); err != nil {
		r.lockIfExhausted(ctx, row.ID)
		return AuthResult{}, ErrInvalidCreds
	}

	// The failure counter is cleared only once every factor has passed
	// (RecordLoginSuccess). Clearing it here, on the password alone, let an
	// attacker holding the password guess TOTP codes without ever reaching
	// MaxFailedAttempts.

	if row.ForceTOTPEnroll || len(row.TOTPSecretEnc) == 0 {
		// No second factor exists yet: the password is the whole proof.
		r.RecordLoginSuccess(ctx, row.ID)
		return AuthResult{
			Admin:               row.toAdmin(),
			NeedsPasswordChange: row.ForcePasswordChange,
			NeedsTOTPEnrollment: true,
		}, nil
	}

	if looksLikeRecoveryCode(totpCode) {
		// A recovery code stands in for the TOTP code and is spent on use.
		if err := r.ConsumeRecoveryCode(ctx, row.ID, totpCode); err != nil {
			if !errors.Is(err, ErrInvalidCreds) {
				return AuthResult{}, err
			}
			r.lockIfExhausted(ctx, row.ID)
			return AuthResult{}, ErrInvalidCreds
		}
		r.RecordLoginSuccess(ctx, row.ID)
		return AuthResult{
			Admin:               row.toAdmin(),
			NeedsPasswordChange: row.ForcePasswordChange,
			UsedRecoveryCode:    true,
		}, nil
	}

	if strings.TrimSpace(totpCode) == "" {
		// The reserved attempt stays counted: interleaving blank codes
		// must not buy extra TOTP guesses.
		return AuthResult{Admin: row.toAdmin()}, ErrTOTPRequired
	}
	secret, err := r.openTOTPSecret(row)
	if err != nil {
		return AuthResult{}, err
	}
	step, ok, err := totp.VerifyStep(secret, totpCode, r.now())
	if err != nil {
		return AuthResult{}, err
	}
	if ok {
		// A valid code is single-use: an intercepted code replayed within its
		// validity window fails like a wrong one.
		if ok, err = r.UseTOTPStep(ctx, row.ID, step); err != nil {
			return AuthResult{}, err
		}
	}
	if !ok {
		r.lockIfExhausted(ctx, row.ID)
		return AuthResult{}, ErrInvalidCreds
	}

	r.RecordLoginSuccess(ctx, row.ID)

	return AuthResult{
		Admin:               row.toAdmin(),
		NeedsPasswordChange: row.ForcePasswordChange,
	}, nil
}

// dummyBcryptHash is a real hash at bcrypt.DefaultCost — the cost Create
// and ChangePassword use — so comparing against it for an unknown email
// takes as long as comparing against a stored hash.
var dummyBcryptHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("sealkeeper-unknown-admin"), bcrypt.DefaultCost)
	if err != nil {
		panic("admin: cannot build dummy bcrypt hash: " + err.Error())
	}
	return h
})

// ResetForBootstrap rewrites the password and zeroes out any TOTP
// enrolment + recovery codes so the admin is forced back through the
// setup wizard on the next login. Used by the offline
// `sealkeeper admin reset-password` CLI when an operator has lost
// either factor. Sessions of the target admin are revoked in the same
// transaction so a stale cookie can't ride past the gate.
//
// The caller is responsible for surfacing the new plaintext password
// out-of-band; this method never logs it.
func (r *Repo) ResetForBootstrap(ctx context.Context, adminID int64, newPassword string) error {
	if err := r.validateNewPassword(ctx, adminID, newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		rebind(r.db, `UPDATE admins
			SET password_hash = ?, force_password_change = ?, force_totp_enroll = ?,
			    totp_secret_enc = NULL, totp_recovery_codes_enc = NULL,
			    failed_attempts = 0, locked_until = NULL, updated_at = ?
			WHERE id = ?`),
		string(hash), true, true, now, adminID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL`),
		now, adminID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ChangePassword updates the password hash and clears force_password_change.
// Rejects candidates below the ANSSI B3 floor (see password.go).
func (r *Repo) ChangePassword(ctx context.Context, adminID int64, newPassword string) error {
	if err := r.validateNewPassword(ctx, adminID, newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	_, err = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins
			SET password_hash = ?, force_password_change = ?, updated_at = ?
			WHERE id = ?`),
		string(hash), false, now, adminID,
	)
	return err
}

// EnrollTOTP stores an encrypted TOTP secret + the encrypted JSON array of
// recovery codes. Clears force_totp_enroll.
func (r *Repo) EnrollTOTP(ctx context.Context, adminID int64, secret totp.Secret, recoveryCodes []string) error {
	aad := adminAAD(adminID)
	secEnc, err := r.box.Seal([]byte(secret), aad)
	if err != nil {
		return fmt.Errorf("admin.EnrollTOTP: seal secret: %w", err)
	}
	codesJSON, err := json.Marshal(recoveryCodes)
	if err != nil {
		return err
	}
	codesEnc, err := r.box.Seal(codesJSON, aad)
	if err != nil {
		return fmt.Errorf("admin.EnrollTOTP: seal codes: %w", err)
	}
	now := r.now().UTC()
	_, err = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins
			SET totp_secret_enc = ?, totp_recovery_codes_enc = ?, force_totp_enroll = ?,
			    totp_last_step = 0, updated_at = ?
			WHERE id = ?`),
		secEnc, codesEnc, false, now, adminID,
	)
	return err
}

// ConsumeRecoveryCode tries to spend one of the stored recovery codes.
// Returns nil when the code is accepted.
func (r *Repo) ConsumeRecoveryCode(ctx context.Context, adminID int64, code string) error {
	row, err := r.loadByID(ctx, adminID)
	if err != nil {
		return err
	}
	if len(row.TOTPRecoveryCodesEnc) == 0 {
		return ErrInvalidCreds
	}
	aad := adminAAD(adminID)
	pt, err := r.box.Open(row.TOTPRecoveryCodesEnc, aad)
	if err != nil {
		return err
	}
	var codes []string
	if err := json.Unmarshal(pt, &codes); err != nil {
		return err
	}
	next, ok := totp.ConsumeRecovery(codes, code)
	if !ok {
		return ErrInvalidCreds
	}
	nextJSON, _ := json.Marshal(next)
	nextEnc, err := r.box.Seal(nextJSON, aad)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	// Compare-and-swap on the ciphertext we decrypted: two concurrent logins
	// with the same code cannot both spend it.
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET totp_recovery_codes_enc = ?, updated_at = ?
			WHERE id = ? AND totp_recovery_codes_enc = ?`),
		nextEnc, now, adminID, row.TOTPRecoveryCodesEnc,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return ErrInvalidCreds
	}
	return nil
}

// looksLikeRecoveryCode tells a recovery code ("AB3K9-7M2VX") apart from a
// 6-digit TOTP code.
func looksLikeRecoveryCode(code string) bool {
	c := strings.TrimSpace(code)
	return len(c) == 11 && c[5] == '-'
}

// SealSetup wraps the TOTP secret and recovery codes drafted for the setup
// wizard so they can round-trip through the browser without being chosen
// by it. The AAD binds the blob to this admin and this session.
func (r *Repo) SealSetup(adminID int64, sessionToken string, secret totp.Secret, codes []string) (string, error) {
	pt, err := json.Marshal(setupDraft{Secret: string(secret), Codes: codes})
	if err != nil {
		return "", err
	}
	ct, err := r.box.Seal(pt, setupAAD(adminID, sessionToken))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// OpenSetup reverses SealSetup; any tampering or a blob minted for another
// admin or session fails.
func (r *Repo) OpenSetup(adminID int64, sessionToken, blob string) (totp.Secret, []string, error) {
	ct, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return "", nil, err
	}
	pt, err := r.box.Open(ct, setupAAD(adminID, sessionToken))
	if err != nil {
		return "", nil, err
	}
	var d setupDraft
	if err := json.Unmarshal(pt, &d); err != nil {
		return "", nil, err
	}
	return totp.Secret(d.Secret), d.Codes, nil
}

type setupDraft struct {
	Secret string   `json:"s"`
	Codes  []string `json:"c"`
}

func setupAAD(adminID int64, sessionToken string) []byte {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "sealkeeper-admin-setup:%d:%s", adminID, sessionToken)
	return h.Sum(nil)
}

// ----- sessions -------------------------------------------------------------

// CreateSession mints a new admin_sessions row with an opaque 256-bit token
// and a separate CSRF token. The caller stores the cookie value
// (`sk_admin_session=<token>`) and the CSRF token in a same-site Strict
// `sk_admin_csrf` cookie (double-submit pattern).
func (r *Repo) CreateSession(ctx context.Context, adminID int64, ipHash, uaHash string) (Session, error) {
	tok, err := opaqueToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf := sessionCSRF(tok)
	now := r.now().UTC()
	expires := now.Add(SessionTTL)
	idle := now.Add(SessionIdleTTL)

	_, err = r.db.ExecContext(ctx,
		rebind(r.db, `INSERT INTO admin_sessions
			(token, admin_id, issued_at, expires_at, idle_expires_at, csrf_token, ip_hash, ua_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		hashToken(tok), adminID, now, expires, idle, hashToken(csrf), nullable(ipHash), nullable(uaHash),
	)
	if err != nil {
		return Session{}, fmt.Errorf("admin.CreateSession: %w", err)
	}
	return Session{
		Token:         tok,
		AdminID:       adminID,
		CSRFToken:     csrf,
		IssuedAt:      now,
		ExpiresAt:     expires,
		IdleExpiresAt: idle,
	}, nil
}

// LookupSession validates a session token. On hit it touches the idle
// deadline (sliding window). Expired / idled-out / revoked sessions return
// ErrSessionExpired.
func (r *Repo) LookupSession(ctx context.Context, token string) (Session, Admin, error) {
	if strings.TrimSpace(token) == "" {
		return Session{}, Admin{}, ErrSessionNotFound
	}
	const q = `SELECT s.token, s.admin_id, s.issued_at, s.expires_at, s.idle_expires_at,
		s.csrf_token, s.revoked_at,
		a.id, a.email, a.force_password_change, a.force_totp_enroll, a.totp_secret_enc,
		a.disabled_at, a.locked_until, a.last_login_at
		FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token = ?`

	row := r.db.QueryRowContext(ctx, rebind(r.db, q), hashToken(token))

	var (
		sessTok                              string
		adminID                              int64
		issuedAt, expiresAt, idleExpiresAt   any
		revokedAt                            any
		csrfTok                              string
		adminPK                              int64
		email                                string
		forcePwd, forceTOTP                  bool
		totpEnc                              []byte
		disabledAt, lockedUntil, lastLoginAt any
	)
	err := row.Scan(&sessTok, &adminID, &issuedAt, &expiresAt, &idleExpiresAt,
		&csrfTok, &revokedAt,
		&adminPK, &email, &forcePwd, &forceTOTP, &totpEnc,
		&disabledAt, &lockedUntil, &lastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, Admin{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, Admin{}, err
	}

	now := r.now().UTC()
	exp, _ := toTime(expiresAt)
	idle, _ := toTime(idleExpiresAt)
	if revokedAt != nil {
		if _, err := toTime(revokedAt); err == nil {
			return Session{}, Admin{}, ErrSessionExpired
		}
	}
	if !now.Before(exp) || !now.Before(idle) {
		return Session{}, Admin{}, ErrSessionExpired
	}
	// A disabled admin must not be able to ride an existing session
	// past the disable point. SetDisabled relies on this check.
	if disabledAt != nil {
		if _, err := toTime(disabledAt); err == nil {
			return Session{}, Admin{}, ErrAccountDisabled
		}
	}

	// Touch idle deadline.
	newIdle := now.Add(SessionIdleTTL)
	_, _ = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_sessions SET idle_expires_at = ? WHERE token = ?`),
		newIdle, sessTok,
	)

	a := Admin{
		ID:                  adminPK,
		Email:               email,
		ForcePasswordChange: forcePwd,
		ForceTOTPEnroll:     forceTOTP,
		TOTPEnrolled:        len(totpEnc) > 0,
	}
	if disabledAt != nil {
		if t, err := toTime(disabledAt); err == nil {
			t := t
			a.Disabled = true
			_ = t
		}
	}
	if lockedUntil != nil {
		if t, err := toTime(lockedUntil); err == nil {
			t := t
			a.LockedUntil = &t
		}
	}
	if lastLoginAt != nil {
		if t, err := toTime(lastLoginAt); err == nil {
			t := t
			a.LastLoginAt = &t
		}
	}

	sess := Session{
		Token:         token,
		AdminID:       adminID,
		CSRFToken:     sessionCSRF(token), // csrf_token column holds only a hash
		IdleExpiresAt: newIdle,
		ExpiresAt:     exp,
	}
	if t, err := toTime(issuedAt); err == nil {
		sess.IssuedAt = t
	}
	return sess, a, nil
}

// RevokeSession marks the session as revoked.
func (r *Repo) RevokeSession(ctx context.Context, token string) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_sessions SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL`),
		now, hashToken(token),
	)
	return err
}

// RevokeOtherSessions revokes every live session of adminID except keepToken
// (pass "" to revoke them all). Called after a credential change so a stolen
// cookie dies with the old password.
func (r *Repo) RevokeOtherSessions(ctx context.Context, adminID int64, keepToken string) error {
	now := r.now().UTC()
	_, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_sessions SET revoked_at = ?
			WHERE admin_id = ? AND token <> ? AND revoked_at IS NULL`),
		now, adminID, hashToken(keepToken),
	)
	return err
}

// VerifyPassword re-checks an authenticated admin's current password before
// a sensitive change (step-up). Failures consume a login attempt, so a
// hijacked session cannot brute-force the password through this path.
func (r *Repo) VerifyPassword(ctx context.Context, adminID int64, password string) error {
	row, err := r.loadByID(ctx, adminID)
	if err != nil {
		return err
	}
	reserved, err := r.reserveAttempt(ctx, adminID)
	if err != nil {
		return err
	}
	if !reserved {
		r.lockIfExhausted(ctx, adminID)
		return ErrAccountLocked
	}
	if err := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password)); err != nil {
		r.lockIfExhausted(ctx, adminID)
		return ErrInvalidCreds
	}
	// Give the reserved attempt back without touching last_login_at.
	_, _ = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET failed_attempts = 0 WHERE id = ? AND locked_until IS NULL`),
		adminID,
	)
	return nil
}

// hashToken is what admin_sessions stores instead of the bearer token: a
// database dump or backup no longer yields usable session cookies.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// sessionCSRF derives the CSRF token from the session token. It is bound
// to the session by construction (a value planted in the CSRF cookie by a
// sibling subdomain cannot match) and needs no storage.
func sessionCSRF(sessionToken string) string {
	m := hmac.New(sha256.New, []byte(sessionToken))
	_, _ = m.Write([]byte("sealkeeper-admin-csrf"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ----- internals ------------------------------------------------------------

type adminRow struct {
	ID                   int64
	Email                string
	PasswordHash         string
	TOTPSecretEnc        []byte
	TOTPRecoveryCodesEnc []byte
	ForcePasswordChange  bool
	ForceTOTPEnroll      bool
	FailedAttempts       int
	LockedUntil          *time.Time
	DisabledAt           *time.Time
	LastLoginAt          *time.Time
}

func (a adminRow) toAdmin() Admin {
	out := Admin{
		ID:                  a.ID,
		Email:               a.Email,
		ForcePasswordChange: a.ForcePasswordChange,
		ForceTOTPEnroll:     a.ForceTOTPEnroll,
		TOTPEnrolled:        len(a.TOTPSecretEnc) > 0,
		LockedUntil:         a.LockedUntil,
		LastLoginAt:         a.LastLoginAt,
		Disabled:            a.DisabledAt != nil,
	}
	return out
}

const adminSelect = `SELECT id, email, password_hash, totp_secret_enc, totp_recovery_codes_enc,
	force_password_change, force_totp_enroll, failed_attempts, locked_until, disabled_at, last_login_at
	FROM admins`

func (r *Repo) loadByEmail(ctx context.Context, email string) (adminRow, error) {
	return r.scanRow(r.db.QueryRowContext(ctx, rebind(r.db, adminSelect+" WHERE email = ?"),
		strings.ToLower(strings.TrimSpace(email))))
}

func (r *Repo) loadByID(ctx context.Context, id int64) (adminRow, error) {
	return r.scanRow(r.db.QueryRowContext(ctx, rebind(r.db, adminSelect+" WHERE id = ?"), id))
}

type rowScanner interface{ Scan(dest ...any) error }

func (r *Repo) scanRow(rs rowScanner) (adminRow, error) {
	var (
		row                                  adminRow
		secretEnc, codesEnc                  []byte
		lockedUntil, disabledAt, lastLoginAt any
	)
	err := rs.Scan(&row.ID, &row.Email, &row.PasswordHash, &secretEnc, &codesEnc,
		&row.ForcePasswordChange, &row.ForceTOTPEnroll, &row.FailedAttempts, &lockedUntil, &disabledAt, &lastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return adminRow{}, ErrNotFound
	}
	if err != nil {
		return adminRow{}, err
	}
	row.TOTPSecretEnc = secretEnc
	row.TOTPRecoveryCodesEnc = codesEnc
	if lockedUntil != nil {
		if t, err := toTime(lockedUntil); err == nil {
			t := t
			row.LockedUntil = &t
		}
	}
	if disabledAt != nil {
		if t, err := toTime(disabledAt); err == nil {
			t := t
			row.DisabledAt = &t
		}
	}
	if lastLoginAt != nil {
		if t, err := toTime(lastLoginAt); err == nil {
			t := t
			row.LastLoginAt = &t
		}
	}
	return row, nil
}

// UseTOTPStep records step as the last TOTP time-step accepted for the
// admin. It reports false when that step (or a later one) was already used,
// which means the code is a replay. The check-and-set is one UPDATE, so two
// concurrent submissions of the same code cannot both pass.
func (r *Repo) UseTOTPStep(ctx context.Context, adminID, step int64) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET totp_last_step = ?, updated_at = ? WHERE id = ? AND totp_last_step < ?`),
		step, r.now().UTC(), adminID, step,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// reserveAttempt counts one login attempt up front. It reports false when
// the account has already used MaxFailedAttempts in the current cycle.
// Successful logins give the attempt back via RecordLoginSuccess.
func (r *Repo) reserveAttempt(ctx context.Context, adminID int64) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET failed_attempts = failed_attempts + 1, updated_at = ?
			WHERE id = ? AND failed_attempts < ?`),
		r.now().UTC(), adminID, MaxFailedAttempts,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// lockIfExhausted starts a lockout once the reserved attempts reach the
// limit. failed_attempts stays at the limit while locked, so reserveAttempt
// keeps refusing until clearExpiredLock runs after LockoutDuration.
func (r *Repo) lockIfExhausted(ctx context.Context, adminID int64) {
	now := r.now().UTC()
	_, _ = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET locked_until = ?, updated_at = ?
			WHERE id = ? AND failed_attempts >= ? AND locked_until IS NULL`),
		now.Add(LockoutDuration), now, adminID, MaxFailedAttempts,
	)
}

// clearExpiredLock opens a new cycle once a lockout has elapsed. The expiry
// is re-checked in SQL so a request holding a stale snapshot can never
// clear a lock that another request has just set.
func (r *Repo) clearExpiredLock(ctx context.Context, adminID int64) {
	now := r.now().UTC()
	_, _ = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET failed_attempts = 0, locked_until = NULL, updated_at = ?
			WHERE id = ? AND locked_until IS NOT NULL AND locked_until <= ?`),
		now, adminID, now,
	)
}

// RecordLoginSuccess clears the failure counter and stamps last_login_at.
// Call it only once every required factor has been verified — password
// plus TOTP in Authenticate, or password plus a WebAuthn assertion in the
// step-up handler. Errors are swallowed: a missed stamp must not block a
// legitimate login.
func (r *Repo) RecordLoginSuccess(ctx context.Context, adminID int64) {
	now := r.now().UTC()
	_, _ = r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admins SET failed_attempts = 0, locked_until = NULL,
			last_login_at = ?, updated_at = ? WHERE id = ?`),
		now, now, adminID,
	)
}

func (r *Repo) openTOTPSecret(row adminRow) (totp.Secret, error) {
	pt, err := r.box.Open(row.TOTPSecretEnc, adminAAD(row.ID))
	if err != nil {
		// The most common cause in eval mode: the master secret was
		// re-generated on the last container start, leaving the
		// stored ciphertext unopenable. Wrap so the HTTP layer can
		// tell the operator instead of returning a vague "internal".
		return "", fmt.Errorf("%w: %s", ErrTOTPUnrecoverable, err.Error())
	}
	return totp.Secret(pt), nil
}

// adminAAD ties the encrypted blob to a specific admin row so the same
// ciphertext, copied to another row, will not decrypt.
func adminAAD(id int64) []byte {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "sealkeeper-admin:%d", id)
	return h.Sum(nil)
}

func opaqueToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rebind(db *sql.DB, query string) string { return storage.Rebind(db, query) }

func toTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), nil
	case []byte:
		return parseTS(string(x))
	case string:
		return parseTS(x)
	case nil:
		return time.Time{}, errors.New("nil time")
	default:
		return time.Time{}, fmt.Errorf("unsupported time type %T", v)
	}
}

func parseTS(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q", s)
}

// Sanitised exposure used by admin handlers via embedded helpers.
var _ = hex.EncodeToString

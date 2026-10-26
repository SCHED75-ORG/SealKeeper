// Package webauthn owns the registration + management of WebAuthn / FIDO2
// authenticators bound to admin accounts. PRD: FR-C.19..23.
//
// Scope of this layer: enrollment (BeginRegistration / FinishRegistration),
// listing, renaming and deletion. The login ceremony that lets an admin
// substitute WebAuthn for TOTP at /admin/login is intentionally deferred to
// a follow-up layer — keeping the gates tightened in one place at a time.
//
// We wrap github.com/go-webauthn/webauthn so the HTTP layer never has to
// touch the library directly. Credentials are persisted as one row per key
// in admin_webauthn_credentials; the COSE public key sits in a BLOB column
// and the canonical credential ID (base64url) is the primary key.
package webauthn

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors surfaced by the admin handlers.
var (
	ErrNotFound       = errors.New("webauthn: credential not found")
	ErrInvalidName    = errors.New("webauthn: friendly name required")
	ErrSessionMissing = errors.New("webauthn: no enrollment session")
	ErrAlreadyExists  = errors.New("webauthn: credential id already registered")
)

// Credential is the row view used by the admin UI.
//
// PublicKey is the COSE-encoded key bytes go-webauthn needs to validate an
// assertion. It is intentionally not surfaced in the admin UI templates —
// reads happen through r.List which redacts the bytes, and the login path
// loads its own copy via listInternal.
type Credential struct {
	CredentialID    string // base64url
	AdminID         int64
	FriendlyName    string
	AttestationType string
	Transports      []string
	AAGUID          []byte
	PublicKey       []byte
	SignCount       uint32
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// AdminIdentity is the minimal admin description needed to drive a WebAuthn
// ceremony. We expose it as a struct rather than reusing admin.Admin to
// keep the package free of import cycles with the admin layer.
type AdminIdentity struct {
	ID          int64
	Email       string
	DisplayName string
}

// Repo persists credentials and runs ceremonies via the go-webauthn library.
type Repo struct {
	db  *sql.DB
	wa  *gowebauthn.WebAuthn
	now func() time.Time
}

// Config tunes the relying-party identity. RPID must be the effective domain
// (no scheme, no port) and Origins must contain the fully qualified origin(s)
// the browser sees in its address bar.
type Config struct {
	RPID          string
	RPDisplayName string
	Origins       []string
}

// NewRepo binds a Repo. It returns an error when the relying-party config
// is invalid (missing RPID / origin), which lets main.go fail fast at
// startup rather than at the first registration attempt.
func NewRepo(db *sql.DB, cfg Config) (*Repo, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RPID required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin required")
	}
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return &Repo{db: db, wa: wa, now: time.Now}, nil
}

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// BeginRegistration starts the registration ceremony. Returns the options
// that must be sent to the browser as JSON and the opaque session data that
// the caller must round-trip back to FinishRegistration unchanged. The
// session is intentionally not persisted server-side — the handler stashes
// it in a signed cookie for the seconds it takes the user to tap the key.
func (r *Repo) BeginRegistration(ctx context.Context, who AdminIdentity, friendlyName string) (options []byte, session []byte, err error) {
	friendlyName = strings.TrimSpace(friendlyName)
	if friendlyName == "" {
		return nil, nil, ErrInvalidName
	}
	user, err := r.loadUser(ctx, who, false)
	if err != nil {
		return nil, nil, err
	}
	creation, sd, err := r.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn.BeginRegistration: %w", err)
	}
	options, err = json.Marshal(creation)
	if err != nil {
		return nil, nil, err
	}
	session, err = json.Marshal(sd)
	if err != nil {
		return nil, nil, err
	}
	return options, session, nil
}

// FinishRegistration parses the browser response, validates it against the
// stashed session, and persists the new credential. The friendly name is
// captured here too so the row carries a meaningful label from the start.
func (r *Repo) FinishRegistration(ctx context.Context, who AdminIdentity, friendlyName string, sessionJSON []byte, req *http.Request) (Credential, error) {
	friendlyName = strings.TrimSpace(friendlyName)
	if friendlyName == "" {
		return Credential{}, ErrInvalidName
	}
	if len(sessionJSON) == 0 {
		return Credential{}, ErrSessionMissing
	}
	var sd gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sd); err != nil {
		return Credential{}, fmt.Errorf("webauthn: parse session: %w", err)
	}
	user, err := r.loadUser(ctx, who, false)
	if err != nil {
		return Credential{}, err
	}
	cred, err := r.wa.FinishRegistration(user, sd, req)
	if err != nil {
		return Credential{}, fmt.Errorf("webauthn.FinishRegistration: %w", err)
	}
	row, err := r.persist(ctx, who.ID, friendlyName, cred)
	if err != nil {
		return Credential{}, err
	}
	return row, nil
}

// List returns every credential bound to an admin, oldest first. The
// PublicKey field is cleared on the returned rows so a template render or
// JSON response can't accidentally leak the COSE key bytes.
func (r *Repo) List(ctx context.Context, adminID int64) ([]Credential, error) {
	rows, err := r.listInternal(ctx, adminID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].PublicKey = nil
	}
	return rows, nil
}

// HasCredentials reports whether the admin has at least one registered key.
// Used by /admin/login to decide whether to offer the "use security key"
// alternative to the TOTP code.
func (r *Repo) HasCredentials(ctx context.Context, adminID int64) (bool, error) {
	var n int64
	err := r.db.QueryRowContext(ctx,
		rebind(r.db, `SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id = ?`),
		adminID,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// listInternal is the read path that retains PublicKey for the login flow.
func (r *Repo) listInternal(ctx context.Context, adminID int64) ([]Credential, error) {
	const q = `SELECT credential_id, admin_id, friendly_name, attestation_type,
		transports, aaguid, public_key, sign_count, user_verified, backup_eligible, backup_state,
		created_at, last_used_at
		FROM admin_webauthn_credentials WHERE admin_id = ? ORDER BY created_at ASC`
	rows, err := r.db.QueryContext(ctx, rebind(r.db, q), adminID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Credential
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Rename updates the friendly_name of one credential. Errors with
// ErrNotFound when the row does not belong to the admin.
func (r *Repo) Rename(ctx context.Context, adminID int64, credentialID, friendlyName string) error {
	friendlyName = strings.TrimSpace(friendlyName)
	if friendlyName == "" {
		return ErrInvalidName
	}
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_webauthn_credentials SET friendly_name = ? WHERE credential_id = ? AND admin_id = ?`),
		friendlyName, credentialID, adminID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes one credential. Errors with ErrNotFound when the row does
// not belong to the admin so the handler can return 404 without leaking
// other admins' credential IDs.
func (r *Repo) Delete(ctx context.Context, adminID int64, credentialID string) error {
	res, err := r.db.ExecContext(ctx,
		rebind(r.db, `DELETE FROM admin_webauthn_credentials WHERE credential_id = ? AND admin_id = ?`),
		credentialID, adminID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// BeginLogin issues the assertion challenge for an already-identified
// admin (multi-factor / step-up scenario, where the password has been
// verified first). Returns the publicKey options to send to the browser and
// the opaque session blob to round-trip back to FinishLogin.
func (r *Repo) BeginLogin(ctx context.Context, who AdminIdentity) (options, session []byte, err error) {
	user, err := r.loadUser(ctx, who, true)
	if err != nil {
		return nil, nil, err
	}
	if len(user.creds) == 0 {
		return nil, nil, ErrNotFound
	}
	assertion, sd, err := r.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn.BeginLogin: %w", err)
	}
	options, err = json.Marshal(assertion)
	if err != nil {
		return nil, nil, err
	}
	session, err = json.Marshal(sd)
	if err != nil {
		return nil, nil, err
	}
	return options, session, nil
}

// FinishLogin validates the assertion response, bumps sign_count +
// last_used_at on the matching credential, and returns the row that was
// used. go-webauthn itself rejects sign-count rollbacks (cloned key
// detection) so we just persist whatever counter the library hands back.
func (r *Repo) FinishLogin(ctx context.Context, who AdminIdentity, sessionJSON []byte, req *http.Request) (Credential, error) {
	if len(sessionJSON) == 0 {
		return Credential{}, ErrSessionMissing
	}
	var sd gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sd); err != nil {
		return Credential{}, fmt.Errorf("webauthn: parse session: %w", err)
	}
	user, err := r.loadUser(ctx, who, true)
	if err != nil {
		return Credential{}, err
	}
	cred, err := r.wa.FinishLogin(user, sd, req)
	if err != nil {
		return Credential{}, fmt.Errorf("webauthn.FinishLogin: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	now := r.now().UTC()
	if _, err := r.db.ExecContext(ctx,
		rebind(r.db, `UPDATE admin_webauthn_credentials
			SET sign_count = ?, last_used_at = ?
			WHERE credential_id = ? AND admin_id = ?`),
		int64(cred.Authenticator.SignCount), now, id, who.ID,
	); err != nil {
		return Credential{}, err
	}
	row := Credential{
		CredentialID:    id,
		AdminID:         who.ID,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
	}
	t := now
	row.LastUsedAt = &t
	return row, nil
}

// ----- gowebauthn.User adapter ---------------------------------------------

type waUser struct {
	id          []byte
	email       string
	displayName string
	creds       []gowebauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                           { return u.id }
func (u *waUser) WebAuthnName() string                         { return u.email }
func (u *waUser) WebAuthnDisplayName() string                  { return u.displayName }
func (u *waUser) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

// loadUser builds the gowebauthn.User adapter and fetches the existing
// credentials.
//
// For registration only the credential IDs are needed (used as
// excludeCredentials to prevent re-enrollment of the same authenticator).
// For login we need the full Credential — PublicKey, SignCount and the
// flags — so go-webauthn can validate the assertion and detect a cloned
// authenticator. The `full` switch flips between the two read paths.
func (r *Repo) loadUser(ctx context.Context, who AdminIdentity, full bool) (*waUser, error) {
	if who.ID == 0 {
		return nil, errors.New("webauthn: admin id required")
	}
	creds, err := r.libraryCredentials(ctx, who.ID, full)
	if err != nil {
		return nil, err
	}
	display := who.DisplayName
	if display == "" {
		display = who.Email
	}
	return &waUser{
		id:          adminUserHandle(who.ID),
		email:       who.Email,
		displayName: display,
		creds:       creds,
	}, nil
}

// libraryCredentials reads existing credentials and converts them to the
// shape the go-webauthn library expects.
func (r *Repo) libraryCredentials(ctx context.Context, adminID int64, full bool) ([]gowebauthn.Credential, error) {
	rows, err := r.listInternal(ctx, adminID)
	if err != nil {
		return nil, err
	}
	out := make([]gowebauthn.Credential, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		raw, err := base64.RawURLEncoding.DecodeString(row.CredentialID)
		if err != nil {
			continue
		}
		c := gowebauthn.Credential{ID: raw}
		if full {
			c.PublicKey = row.PublicKey
			c.AttestationType = row.AttestationType
			c.Authenticator.AAGUID = row.AAGUID
			c.Authenticator.SignCount = row.SignCount
			c.Flags.UserVerified = row.UserVerified
			c.Flags.BackupEligible = row.BackupEligible
			c.Flags.BackupState = row.BackupState
		}
		out = append(out, c)
	}
	return out, nil
}

// persist writes the freshly-minted credential row.
func (r *Repo) persist(ctx context.Context, adminID int64, friendlyName string, cred *gowebauthn.Credential) (Credential, error) {
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	transportsJSON, _ := json.Marshal(transports)
	now := r.now().UTC()
	const q = `INSERT INTO admin_webauthn_credentials
		(credential_id, admin_id, public_key, attestation_type, transports, aaguid,
		 sign_count, friendly_name, user_verified, backup_eligible, backup_state, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, rebind(r.db, q),
		id, adminID, cred.PublicKey, cred.AttestationType, string(transportsJSON), cred.Authenticator.AAGUID,
		int64(cred.Authenticator.SignCount), friendlyName,
		cred.Flags.UserVerified, cred.Flags.BackupEligible, cred.Flags.BackupState, now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return Credential{}, ErrAlreadyExists
		}
		return Credential{}, err
	}
	return Credential{
		CredentialID:    id,
		AdminID:         adminID,
		FriendlyName:    friendlyName,
		AttestationType: cred.AttestationType,
		Transports:      transports,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		CreatedAt:       now,
	}, nil
}

// ----- helpers --------------------------------------------------------------

// adminUserHandle derives the WebAuthn user handle from the admin row id.
// The handle must be opaque to the user and stable across registrations
// for the same admin — a fixed prefix + 8-byte big-endian id satisfies both
// invariants and gives us 16 bytes total, well below the 64-byte cap.
func adminUserHandle(id int64) []byte {
	buf := make([]byte, 16)
	copy(buf, "sk-admin-")
	for i := 0; i < 8; i++ {
		buf[8+i] = byte(id >> (8 * (7 - i)))
	}
	buf[7] = ':'
	return buf
}

type rowScanner interface {
	Scan(...any) error
}

func scanCredential(s rowScanner) (Credential, error) {
	var (
		c              Credential
		transports     string
		aaguid         []byte
		publicKey      []byte
		lastUsed       sql.NullTime
		created        any
		signCount      int64
		userVerified   bool
		backupEligible bool
		backupState    bool
	)
	if err := s.Scan(&c.CredentialID, &c.AdminID, &c.FriendlyName, &c.AttestationType,
		&transports, &aaguid, &publicKey, &signCount, &userVerified, &backupEligible, &backupState,
		&created, &lastUsed); err != nil {
		return Credential{}, err
	}
	c.AAGUID = aaguid
	c.PublicKey = publicKey
	c.SignCount = uint32(signCount)
	c.UserVerified = userVerified
	c.BackupEligible = backupEligible
	c.BackupState = backupState
	if transports != "" {
		_ = json.Unmarshal([]byte(transports), &c.Transports)
	}
	if t, err := toTime(created); err == nil {
		c.CreatedAt = t
	}
	if lastUsed.Valid {
		t := lastUsed.Time.UTC()
		c.LastUsedAt = &t
	}
	return c, nil
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
		time.RFC3339Nano, time.RFC3339,
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

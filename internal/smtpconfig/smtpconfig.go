// Package smtpconfig owns the single-row relay configuration that lives
// next to branding in the admin DB. The values it stores override the
// env-var SMTP configuration the binary booted with — when the row is
// empty (no host saved) the env-var sender stays active.
//
// The password lands AES-256-GCM-wrapped via cryptobox so a snapshot
// of the database alone does not yield the relay credential.
//
// PRD: FR-C.55..58 (admin-configurable SMTP).
package smtpconfig

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/storage"
)

// ErrNotConfigured is returned when no SMTP override is on file — the
// caller is expected to fall back to whatever sender main.go wired
// from the environment.
var ErrNotConfigured = errors.New("smtpconfig: no override saved")

// ErrPasswordRequired is returned by Update when KeepPassword is set but
// the relay destination or identity changed (host, port, username, TLS
// mode, TLS server name, or certificate verification turned off). The
// stored password is write-only: carrying it over to a new destination
// would hand it to whatever server the form now points at (SK-23).
var ErrPasswordRequired = errors.New("smtpconfig: password must be re-entered when the relay destination changes")

// Config is the editable surface of the smtp_config row.
type Config struct {
	Host           string
	Port           int
	Username       string
	Password       string
	FromAddr       string
	TLSMode        string // auto | starttls | implicit | disable
	ServerName     string
	InsecureTLS    bool
	TimeoutSeconds int
	UpdatedAt      time.Time
}

// Configured reports whether the row carries a usable relay config —
// effectively "a host is set".
func (c Config) Configured() bool { return strings.TrimSpace(c.Host) != "" }

// UpdateInputs is the admin form payload (Password may be empty to
// preserve the previously stored value).
type UpdateInputs struct {
	Host           string
	Port           int
	Username       string
	Password       string
	KeepPassword   bool
	FromAddr       string
	TLSMode        string
	ServerName     string
	InsecureTLS    bool
	TimeoutSeconds int
}

// Repo persists smtp_config.
type Repo struct {
	db  *sql.DB
	box *cryptobox.Box
	now func() time.Time
}

// NewRepo binds a Repo. The cryptobox is required — without it we
// would have to store the relay password in cleartext.
func NewRepo(db *sql.DB, box *cryptobox.Box) *Repo {
	return &Repo{db: db, box: box, now: time.Now}
}

// Get returns the current override (or ErrNotConfigured when no host
// is on file). The password is decrypted on the fly; callers should
// not hold the returned Config in long-lived memory.
func (r *Repo) Get(ctx context.Context) (Config, error) {
	const q = `SELECT host, port, username, password_enc, from_addr, tls_mode,
		server_name, insecure_tls, timeout_seconds, updated_at
		FROM smtp_config WHERE id = 1`
	var (
		c            Config
		pwdEnc       []byte
		updatedAtCol any
	)
	err := r.db.QueryRowContext(ctx, q).Scan(
		&c.Host, &c.Port, &c.Username, &pwdEnc, &c.FromAddr, &c.TLSMode,
		&c.ServerName, &c.InsecureTLS, &c.TimeoutSeconds, &updatedAtCol,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Config{}, ErrNotConfigured
	}
	if err != nil {
		return Config{}, err
	}
	if !c.Configured() {
		return c, ErrNotConfigured
	}
	if t, err := toTime(updatedAtCol); err == nil {
		c.UpdatedAt = t
	}
	if len(pwdEnc) > 0 {
		pt, err := r.box.Open(pwdEnc, smtpAAD())
		if err != nil {
			return Config{}, fmt.Errorf("smtpconfig.Get: decrypt password: %w", err)
		}
		c.Password = string(pt)
	}
	return c, nil
}

// Update upserts the single row, optionally preserving the previously
// stored password when KeepPassword is true. An empty Host with
// KeepPassword=false clears the override entirely.
func (r *Repo) Update(ctx context.Context, in UpdateInputs, adminID *int64) error {
	if strings.TrimSpace(in.Host) == "" {
		_, err := r.db.ExecContext(ctx, rebind(r.db,
			`UPDATE smtp_config SET host='', port=587, username='', password_enc=NULL,
				from_addr='', tls_mode='auto', server_name='', insecure_tls=FALSE,
				timeout_seconds=30, updated_by_admin_id=?, updated_at=?
				WHERE id = 1`),
			nullableInt(adminID), r.now().UTC())
		if err != nil {
			return err
		}
		// If no row yet, insert a cleared one so subsequent Get is consistent.
		var n int64
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM smtp_config`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			_, err := r.db.ExecContext(ctx, rebind(r.db,
				`INSERT INTO smtp_config (id, updated_by_admin_id, created_at, updated_at)
					VALUES (1, ?, ?, ?)`),
				nullableInt(adminID), r.now().UTC(), r.now().UTC())
			return err
		}
		return nil
	}

	port := in.Port
	if port <= 0 {
		port = 587
	}
	timeout := in.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	tlsMode := strings.ToLower(strings.TrimSpace(in.TLSMode))
	switch tlsMode {
	case "auto", "starttls", "implicit", "disable":
	default:
		tlsMode = "auto"
	}

	// Build the password ciphertext. If KeepPassword is set (and no new
	// password typed) we read the existing one and re-seal it — but only
	// when the relay destination and identity are unchanged.
	pwd := in.Password
	if in.KeepPassword && pwd == "" {
		prev, err := r.Get(ctx)
		if err == nil && prev.Password != "" {
			if retargeted(prev, in.Host, port, in.Username, tlsMode, in.ServerName, in.InsecureTLS) {
				return ErrPasswordRequired
			}
			pwd = prev.Password
		}
	}
	var pwdEnc []byte
	if pwd != "" {
		var err error
		pwdEnc, err = r.box.Seal([]byte(pwd), smtpAAD())
		if err != nil {
			return fmt.Errorf("smtpconfig.Update: seal password: %w", err)
		}
	}

	now := r.now().UTC()
	// Upsert via two-step probe + INSERT/UPDATE — keeps the SQL
	// portable between SQLite and Postgres without ON CONFLICT clauses.
	var n int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM smtp_config WHERE id = 1`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := r.db.ExecContext(ctx, rebind(r.db,
			`INSERT INTO smtp_config
				(id, host, port, username, password_enc, from_addr, tls_mode, server_name,
				 insecure_tls, timeout_seconds, updated_by_admin_id, created_at, updated_at)
				VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			in.Host, port, in.Username, pwdEnc, in.FromAddr, tlsMode, in.ServerName,
			in.InsecureTLS, timeout, nullableInt(adminID), now, now)
		return err
	}
	_, err := r.db.ExecContext(ctx, rebind(r.db,
		`UPDATE smtp_config SET host=?, port=?, username=?, password_enc=?, from_addr=?,
			tls_mode=?, server_name=?, insecure_tls=?, timeout_seconds=?,
			updated_by_admin_id=?, updated_at=? WHERE id = 1`),
		in.Host, port, in.Username, pwdEnc, in.FromAddr, tlsMode, in.ServerName,
		in.InsecureTLS, timeout, nullableInt(adminID), now)
	return err
}

// ----- helpers --------------------------------------------------------------

// retargeted reports whether the submitted relay settings would send the
// stored credential somewhere (or to someone) else than it was saved for.
// Turning certificate verification *off* counts; turning it on does not.
func retargeted(prev Config, host string, port int, username, tlsMode, serverName string, insecure bool) bool {
	return !strings.EqualFold(strings.TrimSpace(prev.Host), strings.TrimSpace(host)) ||
		prev.Port != port ||
		prev.Username != username ||
		!strings.EqualFold(prev.TLSMode, tlsMode) ||
		!strings.EqualFold(strings.TrimSpace(prev.ServerName), strings.TrimSpace(serverName)) ||
		(insecure && !prev.InsecureTLS)
}

// smtpAAD ties the encrypted password to its purpose so the same
// blob, copied to e.g. the admin TOTP column, would not decrypt.
func smtpAAD() []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("sealkeeper-smtp"))
	return h.Sum(nil)
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
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

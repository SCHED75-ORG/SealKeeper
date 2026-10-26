// libraries.go owns the Repo + on-disk store. Pairs with validator.go.
package libraries

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
)

// Errors.
var (
	ErrNotFound       = errors.New("libraries: not found")
	ErrAlreadyExists  = errors.New("libraries: identical content already uploaded")
	ErrSystemReadOnly = errors.New("libraries: system libraries cannot be deleted")
)

// Library is the row view returned by Repo methods.
type Library struct {
	ID               int64
	Name             string
	Kind             Kind
	Language         string
	Description      string
	SHA256           string
	EntryCount       int
	SizeBytes        int64
	FilePath         string // relative to Repo.Dir
	System           bool
	CreatedByAdminID *int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Repo owns the libraries table and the on-disk store.
type Repo struct {
	db  *sql.DB
	dir string
	now func() time.Time
}

// NewRepo binds a Repo to a *sql.DB and a directory.
//
// The directory is created if missing (0o755). It is the caller's
// responsibility to make sure SK_LIBRARIES_DIR points at a writable
// volume in production — typically the same /data mount that already
// stores the SQLite database in eval mode.
func NewRepo(db *sql.DB, dir string) (*Repo, error) {
	if strings.TrimSpace(dir) == "" {
		dir = "data/libraries"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("libraries.NewRepo: %w", err)
	}
	return &Repo{db: db, dir: dir, now: time.Now}, nil
}

// Dir returns the on-disk root used by the store.
func (r *Repo) Dir() string { return r.dir }

// WithClock for tests.
func (r *Repo) WithClock(now func() time.Time) *Repo {
	c := *r
	c.now = now
	return &c
}

// UploadInputs is the call payload for Upload.
type UploadInputs struct {
	Name        string
	Kind        Kind
	Language    string
	Description string
	System      bool
	Content     io.Reader
	AdminID     *int64
}

// Upload validates, hashes and persists a fresh library. Idempotency: when
// the SHA-256 already exists in the database, Upload returns the existing
// row + ErrAlreadyExists so the admin handler can surface a friendly
// "already uploaded under name X" message.
func (r *Repo) Upload(ctx context.Context, in UploadInputs) (Library, Report, error) {
	if strings.TrimSpace(in.Name) == "" {
		return Library{}, Report{}, errors.New("libraries.Upload: name required")
	}
	if strings.TrimSpace(in.Language) == "" {
		return Library{}, Report{}, errors.New("libraries.Upload: language required")
	}
	if in.Content == nil {
		return Library{}, Report{}, errors.New("libraries.Upload: nil content")
	}

	// Stream the whole body into memory once: we need to validate AND hash AND
	// write to disk. Libraries are bounded in size by FR-C upload limits
	// (well under SK_MAX_LIBRARY_SIZE_MB). For the v0.1 traffic profile this
	// is fine.
	raw, err := io.ReadAll(in.Content)
	if err != nil {
		return Library{}, Report{}, fmt.Errorf("libraries.Upload: read: %w", err)
	}

	report, err := Validate(in.Kind, bytesReader(raw))
	if err != nil {
		return Library{}, report, err
	}
	if report.HasErrors() {
		return Library{}, report, fmt.Errorf("libraries.Upload: %d line errors", len(report.FirstErrors))
	}

	sum := sha256.Sum256(raw)
	hashHex := hex.EncodeToString(sum[:])
	relPath := hashHex + ".txt"

	// Duplicate hash → return the existing row.
	if existing, err := r.findBySHA(ctx, hashHex); err == nil {
		return existing, report, ErrAlreadyExists
	} else if !errors.Is(err, ErrNotFound) {
		return Library{}, report, err
	}

	abs := filepath.Join(r.dir, relPath)
	if err := os.WriteFile(abs, raw, 0o640); err != nil {
		return Library{}, report, fmt.Errorf("libraries.Upload: write file: %w", err)
	}

	now := r.now().UTC()
	const ins = `INSERT INTO libraries
		(name, kind, language, description, sha256, entry_count, size_bytes, file_path,
		 system_flag, created_by_admin_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	id, err := storage.InsertReturningID(ctx, r.db, ins,
		strings.TrimSpace(in.Name),
		string(in.Kind),
		strings.ToLower(strings.TrimSpace(in.Language)),
		strings.TrimSpace(in.Description),
		hashHex,
		report.EntryCount,
		int64(len(raw)),
		relPath,
		in.System,
		nullableInt(in.AdminID),
		now, now,
	)
	if err != nil {
		// Best-effort cleanup so an orphan file doesn't survive a partial insert.
		_ = os.Remove(abs)
		return Library{}, report, fmt.Errorf("libraries.Upload: insert: %w", err)
	}
	lib, err := r.Get(ctx, id)
	return lib, report, err
}

// List returns every row in name order.
func (r *Repo) List(ctx context.Context) ([]Library, error) {
	rows, err := r.db.QueryContext(ctx, selectQ+` ORDER BY kind, language, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Library
	for rows.Next() {
		lib, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, lib)
	}
	return out, rows.Err()
}

// Get returns a row by id.
func (r *Repo) Get(ctx context.Context, id int64) (Library, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+` WHERE id = ?`), id))
}

// Sample reads `n` first entries from the on-disk file (FR-C.56).
func (r *Repo) Sample(ctx context.Context, id int64, n int) (Library, []string, error) {
	lib, err := r.Get(ctx, id)
	if err != nil {
		return Library{}, nil, err
	}
	if n <= 0 {
		n = 10
	}
	f, err := os.Open(filepath.Join(r.dir, lib.FilePath))
	if err != nil {
		return lib, nil, fmt.Errorf("libraries.Sample: open: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := make([]string, 0, n)
	for sc.Scan() && len(out) < n {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return lib, out, sc.Err()
}

// Open returns a ReadCloser on the raw file. The caller MUST Close.
// Used by the admin download endpoint (FR-C.54).
func (r *Repo) Open(ctx context.Context, id int64) (Library, io.ReadCloser, error) {
	lib, err := r.Get(ctx, id)
	if err != nil {
		return Library{}, nil, err
	}
	f, err := os.Open(filepath.Join(r.dir, lib.FilePath))
	if err != nil {
		return lib, nil, fmt.Errorf("libraries.Open: %w", err)
	}
	return lib, f, nil
}

// Delete removes a row + its on-disk file. System libraries are rejected
// (FR-C.52).
func (r *Repo) Delete(ctx context.Context, id int64) error {
	lib, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if lib.System {
		return ErrSystemReadOnly
	}
	if _, err := r.db.ExecContext(ctx, rebind(r.db, "DELETE FROM libraries WHERE id = ?"), id); err != nil {
		return fmt.Errorf("libraries.Delete: %w", err)
	}
	// Best-effort file removal: a missing file is fine, the row is gone.
	_ = os.Remove(filepath.Join(r.dir, lib.FilePath))
	return nil
}

// ----- internals ------------------------------------------------------------

const selectQ = `SELECT id, name, kind, language, description, sha256, entry_count,
	size_bytes, file_path, system_flag, created_by_admin_id, created_at, updated_at
	FROM libraries`

type rowScanner interface{ Scan(dest ...any) error }

func (r *Repo) findBySHA(ctx context.Context, sha string) (Library, error) {
	return scan(r.db.QueryRowContext(ctx, rebind(r.db, selectQ+` WHERE sha256 = ?`), sha))
}

func scan(rs rowScanner) (Library, error) {
	var (
		lib                  Library
		kind                 string
		createdBy            sql.NullInt64
		createdAt, updatedAt any
	)
	err := rs.Scan(&lib.ID, &lib.Name, &kind, &lib.Language, &lib.Description,
		&lib.SHA256, &lib.EntryCount, &lib.SizeBytes, &lib.FilePath, &lib.System,
		&createdBy, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Library{}, ErrNotFound
	}
	if err != nil {
		return Library{}, err
	}
	lib.Kind = Kind(kind)
	if createdBy.Valid {
		v := createdBy.Int64
		lib.CreatedByAdminID = &v
	}
	if t, err := toTime(createdAt); err == nil {
		lib.CreatedAt = t
	}
	if t, err := toTime(updatedAt); err == nil {
		lib.UpdatedAt = t
	}
	return lib, nil
}

func bytesReader(b []byte) io.Reader { return readerFromBytes(b) }

// Tiny adapter so the unit tests can probe Validate without pulling
// bytes.NewReader into the test imports list.
type sliceReader struct {
	b    []byte
	read int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.read >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.read:])
	r.read += n
	return n, nil
}

func readerFromBytes(b []byte) *sliceReader { return &sliceReader{b: b} }

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

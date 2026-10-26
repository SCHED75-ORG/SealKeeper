package webauthn_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

// seedNonCountingKey inserts an admin and one credential whose stored
// sign_count is 0, like a passkey that never counts: the SK-27 clone
// check cannot catch a replay for such a key.
func seedNonCountingKey(t *testing.T, db *sql.DB) (webauthn.AdminIdentity, softKey) {
	t.Helper()
	ctx := context.Background()
	adminID, err := storage.InsertReturningID(ctx, db,
		`INSERT INTO admins (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"ops@sealkeeper.test", "x", time.Now().UTC(), time.Now().UTC())
	if err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	k := newSoftKey(t)
	if _, err := db.ExecContext(ctx, storage.Rebind(db,
		`INSERT INTO admin_webauthn_credentials (credential_id, admin_id, public_key, sign_count, created_at)
		 VALUES (?, ?, ?, ?, ?)`),
		base64.RawURLEncoding.EncodeToString(k.id), adminID, k.coseKey(), 0, time.Now().UTC()); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	return webauthn.AdminIdentity{ID: adminID, Email: "ops@sealkeeper.test"}, k
}

// beginLogin runs BeginLogin and returns the client-held session blob
// with "expires" stripped (as an attacker would), plus a signed
// assertion over its challenge with counter 0.
func beginLogin(t *testing.T, r *webauthn.Repo, who webauthn.AdminIdentity, k softKey) (session, edited, assertion []byte) {
	t.Helper()
	_, session, err := r.BeginLogin(context.Background(), who)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var sd map[string]any
	if err := json.Unmarshal(session, &sd); err != nil {
		t.Fatalf("session: %v", err)
	}
	challenge, _ := sd["challenge"].(string)
	delete(sd, "expires")
	edited, err = json.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	return session, edited, k.assertion(t, challenge, 0)
}

func finishLogin(r *webauthn.Repo, who webauthn.AdminIdentity, session, assertion []byte) error {
	req := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/login/webauthn/finish", bytes.NewReader(assertion))
	req.Header.Set("Content-Type", "application/json")
	_, err := r.FinishLogin(context.Background(), who, session, req)
	return err
}

// A captured (session blob, assertion) pair must log in at most once, and
// editing the client-held blob (dropping "expires") must not resurrect it.
func TestFinishLoginRefusesAssertionReplay(t *testing.T) {
	t.Parallel()
	r, db := newRepoWithDB(t)
	who, k := seedNonCountingKey(t, db)
	session, edited, assertion := beginLogin(t, r, who, k)

	if err := finishLogin(r, who, session, assertion); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	for name, blob := range map[string][]byte{"original blob": session, "blob without expires": edited} {
		if err := finishLogin(r, who, blob, assertion); !errors.Is(err, webauthn.ErrSessionMissing) {
			t.Errorf("replay with %s: err = %v, want ErrSessionMissing", name, err)
		}
	}
}

// The challenge's lifetime and owner are the server's record, not the
// client blob's: an expired challenge or one issued to another admin is
// refused, and a failed attempt burns the challenge.
func TestFinishLoginChallengeIsServerBound(t *testing.T) {
	t.Parallel()
	base, db := newRepoWithDB(t)
	now := time.Now()
	r := base.WithClock(func() time.Time { return now })
	who, k := seedNonCountingKey(t, db)

	_, edited, assertion := beginLogin(t, r, who, k)
	now = now.Add(time.Hour)
	if err := finishLogin(r, who, edited, assertion); !errors.Is(err, webauthn.ErrSessionMissing) {
		t.Errorf("expired challenge: err = %v, want ErrSessionMissing", err)
	}

	_, edited, assertion = beginLogin(t, r, who, k)
	other := webauthn.AdminIdentity{ID: who.ID + 1, Email: "other@sealkeeper.test"}
	if err := finishLogin(r, other, edited, assertion); !errors.Is(err, webauthn.ErrSessionMissing) {
		t.Errorf("challenge redeemed by another admin: err = %v, want ErrSessionMissing", err)
	}
	if err := finishLogin(r, who, edited, assertion); !errors.Is(err, webauthn.ErrSessionMissing) {
		t.Errorf("challenge reused after a failed attempt: err = %v, want ErrSessionMissing", err)
	}

	_, edited, assertion = beginLogin(t, r, who, k)
	if err := finishLogin(r, who, edited, assertion); err != nil {
		t.Errorf("fresh challenge: %v", err)
	}
}

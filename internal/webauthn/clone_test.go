package webauthn_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

const (
	testRPID   = "sealkeeper.test"
	testOrigin = "https://sealkeeper.test"
)

// softKey is a software P-256 authenticator holding one credential.
type softKey struct {
	priv *ecdsa.PrivateKey
	id   []byte
}

func newSoftKey(t *testing.T) softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return softKey{priv: priv, id: id}
}

// coseKey hand-encodes the EC2 / ES256 COSE_Key as CBOR:
// {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
func (k softKey) coseKey() []byte {
	pub, err := k.priv.PublicKey.Bytes() // 0x04 || x || y
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	b.Write([]byte{0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01})
	b.Write([]byte{0x21, 0x58, 0x20})
	b.Write(pub[1:33])
	b.Write([]byte{0x22, 0x58, 0x20})
	b.Write(pub[33:65])
	return b.Bytes()
}

// assertion builds the JSON body a browser posts to finish a login,
// signed with the given signature counter.
func (k softKey) assertion(t *testing.T, challenge string, counter uint32) []byte {
	t.Helper()
	return k.assertionWithFlags(t, challenge, counter, 0x05) // user present + user verified
}

// assertionWithFlags is assertion with explicit authenticator-data flags.
func (k softKey) assertionWithFlags(t *testing.T, challenge string, counter uint32, flags byte) []byte {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    testOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(testRPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, counter)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    enc(k.id),
		"rawId": enc(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    enc(clientData),
			"authenticatorData": enc(authData),
			"signature":         enc(sig),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newRepoWithDB(t *testing.T) (*webauthn.Repo, *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: storagetest.DSN(t)})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	repo, err := webauthn.NewRepo(s.DB(), webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "SealKeeper test",
		Origins:       []string{testOrigin},
	})
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}
	return repo, s.DB()
}

// login runs BeginLogin + FinishLogin with an assertion carrying counter.
func login(t *testing.T, r *webauthn.Repo, who webauthn.AdminIdentity, k softKey, counter uint32) (webauthn.Credential, error) {
	t.Helper()
	ctx := context.Background()
	_, session, err := r.BeginLogin(ctx, who)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var sd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(session, &sd); err != nil {
		t.Fatalf("session: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/login/webauthn/finish",
		bytes.NewReader(k.assertion(t, sd.Challenge, counter)))
	req.Header.Set("Content-Type", "application/json")
	return r.FinishLogin(ctx, who, session, req)
}

// SK-27: an assertion whose signature counter does not move forward from
// the stored value is the WebAuthn clone signal. go-webauthn only flags
// it, so FinishLogin must refuse it.
func TestFinishLoginRefusesCounterRollback(t *testing.T) {
	t.Parallel()
	r, db := newRepoWithDB(t)
	ctx := context.Background()
	adminID, err := storage.InsertReturningID(ctx, db,
		`INSERT INTO admins (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"ops@sealkeeper.test", "x", time.Now().UTC(), time.Now().UTC())
	if err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	k := newSoftKey(t)
	credID := base64.RawURLEncoding.EncodeToString(k.id)
	if _, err := db.ExecContext(ctx, storage.Rebind(db,
		`INSERT INTO admin_webauthn_credentials (credential_id, admin_id, public_key, sign_count, created_at)
		 VALUES (?, ?, ?, ?, ?)`),
		credID, adminID, k.coseKey(), 100, time.Now().UTC()); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	who := webauthn.AdminIdentity{ID: adminID, Email: "ops@sealkeeper.test"}

	// A counter that moves forward is accepted and stored.
	cred, err := login(t, r, who, k, 101)
	if err != nil {
		t.Fatalf("login with counter 101: %v", err)
	}
	if cred.SignCount != 101 {
		t.Errorf("SignCount = %d, want 101", cred.SignCount)
	}

	// Going backwards, or replaying the same value, is refused.
	for _, counter := range []uint32{5, 101} {
		cred, err = login(t, r, who, k, counter)
		if !errors.Is(err, webauthn.ErrCloneDetected) {
			t.Fatalf("login with counter %d: err = %v, want ErrCloneDetected", counter, err)
		}
		if cred.CredentialID != credID {
			t.Errorf("CredentialID = %q, want %q for the audit trail", cred.CredentialID, credID)
		}
	}
	var stored int64
	if err := db.QueryRowContext(ctx, storage.Rebind(db,
		`SELECT sign_count FROM admin_webauthn_credentials WHERE credential_id = ?`), credID).Scan(&stored); err != nil {
		t.Fatalf("read sign_count: %v", err)
	}
	if stored != 101 {
		t.Errorf("stored sign_count = %d, want 101 (a refused assertion must not move it)", stored)
	}
}

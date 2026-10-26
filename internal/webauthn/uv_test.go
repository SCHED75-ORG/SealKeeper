package webauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

// attestation builds the JSON body a browser posts to finish a
// registration: a "none"-format attestation object over authenticator data
// carrying the given flags (0x01 user present, 0x04 user verified, 0x40
// attested credential data).
func (k softKey) attestation(t *testing.T, challenge string, flags byte) []byte {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.create",
		"challenge": challenge,
		"origin":    testOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(testRPID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, flags|0x40)
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(k.id)))
	authData = append(authData, k.id...)
	authData = append(authData, k.coseKey()...)

	// CBOR {"fmt": "none", "attStmt": {}, "authData": h'...'}
	var att bytes.Buffer
	att.WriteByte(0xA3)
	att.WriteString("\x63fmt\x64none")
	att.WriteString("\x67attStmt\xA0")
	att.WriteString("\x68authData\x59")
	att.Write(binary.BigEndian.AppendUint16(nil, uint16(len(authData))))
	att.Write(authData)

	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    enc(k.id),
		"rawId": enc(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    enc(clientData),
			"attestationObject": enc(att.Bytes()),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func challengeOf(t *testing.T, session []byte) string {
	t.Helper()
	var sd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(session, &sd); err != nil {
		t.Fatalf("session: %v", err)
	}
	return sd.Challenge
}

func postJSON(path string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, testOrigin+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// Registration asks the authenticator for user verification, does not ask
// for a discoverable credential (the step-up always names the allowed
// credentials) and asks for no attestation.
func TestBeginRegistrationOptions(t *testing.T) {
	t.Parallel()
	r, _ := newRepoWithDB(t)
	options, _, err := r.BeginRegistration(context.Background(),
		webauthn.AdminIdentity{ID: 1, Email: "ops@sealkeeper.test"}, "key")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	var got struct {
		PublicKey struct {
			Attestation            string `json:"attestation"`
			AuthenticatorSelection struct {
				UserVerification   string `json:"userVerification"`
				ResidentKey        string `json:"residentKey"`
				RequireResidentKey *bool  `json:"requireResidentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &got); err != nil {
		t.Fatal(err)
	}
	sel := got.PublicKey.AuthenticatorSelection
	if sel.UserVerification != "required" {
		t.Errorf("userVerification = %q, want required", sel.UserVerification)
	}
	if sel.ResidentKey != "discouraged" || sel.RequireResidentKey == nil || *sel.RequireResidentKey {
		t.Errorf("residentKey = %q, requireResidentKey = %v, want discouraged / false", sel.ResidentKey, sel.RequireResidentKey)
	}
	if got.PublicKey.Attestation != "none" {
		t.Errorf("attestation = %q, want none", got.PublicKey.Attestation)
	}
}

// A key enrolled as a second factor must prove user verification (PIN,
// biometric): a bare touch would make a stolen key enough on its own.
// The session's userVerification is round-tripped through the browser, so
// it must not be what decides.
func TestFinishRegistrationRequiresUserVerification(t *testing.T) {
	t.Parallel()
	r, db := newRepoWithDB(t)
	ctx := context.Background()
	adminID, err := storage.InsertReturningID(ctx, db,
		`INSERT INTO admins (email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"ops@sealkeeper.test", "x", time.Now().UTC(), time.Now().UTC())
	if err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	who := webauthn.AdminIdentity{ID: adminID, Email: "ops@sealkeeper.test"}

	register := func(flags byte, tamper bool) error {
		_, session, err := r.BeginRegistration(ctx, who, "key")
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		if tamper {
			var sd map[string]any
			if err := json.Unmarshal(session, &sd); err != nil {
				t.Fatal(err)
			}
			sd["userVerification"] = "discouraged"
			if session, err = json.Marshal(sd); err != nil {
				t.Fatal(err)
			}
		}
		k := newSoftKey(t)
		_, err = r.FinishRegistration(ctx, who, "key", session,
			postJSON("/admin/security/finish", k.attestation(t, challengeOf(t, session), flags)))
		return err
	}

	if err := register(0x05, false); err != nil {
		t.Fatalf("registration with UV: %v", err)
	}
	for _, tamper := range []bool{false, true} {
		if err := register(0x01, tamper); err == nil {
			t.Errorf("registration without UV (tampered session %v) accepted", tamper)
		}
	}
	creds, err := r.List(ctx, adminID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Errorf("stored %d credentials, want only the user-verified one", len(creds))
	}
}

// The login step-up replaces TOTP: an assertion without the UV flag is
// "something you have" only and must be refused, even when the session
// blob claims UV was not required.
func TestFinishLoginRequiresUserVerification(t *testing.T) {
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
		credID, adminID, k.coseKey(), 0, time.Now().UTC()); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
	who := webauthn.AdminIdentity{ID: adminID, Email: "ops@sealkeeper.test"}

	options, _, err := r.BeginLogin(ctx, who)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var opts struct {
		PublicKey struct {
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatal(err)
	}
	if opts.PublicKey.UserVerification != "required" {
		t.Errorf("assertion userVerification = %q, want required", opts.PublicKey.UserVerification)
	}

	counter := uint32(1)
	for _, tamper := range []bool{false, true} {
		_, session, err := r.BeginLogin(ctx, who)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		if tamper {
			var sd map[string]any
			if err := json.Unmarshal(session, &sd); err != nil {
				t.Fatal(err)
			}
			sd["userVerification"] = "discouraged"
			if session, err = json.Marshal(sd); err != nil {
				t.Fatal(err)
			}
		}
		_, err = r.FinishLogin(ctx, who, session, postJSON("/admin/login/webauthn/finish",
			k.assertionWithFlags(t, challengeOf(t, session), counter, 0x01)))
		counter++
		if err == nil {
			t.Errorf("assertion without UV (tampered session %v) accepted", tamper)
		}
	}
	var stored int64
	if err := db.QueryRowContext(ctx, storage.Rebind(db,
		`SELECT sign_count FROM admin_webauthn_credentials WHERE credential_id = ?`), credID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Errorf("sign_count = %d, a refused assertion must not move it", stored)
	}
	_, session, err := r.BeginLogin(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.FinishLogin(ctx, who, session, postJSON("/admin/login/webauthn/finish",
		k.assertionWithFlags(t, challengeOf(t, session), counter, 0x05))); err != nil {
		t.Errorf("assertion with UV: %v", err)
	}
}

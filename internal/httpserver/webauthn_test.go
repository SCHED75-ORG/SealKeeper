package httpserver

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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/webauthn"
)

const waOrigin = "http://sk.test"

// waKey is a software P-256 authenticator that always reports user
// presence + user verification.
type waKey struct {
	priv *ecdsa.PrivateKey
	id   []byte
}

func newWAKey(t *testing.T) waKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return waKey{priv: priv, id: id}
}

func (k waKey) authData(counter uint32, attested bool) []byte {
	rpHash := sha256.Sum256([]byte("sk.test"))
	d := append([]byte{}, rpHash[:]...)
	flags := byte(0x05)
	if attested {
		flags |= 0x40
	}
	d = append(d, flags)
	d = binary.BigEndian.AppendUint32(d, counter)
	if !attested {
		return d
	}
	pub, _ := k.priv.PublicKey.Bytes()
	d = append(d, make([]byte, 16)...)
	d = binary.BigEndian.AppendUint16(d, uint16(len(k.id)))
	d = append(d, k.id...)
	d = append(d, 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20)
	d = append(d, pub[1:33]...)
	d = append(d, 0x22, 0x58, 0x20)
	return append(d, pub[33:65]...)
}

func clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": waOrigin})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k waKey) attestation(t *testing.T, challenge string) []byte {
	t.Helper()
	ad := k.authData(0, true)
	var att bytes.Buffer
	att.WriteString("\xA3\x63fmt\x64none\x67attStmt\xA0\x68authData\x59")
	att.Write(binary.BigEndian.AppendUint16(nil, uint16(len(ad))))
	att.Write(ad)
	enc := base64.RawURLEncoding.EncodeToString
	b, _ := json.Marshal(map[string]any{
		"id": enc(k.id), "rawId": enc(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    enc(clientData(t, "webauthn.create", challenge)),
			"attestationObject": enc(att.Bytes()),
		},
	})
	return b
}

func (k waKey) assertion(t *testing.T, challenge string, counter uint32) []byte {
	t.Helper()
	ad := k.authData(counter, false)
	cd := clientData(t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	b, _ := json.Marshal(map[string]any{
		"id": enc(k.id), "rawId": enc(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    enc(cd),
			"authenticatorData": enc(ad),
			"signature":         enc(sig),
		},
	})
	return b
}

func challengeFromOptions(t *testing.T, options []byte) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatalf("options: %v (%s)", err, options)
	}
	return o.PublicKey.Challenge
}

func newWebauthnServer(t *testing.T) (*Server, *webauthn.Repo, *admin.Repo, *sql.DB) {
	t.Helper()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	wa, err := webauthn.NewRepo(db, webauthn.Config{RPID: "sk.test", RPDisplayName: "test", Origins: []string{waOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	s.SetWebauthn(wa)
	return s, wa, repo, db
}

func enrolFinish(h http.Handler, sess admin.Session, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/admin/security/finish", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", sess.CSRFToken)
	r.AddCookie(&http.Cookie{Name: cookieAdminSession, Value: sess.Token})
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func responseCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Value != "" {
			out = append(out, c)
		}
	}
	return out
}

// /admin/security/begin demands the current password; /finish must not be
// reachable without it. The ceremony session cookie used to be the raw
// JSON blob, so a hijacked admin session could mint its own (challenge,
// user handle, UV requirement) and enrol an attacker key at /finish
// without ever passing the password step-up.
func TestWebauthnEnrolFinishRefusesForgedSession(t *testing.T) {
	t.Parallel()
	s, wa, repo, db := newWebauthnServer(t)
	sess := adminSessionFor(t, repo, db)
	h := s.Router()
	ctx := context.Background()
	who := webauthn.AdminIdentity{ID: sess.AdminID, Email: "ops@example.test"}

	// Forged: a ceremony session the server never handed out.
	options, session, err := wa.BeginRegistration(ctx, who, "attacker")
	if err != nil {
		t.Fatal(err)
	}
	w := enrolFinish(h, sess, newWAKey(t).attestation(t, challengeFromOptions(t, options)),
		&http.Cookie{Name: cookieWebauthnSession, Value: base64.RawURLEncoding.EncodeToString(session)},
		&http.Cookie{Name: cookieWebauthnSession + "_name", Value: base64.RawURLEncoding.EncodeToString([]byte("attacker"))})
	if w.Code != http.StatusBadRequest {
		t.Errorf("forged session: status %d, want 400 (body %q)", w.Code, w.Body.String())
	}
	if creds, _ := wa.List(ctx, sess.AdminID); len(creds) != 0 {
		t.Fatalf("forged session enrolled %d credential(s)", len(creds))
	}

	// Genuine: begin with the current password, then finish.
	w = adminPOST(h, sess, "/admin/security/begin", url.Values{
		"friendly_name": {"yubikey"}, "current_password": {"supersecret-12chars"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("begin: status %d (%s)", w.Code, w.Body.String())
	}
	cookies := responseCookies(w)
	challenge := challengeFromOptions(t, w.Body.Bytes())

	// The genuine cookies cannot be replayed under another admin session.
	other, err := repo.CreateSession(ctx, sess.AdminID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if w := enrolFinish(h, other, newWAKey(t).attestation(t, challenge), cookies...); w.Code != http.StatusBadRequest {
		t.Errorf("session from another admin session: status %d, want 400", w.Code)
	}

	// Nor can the friendly name be swapped after the password check.
	swapped := []*http.Cookie{}
	for _, c := range cookies {
		if c.Name == cookieWebauthnSession+"_name" {
			c = &http.Cookie{Name: c.Name, Value: base64.RawURLEncoding.EncodeToString([]byte("renamed"))}
		}
		swapped = append(swapped, c)
	}
	if w := enrolFinish(h, sess, newWAKey(t).attestation(t, challenge), swapped...); w.Code != http.StatusBadRequest {
		t.Errorf("swapped friendly name: status %d, want 400", w.Code)
	}

	if w := enrolFinish(h, sess, newWAKey(t).attestation(t, challenge), cookies...); w.Code != http.StatusOK {
		t.Fatalf("genuine finish: status %d (%s)", w.Code, w.Body.String())
	}
	creds, err := wa.List(ctx, sess.AdminID)
	if err != nil || len(creds) != 1 || creds[0].FriendlyName != "yubikey" || !creds[0].UserVerified {
		t.Fatalf("after genuine enrolment: %+v, %v", creds, err)
	}
}

func loginFinish(h http.Handler, pending, csrf string, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/admin/login/webauthn/finish?csrf_token="+url.QueryEscape(csrf), bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: cookieAdminLoginStep, Value: pending})
	r.AddCookie(&http.Cookie{Name: cookieLoginCSRF, Value: csrf})
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The login assertion session is round-tripped the same way; a forged one
// lets the client pick the challenge (replaying an assertion captured
// earlier) and drop the UV requirement.
func TestWebauthnLoginFinishRefusesForgedSession(t *testing.T) {
	t.Parallel()
	s, wa, repo, db := newWebauthnServer(t)
	sess := adminSessionFor(t, repo, db)
	h := s.Router()
	ctx := context.Background()
	who := webauthn.AdminIdentity{ID: sess.AdminID, Email: "ops@example.test"}

	// Enrol a key through the real handlers.
	k := newWAKey(t)
	w := adminPOST(h, sess, "/admin/security/begin", url.Values{
		"friendly_name": {"yubikey"}, "current_password": {"supersecret-12chars"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("begin: status %d", w.Code)
	}
	if w := enrolFinish(h, sess, k.attestation(t, challengeFromOptions(t, w.Body.Bytes())), responseCookies(w)...); w.Code != http.StatusOK {
		t.Fatalf("enrol: status %d (%s)", w.Code, w.Body.String())
	}

	pending, _, err := s.loginPending.Issue(sess.AdminID)
	if err != nil {
		t.Fatal(err)
	}
	const csrf = "login-csrf-token"

	options, session, err := wa.BeginLogin(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	w = loginFinish(h, pending, csrf, k.assertion(t, challengeFromOptions(t, options), 1),
		&http.Cookie{Name: cookieAdminLoginAssertion, Value: base64.RawURLEncoding.EncodeToString(session)})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("forged assertion session: status %d, want 400 (body %q)", w.Code, w.Body.String())
	}

	// Genuine: begin through the handler, then finish.
	br := httptest.NewRequest(http.MethodPost, "/admin/login/webauthn/begin",
		strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	br.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	br.AddCookie(&http.Cookie{Name: cookieAdminLoginStep, Value: pending})
	br.AddCookie(&http.Cookie{Name: cookieLoginCSRF, Value: csrf})
	bw := httptest.NewRecorder()
	h.ServeHTTP(bw, br)
	if bw.Code != http.StatusOK {
		t.Fatalf("login begin: status %d", bw.Code)
	}
	w = loginFinish(h, pending, csrf, k.assertion(t, challengeFromOptions(t, bw.Body.Bytes()), 2), responseCookies(bw)...)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "redirect") {
		t.Fatalf("genuine login finish: status %d (%s)", w.Code, w.Body.String())
	}
}

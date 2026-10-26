package httpserver

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/tokens"
)

func countTokens(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM request_tokens").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Regression: POST /api/v1/request accepted cross-origin "simple requests"
// (text/plain, no preflight), so any website could make its visitors'
// browsers mint reveal links from their own IPs.
func TestRequestRefusesCrossSiteAndNonJSON(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	s.requestFloor = 0
	h := s.Router()

	cases := []struct {
		name    string
		ctype   string
		headers map[string]string
		want    int
	}{
		{name: "text/plain simple request", ctype: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "no content type", ctype: "", want: http.StatusUnsupportedMediaType},
		{name: "form encoded", ctype: "application/x-www-form-urlencoded", want: http.StatusUnsupportedMediaType},
		{name: "cross-site fetch metadata", ctype: "application/json", headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, want: http.StatusForbidden},
		{name: "same-site sibling", ctype: "application/json", headers: map[string]string{"Sec-Fetch-Site": "same-site"}, want: http.StatusForbidden},
		{name: "foreign origin without fetch metadata", ctype: "application/json", headers: map[string]string{"Origin": "https://evil.example"}, want: http.StatusForbidden},
		{name: "text/plain from a foreign origin", ctype: "text/plain", headers: map[string]string{"Origin": "https://evil.example"}, want: http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"victim@example.test"}`))
			if c.ctype != "" {
				r.Header.Set("Content-Type", c.ctype)
			}
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status=%d body=%q, want %d", w.Code, w.Body.String(), c.want)
			}
		})
	}
	if n := countTokens(t, repo.DB()); n != 0 {
		t.Fatalf("%d tokens minted by refused requests", n)
	}

	// The landing page's same-origin fetch, and non-browser JSON clients,
	// still get the FR-B.13 202.
	for _, hdr := range []map[string]string{
		{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"},
		{"Origin": "http://example.com"},
		{},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/request", strings.NewReader(`{"email":"user@example.test"}`))
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusAccepted {
			t.Fatalf("headers %v: status=%d body=%q, want 202", hdr, w.Code, w.Body.String())
		}
	}
}

// Regression: /reveal/{token} and /api/v1/policy?token= told unknown,
// expired and consumed tokens apart with no rate limit at all.
func TestTokenLookupsAreRateLimitedPerIP(t *testing.T) {
	t.Parallel()
	s, repo := newAdminServer(t)
	tr := tokens.NewRepo(repo.DB())
	s.SetTokens(tr)
	h := s.Router()

	get := func(path, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const attacker = "203.0.113.9:4000"
	for i := 0; i < tokenLookupPerIPWindow; i++ {
		path := "/reveal/probe"
		if i%2 == 1 {
			path = "/api/v1/policy?token=probe"
		}
		if w := get(path, attacker); w.Code == http.StatusTooManyRequests {
			t.Fatalf("lookup %d rate-limited before the cap", i)
		}
	}
	if w := get("/reveal/probe", attacker); w.Code != http.StatusTooManyRequests {
		t.Fatalf("reveal page: status=%d, want 429 past the cap", w.Code)
	}

	// A limited policy fetch must not burn a valid token.
	tok, err := tr.Issue(context.Background(), tokens.IssueOptions{Email: "user@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	w := get("/api/v1/policy?token="+tok.Token, attacker)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("policy: status=%d retry-after=%q, want 429 + Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if got, _ := tr.Get(context.Background(), tok.Token); got.ConsumedAt != nil {
		t.Fatal("rate-limited policy fetch consumed the token")
	}

	// Other clients and the token-less policy document are unaffected.
	if w := get("/api/v1/policy?token="+tok.Token, "198.51.100.4:4000"); w.Code != http.StatusOK {
		t.Fatalf("other IP: status=%d, want 200", w.Code)
	}
	if w := get("/api/v1/policy", attacker); w.Code != http.StatusOK {
		t.Fatalf("token-less policy: status=%d, want 200", w.Code)
	}
}

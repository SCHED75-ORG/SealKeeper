package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/config"
	"github.com/sched75/sealkeeper/internal/cryptobox"
	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/smtpconfig"
)

// Regression: /admin/smtp/save reassigned Server.sender while
// POST /api/v1/request read it on other goroutines. Run with -race.
func TestSMTPSaveDoesNotRaceRequests(t *testing.T) {
	t.Parallel()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	s.requestFloor = 0
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	box, err := cryptobox.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	s.SetSMTPConfig(smtpconfig.NewRepo(db, box))
	if _, err := domains.NewRepo(db).Create(context.Background(), "example.test", "", true, nil); err != nil {
		t.Fatal(err)
	}
	sess := adminSessionFor(t, repo, db)
	h := s.Router()

	const rounds = 20
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range rounds {
			w := adminPOST(h, sess, "/admin/smtp/save", url.Values{
				// Port 1 on loopback: background sends fail fast.
				"host":            {"127.0.0.1"},
				"port":            {"1"},
				"from_addr":       {"noreply@sk.test"},
				"tls_mode":        {"disable"},
				"timeout_seconds": {"1"},
				"password":        {fmt.Sprintf("pw-%d", i)},
			})
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/smtp?ok=saved" {
				t.Errorf("save %d: %d %q", i, w.Code, w.Header().Get("Location"))
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := range rounds {
			remote := fmt.Sprintf("192.0.2.%d:1000", 20+i)
			if w := postRequest(h, remote, fmt.Sprintf("u%d@example.test", i)); w.Code != http.StatusAccepted {
				t.Errorf("request %d: %d", i, w.Code)
				return
			}
		}
	}()
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.WaitMail(ctx)
	if got := s.currentSender().Name(); got != "smtp" {
		t.Fatalf("active sender = %q, want smtp after the saves", got)
	}
}

package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/admin"
	"github.com/sched75/sealkeeper/internal/config"
)

// Regression (SK-04 follow-up): the admin-management handlers had no
// current-password step-up, so a stolen session cookie alone could mint
// a new admin (its one-time password came back in the response), sign in
// with it, and disable or delete the real operator.
func TestAdminsManagementRequiresCurrentPassword(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, repo, db := newModeServer(t, config.ModeProduction, false)
	sess := adminSessionFor(t, repo, db) // ops@example.test / supersecret-12chars
	h := s.Router()

	victim, err := repo.Create(ctx, "victim@example.test", "victim-password-12")
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(victim.ID, 10)

	// Two failures per password keep the operator below the lockout threshold.
	for i, pwd := range []string{"", "wrong-password-123"} {
		form := url.Values{"email": {"evil@attacker.test"}}
		if pwd != "" {
			form.Set("current_password", pwd)
		}
		w := adminPOST(h, sess, "/admin/admins/add", form)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/admins?err=current_password" {
			t.Errorf("add with %q: %d %q, want 303 err=current_password", pwd, w.Code, w.Header().Get("Location"))
		}
		if strings.Contains(w.Body.String(), "bootstrap-password") {
			t.Errorf("add with %q leaked a bootstrap password", pwd)
		}
		if _, err := repo.FindByEmail(ctx, "evil@attacker.test"); !errors.Is(err, admin.ErrNotFound) {
			t.Fatalf("add with %q created the admin (err=%v)", pwd, err)
		}

		if i == 0 {
			w = adminPOST(h, sess, "/admin/admins/"+id+"/toggle", url.Values{"current_password": {pwd}})
			if w.Header().Get("Location") != "/admin/admins?err=current_password" {
				t.Errorf("toggle with %q: %q, want err=current_password", pwd, w.Header().Get("Location"))
			}
		} else {
			w = adminPOST(h, sess, "/admin/admins/"+id+"/delete", url.Values{
				"confirm": {victim.Email}, "current_password": {pwd},
			})
			if w.Header().Get("Location") != "/admin/admins?err=current_password" {
				t.Errorf("delete with %q: %q, want err=current_password", pwd, w.Header().Get("Location"))
			}
		}
		got, err := repo.FindByID(ctx, victim.ID)
		if err != nil || got.Disabled {
			t.Fatalf("victim after step-up failure with %q: disabled=%v err=%v", pwd, got.Disabled, err)
		}
	}

	// With the operator's password every action goes through.
	ok := "supersecret-12chars"
	w := adminPOST(h, sess, "/admin/admins/add", url.Values{"email": {"new@example.test"}, "current_password": {ok}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-testid="bootstrap-password"`) {
		t.Errorf("add with password: %d, want 200 with the bootstrap password", w.Code)
	}
	if _, err := repo.FindByEmail(ctx, "new@example.test"); err != nil {
		t.Errorf("add with password did not create the admin: %v", err)
	}
	w = adminPOST(h, sess, "/admin/admins/"+id+"/toggle", url.Values{"current_password": {ok}})
	if w.Header().Get("Location") != "/admin/admins?ok=toggled" {
		t.Errorf("toggle with password: %q", w.Header().Get("Location"))
	}
	w = adminPOST(h, sess, "/admin/admins/"+id+"/delete", url.Values{"confirm": {victim.Email}, "current_password": {ok}})
	if w.Header().Get("Location") != "/admin/admins?ok=deleted" {
		t.Errorf("delete with password: %q", w.Header().Get("Location"))
	}
}

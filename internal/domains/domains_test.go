package domains_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepo(t *testing.T) (*domains.Repo, storage.Store) {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return domains.NewRepo(s.DB()), s
}

// ----- Canonicalize ---------------------------------------------------------

func TestCanonicalizeAcceptsFQDNAndWildcard(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Example.COM":         "example.com",
		"  example.com  ":     "example.com",
		".example.com":        "example.com",
		"*.example.com":       "*.example.com",
		"*.SUB.example.COM":   "*.sub.example.com",
		"server-1.example.fr": "server-1.example.fr",
	}
	for in, want := range cases {
		got, err := domains.Canonicalize(in)
		if err != nil {
			t.Errorf("Canonicalize(%q) err: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Canonicalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalizeRejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "  ", "no-dot", "example", "example.*", "*.*", "host*.example.com", "example..com"} {
		if _, err := domains.Canonicalize(bad); !errors.Is(err, domains.ErrInvalidName) {
			t.Errorf("Canonicalize(%q) err = %v, want ErrInvalidName", bad, err)
		}
	}
}

// ----- CRUD + Allows --------------------------------------------------------

// Regression (SK-37): an empty table admitted every domain, production
// included. The default repo now fails closed.
func TestEmptyTableFailsClosedByDefault(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	if r.OpenWhenEmpty() {
		t.Fatal("NewRepo must default to fail-closed")
	}
	ok, err := r.Allows(context.Background(), "anything.test")
	if ok || !errors.Is(err, domains.ErrEmptyAllowlist) {
		t.Fatalf("Allows on empty table = %v, %v; want false, ErrEmptyAllowlist", ok, err)
	}
}

func TestEmptyTableOpenWhenOptedIn(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	open := r.WithOpenWhenEmpty(true)
	ok, err := open.Allows(context.Background(), "anything.test")
	if err != nil || !ok {
		t.Fatalf("Allows on empty open table = %v, %v; want true, nil", ok, err)
	}
	if r.OpenWhenEmpty() {
		t.Fatal("WithOpenWhenEmpty mutated the receiver")
	}
	// As soon as a row lands the list is the gate, open or not.
	if _, err := open.Create(context.Background(), "corp.test", "", true, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := open.Allows(context.Background(), "anything.test"); ok || err != nil {
		t.Fatalf("Allows unlisted with populated table = %v, %v; want false, nil", ok, err)
	}
}

func TestCreateAndAllowsExact(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "Example.com", "demo", true, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ok, err := r.Allows(ctx, "example.com")
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}
	if !ok {
		t.Fatal("exact match must allow")
	}
	ok, _ = r.Allows(ctx, "other.com")
	if ok {
		t.Fatal("other domain must be denied")
	}
}

func TestWildcardAllowsSubdomains(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "*.entreprise.com", "", true, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, d := range []string{"paris.entreprise.com", "fr.paris.entreprise.com"} {
		ok, _ := r.Allows(ctx, d)
		if !ok {
			t.Errorf("Allows(%q) = false, want true", d)
		}
	}
	// Bare apex NOT matched by wildcard alone.
	ok, _ := r.Allows(ctx, "entreprise.com")
	if ok {
		t.Error("bare apex must NOT be matched by *.entreprise.com alone")
	}
	// Sibling tree not matched.
	ok, _ = r.Allows(ctx, "evil.com")
	if ok {
		t.Error("sibling tree must NOT match")
	}
}

func TestDisableHidesFromAllows(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	d, _ := r.Create(ctx, "example.com", "", true, nil)
	ok, _ := r.Allows(ctx, "example.com")
	if !ok {
		t.Fatal("active should allow")
	}
	if err := r.SetActive(ctx, d.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	ok, _ = r.Allows(ctx, "example.com")
	if ok {
		t.Fatal("inactive must NOT allow")
	}
}

func TestDuplicateRejected(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	if _, err := r.Create(ctx, "example.com", "", true, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := r.Create(ctx, "Example.COM", "", true, nil)
	if !errors.Is(err, domains.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	_, _ = r.Create(ctx, "b.example.com", "", true, nil)
	_, _ = r.Create(ctx, "a.example.com", "", true, nil)
	list, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Name != "a.example.com" {
		t.Fatalf("List order/length wrong: %+v", list)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	d, _ := r.Create(ctx, "example.com", "", true, nil)
	if err := r.Delete(ctx, d.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.Get(ctx, d.ID); !errors.Is(err, domains.ErrNotFound) {
		t.Fatalf("post-delete Get err = %v, want ErrNotFound", err)
	}
}

func TestInvalidEmailDomainNeverAllowed(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	_, _ = r.Create(ctx, "example.com", "", true, nil)
	ok, _ := r.Allows(ctx, "")
	if ok {
		t.Fatal("empty input must NOT be allowed once table has entries")
	}
}

// ----- Import ---------------------------------------------------------------

func TestImportCreatesSkipsAndReports(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	// Seed one row so the dup branch is exercised.
	if _, err := r.Create(ctx, "example.com", "", true, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	csv := "name,description,active\n" +
		"example.com,,true\n" + // duplicate -> Skipped
		"new.example.com,fresh,true\n" + // -> Created
		"*.acme.test,wildcard,true\n" + // -> Created
		",empty,true\n" + // -> error (invalid name)
		"bad name,desc,false\n" // -> error (Canonicalize)
	sum, err := r.Import(ctx, strings.NewReader(csv), nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if sum.Created != 2 {
		t.Errorf("Created = %d, want 2", sum.Created)
	}
	if sum.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", sum.Skipped)
	}
	if len(sum.Errors) != 1 {
		t.Errorf("Errors = %d, want 1 (bad-name row), got: %+v", len(sum.Errors), sum.Errors)
	}
}

func TestImportHonoursActiveColumn(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	csv := "x.test,note,off\n"
	if _, err := r.Import(ctx, strings.NewReader(csv), nil); err != nil {
		t.Fatalf("Import: %v", err)
	}
	row, err := r.GetByName(ctx, "x.test")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if row.Active {
		t.Errorf("expected inactive, got active=true")
	}
}

// FR-C.23: FindMatchingIssued keeps a disabled domain resolvable for links
// already issued, while an active row (even a wildcard) still wins and
// FindMatching keeps refusing the disabled one.
func TestFindMatchingIssuedFallsBackToInactiveRow(t *testing.T) {
	t.Parallel()
	r, _ := newRepo(t)
	ctx := context.Background()
	exact, err := r.Create(ctx, "paris.corp.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetActive(ctx, exact.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.FindMatching(ctx, "paris.corp.test"); !errors.Is(err, domains.ErrNotFound) {
		t.Fatalf("FindMatching on a disabled row = %v, want ErrNotFound", err)
	}
	got, err := r.FindMatchingIssued(ctx, "paris.corp.test")
	if err != nil || got.ID != exact.ID {
		t.Fatalf("FindMatchingIssued = %+v, %v, want the disabled exact row", got, err)
	}

	wild, err := r.Create(ctx, "*.corp.test", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = r.FindMatchingIssued(ctx, "paris.corp.test")
	if err != nil || got.ID != wild.ID {
		t.Fatalf("FindMatchingIssued = %+v, %v, want the active wildcard first", got, err)
	}
	if _, err := r.FindMatchingIssued(ctx, "other.test"); !errors.Is(err, domains.ErrNotFound) {
		t.Fatalf("FindMatchingIssued(unknown) = %v, want ErrNotFound", err)
	}
}

package elevations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

func newRepos(t *testing.T) (*elevations.Repo, *domains.Repo) {
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
	return elevations.NewRepo(s.DB()), domains.NewRepo(s.DB())
}

func TestCreateAndLookup(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	_, err := er.Create(ctx, d.ID, "Alice@Example.com", elevations.LevelB2, "manager", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	lvl, err := er.Lookup(ctx, d.ID, "alice@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if lvl != elevations.LevelB2 {
		t.Errorf("level = %q, want B2", lvl)
	}
}

func TestLookupUnknown(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	d, _ := dr.Create(context.Background(), "example.com", "", true, nil)
	lvl, err := er.Lookup(context.Background(), d.ID, "missing@example.com")
	if !errors.Is(err, elevations.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if lvl != elevations.LevelB1 {
		t.Errorf("default level = %q, want B1", lvl)
	}
}

func TestInvalidLevelRejected(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	d, _ := dr.Create(context.Background(), "example.com", "", true, nil)
	if _, err := er.Create(context.Background(), d.ID, "x@example.com", elevations.Level("B5"), "", nil); !errors.Is(err, elevations.ErrInvalidLevel) {
		t.Fatalf("err = %v, want ErrInvalidLevel", err)
	}
}

func TestDuplicateRejected(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	if _, err := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB2, "", nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// FR-C.39: an email is in at most one list — second Create rejected
	// regardless of level.
	if _, err := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB3, "", nil); !errors.Is(err, elevations.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestListPerDomain(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	a, _ := dr.Create(ctx, "a.test", "", true, nil)
	b, _ := dr.Create(ctx, "b.test", "", true, nil)
	_, _ = er.Create(ctx, a.ID, "x@a.test", elevations.LevelB2, "", nil)
	_, _ = er.Create(ctx, b.ID, "y@b.test", elevations.LevelB3, "", nil)
	listA, _ := er.List(ctx, a.ID)
	if len(listA) != 1 || listA[0].Email != "x@a.test" {
		t.Errorf("listA = %+v", listA)
	}
	all, _ := er.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("ListAll = %d, want 2", len(all))
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	d, _ := dr.Create(ctx, "example.com", "", true, nil)
	e, _ := er.Create(ctx, d.ID, "x@example.com", elevations.LevelB2, "", nil)
	if err := er.Delete(ctx, e.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := er.Get(ctx, e.ID); !errors.Is(err, elevations.ErrNotFound) {
		t.Errorf("post-delete Get err = %v, want ErrNotFound", err)
	}
}

// ----- Import ---------------------------------------------------------------

func TestImportRoundTrip(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	dom, err := dr.Create(ctx, "example.com", "", true, nil)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	resolver := func(ctx context.Context, name string) (int64, error) {
		row, err := dr.GetByName(ctx, name)
		if err != nil {
			return 0, err
		}
		return row.ID, nil
	}
	// Seed one row to exercise the dup branch.
	if _, err := er.Create(ctx, dom.ID, "boss@example.com", elevations.LevelB3, "", nil); err != nil {
		t.Fatalf("seed elevation: %v", err)
	}
	csv := "domain,email,level,reason\n" +
		"example.com,boss@example.com,B3,already-here\n" + // duplicate -> Skipped
		"example.com,sec@example.com,B2,security squad\n" + // -> Created
		"unknown.test,x@unknown.test,B2,\n" + // -> error (unknown domain)
		"example.com,bad@example.com,Z9,\n" + // -> error (invalid level)
		"example.com,,B2,\n" // -> error (empty email)
	sum, err := er.Import(ctx, strings.NewReader(csv), resolver, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if sum.Created != 1 {
		t.Errorf("Created = %d, want 1", sum.Created)
	}
	if sum.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", sum.Skipped)
	}
	if len(sum.Errors) != 3 {
		t.Errorf("Errors = %d, want 3; got %+v", len(sum.Errors), sum.Errors)
	}
}

func TestImportRequiresResolver(t *testing.T) {
	t.Parallel()
	er, _ := newRepos(t)
	_, err := er.Import(context.Background(), strings.NewReader("a,b,B2\n"), nil, nil)
	if err == nil {
		t.Fatal("Import without resolver must error")
	}
}

// TestCreateRefusesMisfiledEmail pins FR-C.39 and FR-C.24: an elevation
// must belong to its domain row (so the domain's cascade removes it) and
// an address sits on at most one list across every domain row.
func TestCreateRefusesMisfiledEmail(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	corp, _ := dr.Create(ctx, "corp.test", "", true, nil)
	other, _ := dr.Create(ctx, "other.test", "", true, nil)
	wild, _ := dr.Create(ctx, "*.corp.test", "", true, nil)

	if _, err := er.Create(ctx, other.ID, "alice@corp.test", elevations.LevelB3, "", nil); !errors.Is(err, elevations.ErrDomainMismatch) {
		t.Fatalf("cross-domain Create: err = %v, want ErrDomainMismatch", err)
	}
	if _, err := er.Create(ctx, wild.ID, "alice@corp.test", elevations.LevelB3, "", nil); !errors.Is(err, elevations.ErrDomainMismatch) {
		t.Fatalf("wildcard must not cover the bare domain: err = %v", err)
	}
	if _, err := er.Create(ctx, corp.ID, "not-an-email", elevations.LevelB2, "", nil); !errors.Is(err, elevations.ErrInvalidEmail) {
		t.Fatalf("malformed email: err = %v, want ErrInvalidEmail", err)
	}
	if _, err := er.Create(ctx, corp.ID, "Bob <bob@corp.test>", elevations.LevelB2, "", nil); !errors.Is(err, elevations.ErrInvalidEmail) {
		t.Fatalf("display-name email: err = %v, want ErrInvalidEmail", err)
	}
	if _, err := er.Create(ctx, wild.ID, "dev@paris.corp.test", elevations.LevelB2, "", nil); err != nil {
		t.Fatalf("wildcard descendant: %v", err)
	}
	if _, err := er.Create(ctx, corp.ID, " Alice@Corp.test ", elevations.LevelB2, "", nil); err != nil {
		t.Fatalf("legit Create: %v", err)
	}

	// Same address on a second list via another covering row: refused.
	paris, _ := dr.Create(ctx, "paris.corp.test", "", true, nil)
	if _, err := er.Create(ctx, paris.ID, "dev@paris.corp.test", elevations.LevelB3, "", nil); !errors.Is(err, elevations.ErrAlreadyExists) {
		t.Fatalf("second list for same email: err = %v, want ErrAlreadyExists", err)
	}

	if lvl, err := er.LookupEmail(ctx, "alice@corp.test"); err != nil || lvl != elevations.LevelB2 {
		t.Fatalf("LookupEmail = %s, %v; want B2", lvl, err)
	}
	if err := dr.Delete(ctx, corp.ID); err != nil {
		t.Fatal(err)
	}
	if lvl, err := er.LookupEmail(ctx, "alice@corp.test"); !errors.Is(err, elevations.ErrNotFound) {
		t.Fatalf("after domain delete LookupEmail = %s, %v; want ErrNotFound", lvl, err)
	}
}

func TestImportRefusesMisfiledEmail(t *testing.T) {
	t.Parallel()
	er, dr := newRepos(t)
	ctx := context.Background()
	_, _ = dr.Create(ctx, "corp.test", "", true, nil)
	_, _ = dr.Create(ctx, "other.test", "", true, nil)
	resolver := func(ctx context.Context, name string) (int64, error) {
		row, err := dr.GetByName(ctx, name)
		return row.ID, err
	}
	csv := "other.test,alice@corp.test,B3,\n" + // -> error (wrong domain)
		"corp.test,alice@corp.test,B2,\n" + // -> Created
		"corp.test,nope,B2,\n" // -> error (invalid email)
	sum, err := er.Import(ctx, strings.NewReader(csv), resolver, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if sum.Created != 1 || len(sum.Errors) != 2 {
		t.Fatalf("summary = %+v, want 1 created, 2 errors", sum)
	}
}

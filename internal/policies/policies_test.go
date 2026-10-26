package policies_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sched75/sealkeeper/internal/domains"
	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

type rigs struct {
	domains    *domains.Repo
	elevations *elevations.Repo
	policies   *policies.Repo
}

func newRig(t *testing.T) rigs {
	t.Helper()
	dsn := storagetest.DSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dsn})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	dr := domains.NewRepo(s.DB())
	er := elevations.NewRepo(s.DB())
	pr := policies.NewRepo(s.DB(), dr, er)
	return rigs{dr, er, pr}
}

// ----- Create + validation --------------------------------------------------

func TestCreateValidationFailures(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	d, _ := r.domains.Create(context.Background(), "example.com", "", true, nil)

	cases := []policies.CreateInputs{
		{DomainID: 0, ANSSILevel: elevations.LevelB1, Name: "x", Generator: policies.GeneratorG2},                             // missing domain
		{DomainID: d.ID, ANSSILevel: "BZ", Name: "x", Generator: policies.GeneratorG2},                                        // bad level
		{DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "x", Generator: "GZ"},                                          // bad gen
		{DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "", Generator: policies.GeneratorG2},                           // empty name
		{DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "x", Generator: policies.GeneratorG2, ParamsJSON: "{not json"}, // bad json
		{DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "x", Generator: policies.GeneratorG2, ParamsJSON: `[1,2,3]`},   // json but not object
	}
	for i, in := range cases {
		if _, err := r.policies.Create(context.Background(), in, nil); !errors.Is(err, policies.ErrInvalidShape) {
			t.Errorf("case %d: err = %v, want ErrInvalidShape", i, err)
		}
	}
}

func TestCreateUniquePerDomainLevel(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	d, _ := r.domains.Create(context.Background(), "example.com", "", true, nil)
	in := policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "default",
		Generator: policies.GeneratorG2, Active: true,
	}
	if _, err := r.policies.Create(context.Background(), in, nil); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := r.policies.Create(context.Background(), in, nil); !errors.Is(err, policies.ErrAlreadyExists) {
		t.Fatalf("second Create err = %v, want ErrAlreadyExists", err)
	}
}

// ----- Resolve --------------------------------------------------------------

func TestResolveNoDomainNoPolicy(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	if _, err := r.policies.Resolve(context.Background(), "ghost@unknown.test"); !errors.Is(err, policies.ErrNoPolicy) {
		t.Fatalf("Resolve unknown domain err = %v, want ErrNoPolicy", err)
	}
}

func TestResolveB1Default(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	d, _ := r.domains.Create(context.Background(), "example.com", "", true, nil)
	_, _ = r.policies.Create(context.Background(), policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1",
		Generator: policies.GeneratorG2, Active: true,
	}, nil)
	got, err := r.policies.Resolve(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ANSSILevel != elevations.LevelB1 {
		t.Errorf("level = %q, want B1", got.ANSSILevel)
	}
}

func TestResolveWildcardDomain(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	d, _ := r.domains.Create(context.Background(), "*.entreprise.com", "", true, nil)
	_, _ = r.policies.Create(context.Background(), policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1-wild",
		Generator: policies.GeneratorG2, Active: true,
	}, nil)
	got, err := r.policies.Resolve(context.Background(), "alice@paris.entreprise.com")
	if err != nil {
		t.Fatalf("Resolve wildcard: %v", err)
	}
	if got.Name != "B1-wild" {
		t.Errorf("name = %q, want B1-wild", got.Name)
	}
}

func TestResolveElevationPicksRightPolicy(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	_, _ = r.policies.Create(ctx, policies.CreateInputs{DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1", Generator: policies.GeneratorG2, Active: true}, nil)
	_, _ = r.policies.Create(ctx, policies.CreateInputs{DomainID: d.ID, ANSSILevel: elevations.LevelB2, Name: "B2", Generator: policies.GeneratorG2, Active: true}, nil)
	_, _ = r.policies.Create(ctx, policies.CreateInputs{DomainID: d.ID, ANSSILevel: elevations.LevelB3, Name: "B3", Generator: policies.GeneratorG3, Active: true}, nil)

	if _, err := r.elevations.Create(ctx, d.ID, "manager@example.com", elevations.LevelB2, "", nil); err != nil {
		t.Fatalf("create B2 elevation: %v", err)
	}
	if _, err := r.elevations.Create(ctx, d.ID, "root@example.com", elevations.LevelB3, "", nil); err != nil {
		t.Fatalf("create B3 elevation: %v", err)
	}

	cases := map[string]elevations.Level{
		"unknown@example.com": elevations.LevelB1,
		"manager@example.com": elevations.LevelB2,
		"root@example.com":    elevations.LevelB3,
	}
	for email, want := range cases {
		got, err := r.policies.Resolve(ctx, email)
		if err != nil {
			t.Errorf("Resolve(%q) err: %v", email, err)
			continue
		}
		if got.ANSSILevel != want {
			t.Errorf("Resolve(%q) = %q, want %q", email, got.ANSSILevel, want)
		}
	}
}

func TestResolveSkipsInactivePolicy(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	p, _ := r.policies.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1",
		Generator: policies.GeneratorG2, Active: true,
	}, nil)
	if err := r.policies.SetActive(ctx, p.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if _, err := r.policies.Resolve(ctx, "user@example.com"); !errors.Is(err, policies.ErrNoPolicy) {
		t.Fatalf("inactive policy err = %v, want ErrNoPolicy", err)
	}
}

func TestResolveElevationButNoMatchingPolicyDenies(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	// Only B1 policy exists; user elevated to B3 must be denied per FR-C.28.
	_, _ = r.policies.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "B1",
		Generator: policies.GeneratorG2, Active: true,
	}, nil)
	_, _ = r.elevations.Create(ctx, d.ID, "root@example.com", elevations.LevelB3, "", nil)
	if _, err := r.policies.Resolve(ctx, "root@example.com"); !errors.Is(err, policies.ErrNoPolicy) {
		t.Fatalf("err = %v, want ErrNoPolicy", err)
	}
}

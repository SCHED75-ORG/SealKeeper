package policies_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sched75/sealkeeper/internal/elevations"
	"github.com/sched75/sealkeeper/internal/policies"
)

// A policy routed as B3 used to save with parameters producing ~24-bit
// passwords: only the browser badge knew. Create and Update now refuse a
// policy whose entropy is below its ANSSI level floor (PRD A FR-A.G1.5,
// FR-A.G2.4, FR-A.G3.3: B1 ≥ 50, B2 ≥ 80, B3 ≥ 100 bits).
func TestCreateRefusesPolicyBelowLevelFloor(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	cases := []struct {
		name   string
		level  elevations.Level
		gen    policies.Generator
		params string
	}{
		{"B3 G3 length 4", elevations.LevelB3, policies.GeneratorG3, `{"length":4}`},
		{"B3 G3 length 16", elevations.LevelB3, policies.GeneratorG3, `{"length":16}`}, // 95.2 bits
		{"B2 G2 tiny dict", elevations.LevelB2, policies.GeneratorG2, `{"library":["alpha","bravo","charlie","delta"]}`},
		{"B1 G2 two words", elevations.LevelB1, policies.GeneratorG2, `{"library":["a","b"]}`},
		{"B1 G1 two citations", elevations.LevelB1, policies.GeneratorG1,
			`{"library":["veni vidi vici","alea jacta est"],"numericGroups":[]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.policies.Create(ctx, policies.CreateInputs{
				DomainID: d.ID, ANSSILevel: c.level, Name: c.name, Generator: c.gen, ParamsJSON: c.params,
			}, nil)
			if !errors.Is(err, policies.ErrBelowFloor) {
				t.Fatalf("err = %v, want ErrBelowFloor", err)
			}
		})
	}
}

func TestCreateAcceptsPolicyAtLevelFloor(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	// 17 × log2(62) = 101.2 bits: clears B3.
	if _, err := r.policies.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB3, Name: "b3", Generator: policies.GeneratorG3,
		ParamsJSON: `{"length":17}`,
	}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

// Update keeps the row's stored level (the form's anssi_level is not
// persisted), so the floor is the stored level's, whatever the form claims.
func TestUpdateRefusesPolicyBelowStoredLevelFloor(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	ctx := context.Background()
	d, _ := r.domains.Create(ctx, "example.com", "", true, nil)
	p, err := r.policies.Create(ctx, policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB3, Name: "b3", Generator: policies.GeneratorG3, Active: true,
	}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	weak := policies.CreateInputs{
		DomainID: d.ID, ANSSILevel: elevations.LevelB1, Name: "b3", Generator: policies.GeneratorG3,
		ParamsJSON: `{"length":10}`, // 59.5 bits: B1 yes, B3 no
		Active:     true,
	}
	if err := r.policies.Update(ctx, p.ID, weak); !errors.Is(err, policies.ErrBelowFloor) {
		t.Fatalf("Update err = %v, want ErrBelowFloor", err)
	}
	got, _ := r.policies.Get(ctx, p.ID)
	if string(got.Params) != "{}" {
		t.Fatalf("params changed to %s despite the refusal", got.Params)
	}
}

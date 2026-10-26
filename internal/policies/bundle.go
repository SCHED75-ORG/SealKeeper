package policies

import (
	"encoding/json"
	"fmt"
)

// The reveal bundle (web/src/params.js) refuses a descriptor with
// InvalidPolicyDescriptor / LibraryNotFound before generating anything.
// Parameter validation is shared with the entropy port in entropy.go, which
// mirrors params.js; this file only adds the descriptor's top-level bounds.
// Keep both in lockstep with params.js.

const (
	maxProposals  = 50
	maxRegenerate = 100
)

// ValidateForReveal reports whether the reveal bundle would accept p, as
// served by the policy endpoint. A non-nil error wraps ErrInvalidShape: the
// browser would throw, so the caller must not consume the user's token.
func ValidateForReveal(p Policy) error {
	return bundleRefusal(p.Generator, string(p.Params), p.ProposalCount, p.RegenerateLimit)
}

// bundleRefusal returns the reason the bundle would refuse the descriptor
// {generator, proposalCount, regenerateLimit, parameters}, or nil.
func bundleRefusal(gen Generator, paramsJSON string, proposalCount, regenerateLimit int) error {
	if proposalCount < 1 || proposalCount > maxProposals {
		return invalid("proposal_count must be an integer in [1, %d], got %d", maxProposals, proposalCount)
	}
	if regenerateLimit < 0 || regenerateLimit > maxRegenerate {
		return invalid("regenerate_limit must be an integer in [0, %d], got %d", maxRegenerate, regenerateLimit)
	}
	_, err := CalculateEntropy(gen, paramsJSON)
	return err
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidShape, fmt.Sprintf(format, args...))
}

// libraryEntries returns the inline library of a G1/G2 parameter object.
func libraryEntries(paramsJSON string) []string {
	var p struct {
		Library []any `json:"library"`
	}
	_ = json.Unmarshal([]byte(paramsJSON), &p)
	out := make([]string, 0, len(p.Library))
	for _, e := range p.Library {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"

	"github.com/sched75/sealkeeper/internal/branding"
	"github.com/sched75/sealkeeper/internal/mailtemplates"
	"github.com/sched75/sealkeeper/internal/policies"
)

// Audit details for configuration changes. They have to answer two
// questions after the fact: "what exactly did a user's browser receive?"
// and "who weakened what, from which value to which?". Policies are
// recorded in full (they hold no secret) with a fingerprint of the
// descriptor served by /api/v1/policy — token.consumed carries the same
// fingerprint. Templates are recorded as content hashes; branding as a
// field-by-field diff.

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// descriptorSHA256 fingerprints a policy descriptor as served to the
// browser. encoding/json sorts map keys, so the same content always hashes
// the same.
func descriptorSHA256(desc map[string]any) string {
	b, err := json.Marshal(desc)
	if err != nil {
		return ""
	}
	return sha256Hex(b)
}

// policySnapshot is the full, reconstructible state of a policy row.
func policySnapshot(p policies.Policy) map[string]any {
	params := string(p.Params)
	out := map[string]any{
		"policy_id":           p.ID,
		"domain_id":           p.DomainID,
		"domain":              p.DomainName,
		"level":               string(p.ANSSILevel),
		"name":                p.Name,
		"generator":           string(p.Generator),
		"params_json":         params,
		"params_sha256":       sha256Hex([]byte(params)),
		"proposal_count":      p.ProposalCount,
		"regenerate_limit":    p.RegenerateLimit,
		"session_ttl_seconds": p.SessionTTLSeconds,
		"notify_on_consult":   p.NotifyOnConsult,
		"active":              p.Active,
	}
	if desc, err := policyDescriptor(p); err == nil {
		out["policy_sha256"] = descriptorSHA256(desc)
	}
	return out
}

// policyDiffFields are compared between two snapshots; params are compared
// by hash (the new text is in the snapshot, the old one in the previous
// event).
var policyDiffFields = []string{
	"name", "generator", "params_sha256", "proposal_count", "regenerate_limit",
	"session_ttl_seconds", "notify_on_consult", "active",
}

// diffFields returns {field: {from, to}} for every field that differs.
func diffFields(before, after map[string]any, fields []string) map[string]any {
	out := map[string]any{}
	for _, f := range fields {
		if !reflect.DeepEqual(before[f], after[f]) {
			out[f] = map[string]any{"from": before[f], "to": after[f]}
		}
	}
	return out
}

// policyUpdateDetails is the policy.updated payload: the new state, the
// changed fields and both fingerprints.
func policyUpdateDetails(before, after policies.Policy) map[string]any {
	b, a := policySnapshot(before), policySnapshot(after)
	a["changes"] = diffFields(b, a, policyDiffFields)
	a["previous_policy_sha256"] = b["policy_sha256"]
	return a
}

// templateHashes fingerprints the three sources of a mail template.
func templateHashes(t mailtemplates.Template) map[string]any {
	return map[string]any{
		"subject_sha256": sha256Hex([]byte(t.Subject)),
		"text_sha256":    sha256Hex([]byte(t.Text)),
		"html_sha256":    sha256Hex([]byte(t.HTML)),
		"system":         t.IsSystem,
	}
}

// templateChangeDetails is the template.saved / template.reset payload.
func templateChangeDetails(kind mailtemplates.Kind, lang string, before, after mailtemplates.Template) map[string]any {
	b, a := templateHashes(before), templateHashes(after)
	changed := []string{}
	for _, part := range []string{"subject", "text", "html"} {
		if b[part+"_sha256"] != a[part+"_sha256"] {
			changed = append(changed, part)
		}
	}
	out := map[string]any{
		"kind":     string(kind),
		"language": lang,
		"changed":  changed,
		"previous": b,
	}
	for k, v := range a {
		out[k] = v
	}
	return out
}

func brandingFields(b branding.Branding) map[string]any {
	return map[string]any{
		"instance_name":   b.InstanceName,
		"primary_color":   b.PrimaryColor,
		"secondary_color": b.SecondaryColor,
		"tertiary_color":  b.TertiaryColor,
		"contact_url":     b.ContactURL,
	}
}

// brandingChanges diffs the editable branding fields.
func brandingChanges(before, after branding.Branding) map[string]any {
	b, a := brandingFields(before), brandingFields(after)
	fields := make([]string, 0, len(a))
	for k := range a {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	return diffFields(b, a, fields)
}

package mail

import (
	"strings"
	"testing"
)

func TestNormalizeAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{name: "bare", in: "  Alice@Example.ORG ", want: "alice@example.org"},
		{name: "localhost admin", in: "admin@localhost", want: "admin@localhost"},
		// Payload from the audit: net/mail accepts CR/LF in a trailing comment.
		{name: "crlf in trailing comment", in: "victim@example.org (x\r\nX-Injected: pwned\r\n\r\n<h1>hi</h1>)", wantErr: true},
		{name: "lf in trailing comment", in: "a@b.com (c\nBcc: x)", wantErr: true},
		{name: "comment without control chars", in: "a@b.com (note)", wantErr: true},
		{name: "display name", in: "Alice <a@b.com>", wantErr: true},
		{name: "two addresses", in: "a@b.com, c@d.com", wantErr: true},
		{name: "too long", in: strings.Repeat("a", 250) + "@b.com", wantErr: true},
		{name: "empty", in: " ", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeAddress(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAddress(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("NormalizeAddress(%q) = %q, %v; want %q", c.in, got, err, c.want)
			}
		})
	}
}

func TestBuildersRejectHeaderInjection(t *testing.T) {
	t.Parallel()
	if _, err := BuildReveal(RevealInputs{
		To: "a@b.com (x\r\nBcc: evil@x.test)", InstanceDomain: "sk.test", RevealURL: "https://sk.test/r/x",
	}); err == nil {
		t.Error("BuildReveal accepted a recipient carrying CR/LF")
	}
	if _, err := Assemble(AssembleInputs{
		To: "a@b.com", InstanceDomain: "sk.test", Subject: "hi\r\nBcc: evil@x.test", Text: "t",
	}); err == nil {
		t.Error("Assemble accepted a subject carrying CR/LF")
	}
}

func TestSubjectIsRFC2047Encoded(t *testing.T) {
	t.Parallel()
	m, err := Assemble(AssembleInputs{To: "a@b.com", InstanceDomain: "sk.test", Subject: "Vos propositions sécurisées", Text: "t"})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !strings.Contains(m.String(), "Subject: =?utf-8?q?") {
		t.Errorf("non-ASCII subject not encoded: %.200s", m.String())
	}
}

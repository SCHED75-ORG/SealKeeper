// Package mail builds RFC 2822 multipart/alternative bodies for SealKeeper
// emails. The skeleton only knows how to render the reveal-link mail
// (FR-B.14..19) — branding hooks, language detection and additional templates
// land alongside module C.
package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	htmltemplate "html/template"
	"mime"
	"net/mail"
	"strings"
	texttemplate "text/template"
	"time"
)

// Message is the assembled mail.
type Message struct {
	From    string
	To      string
	ReplyTo string
	Subject string
	Headers map[string]string // additional headers (Message-ID, MIME-Version, etc.)
	Body    string            // already-encoded multipart body
}

// String returns the full RFC 822 representation that an SMTP DATA stage
// would send. Order of headers is fixed for determinism (helpful for tests).
func (m Message) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.From)
	fmt.Fprintf(&b, "To: %s\r\n", m.To)
	if m.ReplyTo != "" {
		fmt.Fprintf(&b, "Reply-To: %s\r\n", m.ReplyTo)
	}
	// Q-encoding leaves ASCII untouched and makes accented subjects RFC 2047.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", m.Subject))
	for _, k := range sortedKeys(m.Headers) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, m.Headers[k])
	}
	b.WriteString("\r\n")
	b.WriteString(m.Body)
	return b.String()
}

// RevealInputs is what the template needs.
type RevealInputs struct {
	To              string
	InstanceDomain  string // e.g. "sealkeeper.example.com" — for Message-ID + sender
	RevealURL       string // absolute URL the user clicks
	ValidityMinutes int    // for the body copy (FR-B.17)
	Sender          string // optional override (defaults to "SealKeeper <noreply@…>")
	ReplyTo         string // optional
	Subject         string // optional — defaults to FR-B.15
	Now             time.Time
}

// AssembleInputs is the payload for Assemble: pre-rendered text+HTML, plus
// envelope metadata. The package callers (httpserver) use this when the
// admin-editable mailtemplates package has produced a body, so the multipart
// + Message-ID + Date logic stays in one place.
type AssembleInputs struct {
	To             string
	From           string // optional; defaults to "SealKeeper <noreply@<InstanceDomain>>"
	ReplyTo        string
	InstanceDomain string
	Subject        string
	Text           string
	HTML           string
	Now            time.Time
}

// Assemble wraps pre-rendered text + HTML into an RFC 2822
// multipart/alternative message ready for SMTP DATA.
func Assemble(in AssembleInputs) (Message, error) {
	if err := validateRecipient(in.To); err != nil {
		return Message{}, err
	}
	if in.InstanceDomain == "" {
		return Message{}, fmt.Errorf("mail.Assemble: empty InstanceDomain")
	}
	if in.Subject == "" {
		return Message{}, fmt.Errorf("mail.Assemble: empty Subject")
	}
	if in.Text == "" && in.HTML == "" {
		return Message{}, fmt.Errorf("mail.Assemble: both Text and HTML are empty")
	}
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	sender := in.From
	if sender == "" {
		sender = fmt.Sprintf("SealKeeper <noreply@%s>", in.InstanceDomain)
	}

	boundary, err := newBoundary()
	if err != nil {
		return Message{}, err
	}
	body := assembleMultipart(boundary, in.Text, in.HTML)
	msgID := fmt.Sprintf("<%s@%s>", hex.EncodeToString(boundaryBytes(boundary))[:16], in.InstanceDomain)

	m := Message{
		From:    sender,
		To:      in.To,
		ReplyTo: in.ReplyTo,
		Subject: in.Subject,
		Headers: map[string]string{
			"Date":         in.Now.Format(time.RFC1123Z),
			"Message-ID":   msgID,
			"MIME-Version": "1.0",
			"Content-Type": fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary),
			"X-Mailer":     "SealKeeper",
		},
		Body: body,
	}
	if err := checkHeaders(m); err != nil {
		return Message{}, err
	}
	return m, nil
}

// BuildReveal renders the multipart/alternative body announcing a reveal link.
func BuildReveal(in RevealInputs) (Message, error) {
	if err := validateRecipient(in.To); err != nil {
		return Message{}, err
	}
	if in.RevealURL == "" {
		return Message{}, fmt.Errorf("mail.BuildReveal: empty RevealURL")
	}
	if in.InstanceDomain == "" {
		return Message{}, fmt.Errorf("mail.BuildReveal: empty InstanceDomain")
	}
	if in.ValidityMinutes <= 0 {
		in.ValidityMinutes = 15
	}
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}

	sender := in.Sender
	if sender == "" {
		sender = fmt.Sprintf("SealKeeper <noreply@%s>", in.InstanceDomain)
	}
	subject := in.Subject
	if subject == "" {
		subject = "Vos propositions de mot de passe SealKeeper"
	}

	textBody, err := renderText(in)
	if err != nil {
		return Message{}, err
	}
	htmlBody, err := renderHTML(in)
	if err != nil {
		return Message{}, err
	}

	boundary, err := newBoundary()
	if err != nil {
		return Message{}, err
	}
	body := assembleMultipart(boundary, textBody, htmlBody)

	msgID := fmt.Sprintf("<%s@%s>", hex.EncodeToString(boundaryBytes(boundary))[:16], in.InstanceDomain)

	m := Message{
		From:    sender,
		To:      in.To,
		ReplyTo: in.ReplyTo,
		Subject: subject,
		Headers: map[string]string{
			"Date":         in.Now.Format(time.RFC1123Z),
			"Message-ID":   msgID,
			"MIME-Version": "1.0",
			"Content-Type": fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary),
			"X-Mailer":     "SealKeeper",
		},
		Body: body,
	}
	if err := checkHeaders(m); err != nil {
		return Message{}, err
	}
	return m, nil
}

func validateRecipient(addr string) error {
	if addr == "" {
		return fmt.Errorf("mail: empty recipient")
	}
	if _, err := NormalizeAddress(addr); err != nil {
		return fmt.Errorf("mail: invalid recipient %q: %w", addr, err)
	}
	return nil
}

// maxAddressLen is the RFC 5321 path limit.
const maxAddressLen = 254

// NormalizeAddress accepts only a bare addr-spec ("user@example.org") and
// returns it lower-cased. Display names, comments and control characters
// are rejected: net/mail.ParseAddress tolerates CR/LF inside a trailing
// comment, which let a requester inject headers into outbound mail.
func NormalizeAddress(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || len(s) > maxAddressLen {
		return "", fmt.Errorf("mail: address length out of range")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("mail: control character in address")
		}
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	if a.Name != "" || a.Address != s {
		return "", fmt.Errorf("mail: only a bare address is accepted")
	}
	return s, nil
}

// checkHeaders refuses header values that could break out of their line.
func checkHeaders(m Message) error {
	vals := []string{m.From, m.To, m.ReplyTo, m.Subject}
	for k, v := range m.Headers {
		vals = append(vals, k, v)
	}
	for _, v := range vals {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("mail: CR/LF in header value %q", v)
		}
	}
	return nil
}

// ----- template rendering ---------------------------------------------------

const textTpl = `Bonjour,

Vous avez demandé un mot de passe via SealKeeper.

Cliquez sur le lien ci-dessous pour voir vos propositions :
{{ .RevealURL }}

Validité : {{ .ValidityMinutes }} minutes à compter de l'envoi de cet email.
Usage unique : ce lien ne fonctionne qu'une seule fois.

Si vous n'avez pas demandé ce mot de passe, ignorez cet email.

Cordialement,
SealKeeper
`

const htmlTpl = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>SealKeeper</title></head>
<body style="font-family: -apple-system, system-ui, sans-serif; max-width: 540px; margin: 2rem auto; padding: 1rem; color: #1f2937;">
<h2 style="color:#1d4ed8">SealKeeper</h2>
<p>Vous avez demandé un mot de passe via SealKeeper.</p>
<p style="text-align:center; margin: 2rem 0;">
  <a href="{{ .RevealURL }}"
     style="background:#1d4ed8; color:white; text-decoration:none; padding: 0.75rem 1.25rem; border-radius: 0.375rem; display:inline-block">
    Voir mes propositions
  </a>
</p>
<p style="font-size:0.875rem;color:#4b5563">
  Validité : {{ .ValidityMinutes }} minutes à compter de l'envoi de cet email.<br>
  Usage unique : ce lien ne fonctionne qu'une seule fois.
</p>
<p style="font-size:0.875rem;color:#4b5563">
  Si vous n'avez pas demandé ce mot de passe, ignorez simplement cet email.
</p>
<hr style="border:0; border-top:1px solid #e5e7eb; margin:2rem 0;">
<p style="font-size:0.75rem; color:#6b7280;">Powered by SealKeeper · open source · AGPL v3</p>
</body></html>
`

func renderText(in RevealInputs) (string, error) {
	tpl, err := texttemplate.New("text").Parse(textTpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, in); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderHTML(in RevealInputs) (string, error) {
	tpl, err := htmltemplate.New("html").Parse(htmlTpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, in); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func assembleMultipart(boundary, text, html string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "This is a multi-part message in MIME format.\r\n\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(html, "\n", "\r\n"))
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

func newBoundary() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "----=_SK_" + hex.EncodeToString(b), nil
}

func boundaryBytes(b string) []byte { return []byte(b) }

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Tiny stable sort without pulling sort import — fine for ≤10 entries.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

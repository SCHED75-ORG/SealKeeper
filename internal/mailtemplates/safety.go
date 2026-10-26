package mailtemplates

import (
	"errors"
	"fmt"
	"io"
	"strings"
	texttemplate "text/template"
	"text/template/parse"

	"golang.org/x/net/html"
)

// ErrUnsafe flags a template that could leak the reveal token or make the
// mail client fetch remote content. It always comes wrapped together with
// ErrParse so callers that only know ErrParse keep refusing the save.
var ErrUnsafe = errors.New("mailtemplates: unsafe template")

// The templates are admin-editable, so a hostile admin or a stolen admin
// session must not be able to turn the reveal mail into an exfiltration
// channel: the token travels in .RevealURL and would reach a third party
// through an <img>, a CSS url(), a foreign link, a ping= beacon, etc.
//
// The rules, enforced at save time and again on every render:
//
//   - .RevealURL is only ever used as a bare {{ .RevealURL }} action — no
//     pipes, functions, variables, sub-templates or dot rebinding, so the
//     value cannot be sliced, encoded or smuggled elsewhere;
//   - the subject never carries it;
//   - in the text body it stands alone (whitespace or <> delimited);
//   - in the HTML body it is only the whole href of an <a>/<area>, so the
//     link target is the instance's own reveal URL and nothing else;
//   - the HTML loads nothing remote: no script/iframe/object/link/base/
//     form/meta-refresh, no on* handlers, no ping=, no CSS url()/@import,
//     and src-like attributes accept only data:image/ or cid: URLs.
const revealField = "RevealURL"

// Sentinel values used to exercise a template at save time. The token part
// is alphanumeric like a real base64url token, so every escaper html/template
// may apply (URL, CSS, JS, HTML) leaves it verbatim in the output.
const (
	sentinelToken     = "SKREVEALSENTINEL7f3a9c2e"
	sentinelRevealURL = "https://reveal.sealkeeper.invalid/reveal/" + sentinelToken
)

func unsafeErr(part, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s: %s", ErrParse, ErrUnsafe, part, fmt.Sprintf(format, args...))
}

// checkSafety runs the static (parse tree) and dynamic (sentinel render)
// checks. The sources must already parse.
func checkSafety(subject, text, htmlSrc string) error {
	// Literal markup is checked across every branch, so a remote resource
	// hidden behind a condition the sentinel render does not take is still
	// refused at save time.
	lit, err := literalText(htmlSrc)
	if err != nil {
		return err
	}
	if err := checkHTML(lit, ""); err != nil {
		return err
	}
	_, err = renderTemplate(Template{Subject: subject, Text: text, HTML: htmlSrc}, Vars{
		RevealURL:          sentinelRevealURL,
		UserEmail:          "user@example.invalid",
		ValidityMinutes:    15,
		InstanceName:       "SealKeeper",
		InstanceDomain:     "sealkeeper.invalid",
		ContactURL:         "https://contact.sealkeeper.invalid/",
		ConsultedAt:        "2026-01-01T00:00:00Z",
		ConsultedIP:        "ip",
		ConsultedUserAgent: "ua",
	})
	return err
}

// checkStatic vets the parse trees of the three sources.
func checkStatic(tpl Template) error {
	for _, p := range []struct {
		name, src string
		allow     bool
	}{
		{"subject", tpl.Subject, false},
		{"text", tpl.Text, true},
		{"html", tpl.HTML, true},
	} {
		if err := checkTree(p.name, p.src, p.allow); err != nil {
			return err
		}
	}
	return nil
}

// checkTree walks the parse tree of one source. allowReveal says whether a
// bare {{ .RevealURL }} action is permitted in this part at all.
func checkTree(part, src string, allowReveal bool) error {
	t, err := texttemplate.New(part).Parse(src)
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrParse, part, err.Error())
	}
	if len(t.Templates()) > 1 {
		return unsafeErr(part, "define/block sub-templates are not allowed")
	}
	if t.Tree == nil || t.Root == nil {
		return nil
	}
	return walkNode(part, t.Root, allowReveal)
}

func walkNode(part string, n parse.Node, allowReveal bool) error {
	switch x := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if x == nil {
			return nil
		}
		for _, c := range x.Nodes {
			if err := walkNode(part, c, allowReveal); err != nil {
				return err
			}
		}
	case *parse.ActionNode:
		if isBareReveal(x.Pipe) {
			if !allowReveal {
				return unsafeErr(part, "{{ .RevealURL }} is not allowed here")
			}
			return nil
		}
		return walkPipe(part, x.Pipe)
	case *parse.IfNode:
		return walkBranch(part, &x.BranchNode, allowReveal)
	case *parse.RangeNode:
		return walkBranch(part, &x.BranchNode, allowReveal)
	case *parse.WithNode:
		return walkBranch(part, &x.BranchNode, allowReveal)
	case *parse.TemplateNode:
		return unsafeErr(part, "{{ template }} calls are not allowed")
	}
	return nil
}

func walkBranch(part string, b *parse.BranchNode, allowReveal bool) error {
	if err := walkPipe(part, b.Pipe); err != nil {
		return err
	}
	if err := walkNode(part, b.List, allowReveal); err != nil {
		return err
	}
	if b.ElseList != nil {
		return walkNode(part, b.ElseList, allowReveal)
	}
	return nil
}

// walkPipe refuses everything that could read .RevealURL indirectly or
// re-expose the whole Vars struct.
func walkPipe(part string, p *parse.PipeNode) error {
	if p == nil {
		return nil
	}
	if len(p.Decl) > 0 {
		return unsafeErr(part, "template variables are not allowed")
	}
	for _, c := range p.Cmds {
		for _, a := range c.Args {
			if err := walkArg(part, a); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkArg(part string, a parse.Node) error {
	switch x := a.(type) {
	case *parse.DotNode:
		return unsafeErr(part, "{{ . }} is not allowed; name the field")
	case *parse.VariableNode:
		return unsafeErr(part, "template variables are not allowed")
	case *parse.FieldNode:
		for _, id := range x.Ident {
			if id == revealField {
				return unsafeErr(part, "use .RevealURL only as a bare {{ .RevealURL }}")
			}
		}
	case *parse.ChainNode:
		for _, id := range x.Field {
			if id == revealField {
				return unsafeErr(part, "use .RevealURL only as a bare {{ .RevealURL }}")
			}
		}
		return walkArg(part, x.Node)
	case *parse.PipeNode:
		return walkPipe(part, x)
	}
	return nil
}

func isBareReveal(p *parse.PipeNode) bool {
	if p == nil || len(p.Decl) != 0 || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return false
	}
	f, ok := p.Cmds[0].Args[0].(*parse.FieldNode)
	return ok && len(f.Ident) == 1 && f.Ident[0] == revealField
}

// literalText concatenates the literal markup of every branch.
func literalText(src string) (string, error) {
	t, err := texttemplate.New("html").Parse(src)
	if err != nil {
		return "", fmt.Errorf("%w: html: %s", ErrParse, err.Error())
	}
	var b strings.Builder
	var walk func(parse.Node)
	walk = func(n parse.Node) {
		switch x := n.(type) {
		case *parse.ListNode:
			if x == nil {
				return
			}
			for _, c := range x.Nodes {
				walk(c)
			}
		case *parse.TextNode:
			b.Write(x.Text)
		case *parse.IfNode:
			walk(x.List)
			walk(x.ElseList)
		case *parse.RangeNode:
			walk(x.List)
			walk(x.ElseList)
		case *parse.WithNode:
			walk(x.List)
			walk(x.ElseList)
		}
	}
	if t.Tree != nil {
		walk(t.Root)
	}
	return b.String(), nil
}

// checkRendered applies the output rules to a rendered mail. revealURL is
// the value that was substituted for .RevealURL ("" when the kind has none).
func checkRendered(r Rendered, revealURL string) error {
	token := revealToken(revealURL)
	if token != "" && strings.Contains(r.Subject, token) {
		return unsafeErr("subject", "the reveal URL must not appear in the subject")
	}
	if err := checkText(r.Text, revealURL, token); err != nil {
		return err
	}
	return checkHTML(r.HTML, revealURL)
}

// revealToken returns the last path segment of the reveal URL — the part
// that survives any escaping verbatim.
func revealToken(revealURL string) string {
	if revealURL == "" {
		return ""
	}
	return revealURL[strings.LastIndex(revealURL, "/")+1:]
}

func checkText(text, revealURL, token string) error {
	if token == "" {
		return nil
	}
	ok := 0
	for i := 0; ; {
		j := strings.Index(text[i:], revealURL)
		if j < 0 {
			break
		}
		start, end := i+j, i+j+len(revealURL)
		if (start == 0 || strings.ContainsRune(" \t\r\n<", rune(text[start-1]))) &&
			(end == len(text) || strings.ContainsRune(" \t\r\n>", rune(text[end]))) {
			ok++
		}
		i = end
	}
	if strings.Count(text, token) != ok {
		return unsafeErr("text", "the reveal URL must stand on its own, not inside another URL or word")
	}
	return nil
}

// Elements that fetch, embed, redirect or run something.
var forbiddenElements = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true,
	"object": true, "embed": true, "applet": true, "link": true,
	"base": true, "form": true, "input": true, "button": true,
	"portal": true, "svg": true, "math": true, "template": true,
}

// Attributes whose URL value a mail client may fetch on open.
var resourceAttrs = map[string]bool{
	"src": true, "srcset": true, "background": true, "poster": true,
	"data": true, "action": true, "formaction": true, "codebase": true,
	"longdesc": true, "lowsrc": true, "dynsrc": true, "href": true,
	"xlink:href": true, "manifest": true, "archive": true, "classid": true,
	"profile": true, "imagesrcset": true,
}

func checkHTML(src, revealURL string) error {
	token := revealToken(revealURL)
	links := 0
	inStyle := false
	z := html.NewTokenizer(strings.NewReader(src))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if errors.Is(z.Err(), io.EOF) {
				if token != "" && strings.Count(src, token) != links {
					return unsafeErr("html", `the reveal URL may only be the whole href of a link: <a href="{{ .RevealURL }}">`)
				}
				return nil
			}
			return unsafeErr("html", "unreadable markup: %v", z.Err())
		case html.TextToken:
			if inStyle && cssUnsafe(string(z.Text())) {
				return unsafeErr("html", "CSS may not use url(), @import or escapes")
			}
		case html.EndTagToken:
			inStyle = false
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			inStyle = tt == html.StartTagToken && tok.Data == "style"
			n, err := checkTag(tok, revealURL)
			if err != nil {
				return err
			}
			links += n
		}
	}
}

// checkTag vets one start tag and returns how many of its attributes are
// an exact reveal-URL link target.
func checkTag(tok html.Token, revealURL string) (int, error) {
	name := tok.Data
	if forbiddenElements[name] {
		return 0, unsafeErr("html", "<%s> is not allowed in mail templates", name)
	}
	links := 0
	for _, a := range tok.Attr {
		key := strings.ToLower(a.Key)
		if a.Namespace != "" {
			key = a.Namespace + ":" + key
		}
		val := strings.TrimSpace(a.Val)
		switch {
		case strings.HasPrefix(key, "on"):
			return 0, unsafeErr("html", "event handler %q is not allowed", key)
		case key == "ping":
			return 0, unsafeErr("html", "ping= is not allowed")
		case name == "meta" && key == "http-equiv":
			return 0, unsafeErr("html", "<meta http-equiv> is not allowed")
		case key == "style":
			if cssUnsafe(val) {
				return 0, unsafeErr("html", "CSS may not use url(), @import or escapes")
			}
		case key == "href" && (name == "a" || name == "area"):
			if revealURL != "" && val == revealURL {
				links++
			}
		case resourceAttrs[key]:
			if !inlineURL(val) {
				return 0, unsafeErr("html", "%s=%q on <%s> would load remote content; only data:image/ and cid: are allowed", key, val, name)
			}
		}
	}
	return links, nil
}

// inlineURL accepts the values a mail client resolves without a network
// round trip.
func inlineURL(v string) bool {
	l := strings.ToLower(v)
	return l == "" || strings.HasPrefix(l, "data:image/") || strings.HasPrefix(l, "cid:")
}

// cssUnsafe refuses CSS that can fetch (url(), image-set(), @import) and
// any backslash, which would let an escape spell those out (u\72l()).
func cssUnsafe(css string) bool {
	l := strings.ToLower(css)
	for _, bad := range []string{"url(", "image-set(", "@import", "expression(", "\\"} {
		if strings.Contains(l, bad) {
			return true
		}
	}
	return false
}

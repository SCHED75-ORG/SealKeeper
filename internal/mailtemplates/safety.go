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
//   - in the HTML body it is only the whole href of an <a>, so the link
//     target is the instance's own reveal URL and nothing else; anywhere
//     else (text, raw-text element, any other attribute) is refused;
//   - the HTML is held to an allowlist of elements and attributes typical
//     of transactional mail (see allowedElements), checked on the rendered
//     output with both the tokenizer and a scripting-disabled tree builder:
//     nothing that fetches, embeds, redirects or runs, no comments, no CSS
//     url()/@import/escapes, links only to http(s)/mailto/#, and <img src>
//     only data:image/{png,gif,jpeg,webp} or cid:.
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
	if err := checkHTML(lit, "", false); err != nil {
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
	return checkHTML(r.HTML, revealURL, true)
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

// The HTML rules are an allowlist, not a denylist: a mail client parses the
// body with its own (often non-HTML5, always script-less) parser, so any
// element whose content the Go tokenizer and the client could read
// differently — noscript, xmp, noembed, noframes, plaintext, textarea,
// iframe, script, svg/math foreign content, VML, … — is simply not on the
// list. The only raw-text elements allowed are <title> and <style>, and
// their content may not contain a '<' at all, so there is no markup inside
// them for any parser to find.

// allowedElements is what a transactional mail needs and nothing more.
var allowedElements = map[string]bool{
	"html": true, "head": true, "body": true, "meta": true, "title": true, "style": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true, "td": true,
	"th": true, "caption": true, "colgroup": true, "col": true,
	"div": true, "span": true, "p": true, "br": true, "hr": true, "a": true, "img": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"ul": true, "ol": true, "li": true, "dl": true, "dt": true, "dd": true,
	"strong": true, "b": true, "em": true, "i": true, "u": true, "s": true, "small": true,
	"sub": true, "sup": true, "code": true, "pre": true, "blockquote": true,
	"center": true, "font": true, "abbr": true, "address": true,
}

// rawTextElements are the allowed elements the tokenizer reads as raw text.
var rawTextElements = map[string]bool{"title": true, "style": true}

// globalAttrs are presentational attributes that never take a URL.
var globalAttrs = map[string]bool{
	"style": true, "class": true, "id": true, "dir": true, "lang": true, "title": true,
	"align": true, "valign": true, "width": true, "height": true, "bgcolor": true,
	"color": true, "border": true, "cellpadding": true, "cellspacing": true,
	"role": true, "colspan": true, "rowspan": true, "scope": true, "headers": true,
	"span": true, "face": true, "size": true, "alt": true, "start": true, "type": true,
	"summary": true, "nowrap": true,
}

// elementAttrs are the extra attributes allowed on one element.
var elementAttrs = map[string]map[string]bool{
	"a":    {"href": true, "target": true, "rel": true, "name": true},
	"img":  {"src": true},
	"meta": {"charset": true, "name": true, "content": true},
	"html": {"xmlns": true},
}

const errComment = "comments and <!…> constructs are not allowed (conditional comments run in some clients)"

// checkHTML applies the allowlist to an HTML body. revealURL is the value
// substituted for .RevealURL ("" for the literal-markup pass, where actions
// are absent). rendered says the source went through html/template, which
// strips every comment, so a comment left in the output was smuggled in.
func checkHTML(src, revealURL string, rendered bool) error {
	links, err := checkHTMLTokens(src, revealURL, rendered)
	if err != nil {
		return err
	}
	if err := checkHTMLTree(src, rendered); err != nil {
		return err
	}
	if token := revealToken(revealURL); token != "" && strings.Count(src, token) != links {
		return unsafeErr("html", `the reveal URL may only be the whole href of a link: <a href="{{ .RevealURL }}">`)
	}
	return nil
}

// checkHTMLTokens walks the token stream and returns how many links target
// exactly the reveal URL.
func checkHTMLTokens(src, revealURL string, rendered bool) (int, error) {
	links := 0
	raw := "" // the raw-text element we are inside, if any
	z := html.NewTokenizer(strings.NewReader(src))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if errors.Is(z.Err(), io.EOF) {
				return links, nil
			}
			return 0, unsafeErr("html", "unreadable markup: %v", z.Err())
		case html.TextToken:
			if raw != "" {
				if err := checkRawText(raw, string(z.Raw())); err != nil {
					return 0, err
				}
			}
		case html.CommentToken:
			if rendered {
				return 0, unsafeErr("html", errComment)
			}
		case html.DoctypeToken:
			if !strings.EqualFold(strings.TrimSpace(string(z.Text())), "html") {
				return 0, unsafeErr("html", "only <!doctype html> is allowed")
			}
		case html.EndTagToken:
			raw = ""
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			raw = ""
			if tt == html.StartTagToken && rawTextElements[tok.Data] {
				raw = tok.Data
			}
			n, err := checkElement(tok.Data, tok.Attr, revealURL)
			if err != nil {
				return 0, err
			}
			links += n
		}
	}
}

// checkHTMLTree parses the body the way an HTML5 client with scripting
// disabled does and holds every element of the resulting tree to the same
// allowlist, so a construct the tokenizer pass reads differently from a
// tree builder cannot slip through either.
func checkHTMLTree(src string, rendered bool) error {
	doc, err := html.ParseWithOptions(strings.NewReader(src), html.ParseOptionEnableScripting(false))
	if err != nil {
		return unsafeErr("html", "unreadable markup: %v", err)
	}
	var walk func(*html.Node) error
	walk = func(n *html.Node) error {
		switch n.Type {
		case html.ElementNode:
			if n.Namespace != "" {
				return unsafeErr("html", "<%s:%s> foreign content is not allowed", n.Namespace, n.Data)
			}
			if _, err := checkElement(n.Data, n.Attr, ""); err != nil {
				return err
			}
			if rawTextElements[n.Data] {
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type != html.TextNode {
						return unsafeErr("html", "<%s> may only contain text", n.Data)
					}
					if err := checkRawText(n.Data, c.Data); err != nil {
						return err
					}
				}
			}
		case html.CommentNode:
			if rendered {
				return unsafeErr("html", errComment)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(doc)
}

// checkRawText vets the content of an allowed raw-text element.
func checkRawText(elem, text string) error {
	if strings.Contains(text, "<") {
		return unsafeErr("html", "<%s> content may not contain '<'", elem)
	}
	if elem == "style" && cssUnsafe(text) {
		return unsafeErr("html", errCSS)
	}
	return nil
}

const errCSS = "CSS may not use url(), @import, other at-rules than @media, or escapes"

// checkElement vets one element against the allowlist and returns 1 when
// it is a link whose whole href is the reveal URL.
func checkElement(name string, attrs []html.Attribute, revealURL string) (int, error) {
	if !allowedElements[name] {
		return 0, unsafeErr("html", "<%s> is not allowed in mail templates", name)
	}
	links := 0
	for _, a := range attrs {
		key := strings.ToLower(a.Key)
		if a.Namespace != "" || (!globalAttrs[key] && !elementAttrs[name][key] && !strings.HasPrefix(key, "aria-")) {
			return 0, unsafeErr("html", "attribute %q is not allowed on <%s>", key, name)
		}
		val := strings.TrimSpace(a.Val)
		switch {
		case key == "style":
			if cssUnsafe(val) {
				return 0, unsafeErr("html", errCSS)
			}
		case name == "a" && key == "href":
			if revealURL != "" && val == revealURL {
				links++
				continue
			}
			if !linkURL(val) {
				return 0, unsafeErr("html", "href=%q: links may only use https:, http:, mailto: or #", val)
			}
		case name == "img" && key == "src":
			if !inlineImage(val) {
				return 0, unsafeErr("html", "src=%q would load remote content; only data:image/{png,gif,jpeg,webp} and cid: are allowed", val)
			}
		}
	}
	return links, nil
}

// linkURL accepts the click-only link targets a mail may carry. An empty
// href is what the literal-markup pass sees for href="{{ .X }}".
func linkURL(v string) bool {
	l := strings.ToLower(v)
	if l == "" {
		return true
	}
	for _, p := range []string{"https://", "http://", "mailto:", "#"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// inlineImage accepts the image sources a mail client resolves without a
// network round trip. SVG is left out: it is a document, not a bitmap.
// An empty src is what the literal-markup pass sees for src="{{ .X }}";
// the rendered pass then sees the real value.
func inlineImage(v string) bool {
	l := strings.ToLower(v)
	if l == "" || strings.HasPrefix(l, "cid:") {
		return true
	}
	for _, t := range []string{"png", "gif", "jpeg", "jpg", "webp"} {
		if strings.HasPrefix(l, "data:image/"+t+";") || strings.HasPrefix(l, "data:image/"+t+",") {
			return true
		}
	}
	return false
}

// cssUnsafe refuses CSS that can fetch (url(), image-set(), @import,
// @font-face), any at-rule but @media, and any backslash, which would let
// an escape spell those out (u\72l()). Comments and whitespace are dropped
// first so a lenient parser cannot be fed "ur/**/l (".
func cssUnsafe(css string) bool {
	l := strings.ToLower(css)
	if strings.Contains(l, "\\") {
		return true
	}
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		if strings.HasPrefix(l[i:], "/*") {
			end := strings.Index(l[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 3
			continue
		}
		if c := l[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' {
			b.WriteByte(c)
		}
	}
	s := b.String()
	for _, bad := range []string{"url(", "image-set(", "image(", "cross-fade(", "element(", "expression(", "src(", "behavior:", "binding:"} {
		if strings.Contains(s, bad) {
			return true
		}
	}
	for i := 0; ; {
		j := strings.IndexByte(s[i:], '@')
		if j < 0 {
			return false
		}
		if !strings.HasPrefix(s[i+j:], "@media") {
			return true
		}
		i += j + 1
	}
}

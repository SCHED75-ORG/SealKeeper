# Outbound mail: sender identity, SPF, DKIM and DMARC

> The reveal mail carries a live single-use link. A recipient who cannot
> tell a genuine SealKeeper mail from a look-alike will click either, so the
> sending domain must be authenticated end to end. This page states what
> SealKeeper puts on the wire and what the operator must publish in DNS.
>
> PRD: FR-B.14..19 (reveal mail), FR-C.69..75 (templates), module H
> (deployment).

## What SealKeeper sends

Every mail is assembled by `internal/mail.Assemble`:

| Header / part          | Value                                                     | Who controls it                     |
|------------------------|-----------------------------------------------------------|-------------------------------------|
| `From:`                | `SealKeeper <noreply@SK_INSTANCE_DOMAIN>`                 | Operator, through `SK_INSTANCE_DOMAIN` (defaults to the host of `SK_BASE_URL`) |
| `Reply-To:`            | not set                                                   | Nobody                              |
| SMTP envelope `MAIL FROM` (Return-Path) | `SK_SMTP_FROM`, or the address set on `/admin/smtp`, else the `From:` address | Operator / admin |
| `Message-ID:`          | `<32 hex chars@SK_INSTANCE_DOMAIN>`, 128 bits from `crypto/rand`, unique per mail | Nobody |
| MIME boundary          | `----=_SK_` + 128 random bits, independent of the Message-ID | Nobody                         |
| `Subject:` and bodies  | Admin-editable templates (`/admin/templates`)             | Admin, within the template rules below |

Admins cannot change `From:`, add `Reply-To:` or any other header through
templates. A CR or LF in any header value is refused.

Template rules (enforced at save time and again on every send, see
`internal/mailtemplates/safety.go`): `{{ .RevealURL }}` may only be the whole
`href` of a link in the HTML body, appear on its own in the text body, and
never in the subject. The rendered HTML body is held to an allowlist of
elements and attributes typical of transactional mail (layout tables, text
formatting, `<a>`, `<img>`, `<meta charset>`, `<title>`, `<style>`), checked
both with the HTML tokenizer and with a scripting-disabled tree builder.
Anything else is refused, including every element whose content a mail
client could parse differently (`noscript`, `xmp`, `noembed`, `noframes`,
`plaintext`, `textarea`, `iframe`, `script`, `template`, SVG/MathML, VML).
`<title>`/`<style>` content may not contain `<`; CSS may not use `url()`,
`image-set()`, `@import` or any at-rule but `@media`, or backslash escapes;
links may only use `https:`, `http:`, `mailto:` or `#`; `<img src>` only
`data:image/{png,gif,jpeg,webp}` or `cid:`. The shipped defaults load no
remote resource and contain no tracking.

The mail language is the instance setting `SK_MAIL_LANGUAGE` (`en` or `fr`),
never the requester's `Accept-Language`.

## DNS the operator must publish

Below, `seal.example.eu` is `SK_INSTANCE_DOMAIN` and `example.eu` its
organizational domain.

### SPF

Publish SPF for the domain of the **envelope** sender (the `MAIL FROM`
above), authorizing only your relay, and end with `-all`:

```text
seal.example.eu.  TXT  "v=spf1 include:_spf.relay.example.net -all"
```

If `SK_SMTP_FROM` uses a different domain (for example
`bounces@mail.example.eu`), publish SPF for that domain instead. SPF only
counts for DMARC when that domain shares the organizational domain of the
`From:` domain (relaxed alignment) or equals it (strict).

### DKIM

SealKeeper does **not** sign mail itself. The relay (Postfix + OpenDKIM,
Microsoft 365, SES, …) must sign every message with `d=` equal to
`SK_INSTANCE_DOMAIN` or its organizational domain, so the signature aligns
with `From:`. Publish the relay's public key:

```text
s1._domainkey.seal.example.eu.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBg…"
```

Use a 2048-bit RSA (or Ed25519 alongside RSA) key and sign at least
`From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version` and
`Content-Type`.

### DMARC

Publish a DMARC policy for the `From:` domain. Because the mail carries a
credential link, aim for `p=reject` once reports show every legitimate
source aligned:

```text
_dmarc.seal.example.eu.  TXT  "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:dmarc-reports@example.eu"
```

Start with `p=none` while you read the aggregate reports if other systems
send as the same domain, then move to `quarantine` and `reject`. A
dedicated sub-domain for SealKeeper keeps that path short.

### Recommended extras

- **MTA-STS and TLS-RPT** on the recipient side of your organization, so
  the reveal link is not delivered in clear text; on the sending side keep
  `SK_SMTP_TLS` at `auto`/`starttls`/`implicit` and leave
  `SK_SMTP_INSECURE_TLS` unset.
- **No open relay**: the relay should accept submissions from SealKeeper
  only (authenticated or IP-restricted).

## Checking the setup

1. Send a test from `/admin/smtp` to an external mailbox.
2. In the received message, the `Authentication-Results:` header must show
   `spf=pass`, `dkim=pass` with `header.d=` your domain, and `dmarc=pass`.
3. Check the records:

   ```bash
   dig +short TXT seal.example.eu
   dig +short TXT s1._domainkey.seal.example.eu
   dig +short TXT _dmarc.seal.example.eu
   ```

4. Two test mails must show two different `Message-ID:` values.

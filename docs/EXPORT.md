# Export control: the notification, ready to send

Nothing in this repository goes public, by repository visibility or by a
crates.io publish, before the notification below is sent and recorded.
`Cargo.toml` keeps `publish = false` until then, and
[RELEASING.md](RELEASING.md) puts it first in the release order.

**This is not legal advice.** A non-lawyer prepared it from the regulation
text, so that counsel has something concrete to correct. It follows
IronCrypto's [docs/EXPORT.md](https://github.com/nervosys/IronCrypto/blob/master/docs/EXPORT.md),
which sets out the reasoning in more detail.

---

## 1. The determination

The requirement is **15 CFR §742.15(b)**:

- **§742.15(b)(1):** publicly available encryption source code is, in
  general, not subject to the EAR.
- **§742.15(b)(2):** the email notification to BIS and the ENC Encryption
  Request Coordinator applies to publicly available encryption source code
  that provides or performs **"non-standard cryptography"**. Part 772 defines
  that as proprietary or unpublished cryptographic functionality, not adopted
  or approved by a recognised standards body (IEEE, IETF, ISO, ITU, ETSI and
  others) and not otherwise published.

**On its face, IronSocketLayer is standard cryptography.** It implements no
cryptographic primitive at all: every cipher, hash, MAC, KDF, key exchange,
KEM, signature and HPKE operation is IronCrypto's, through `src/crypto/`. It
implements published protocols only (section 2). The ML-KEM hybrid groups and
the ML-DSA TLS code points are IETF Internet-Drafts. Those are published,
which is what the definition turns on, but counsel should confirm that point
explicitly.

If that reading is right, **§742.15(b)(2) does not apply**. The decision
(2026-10-05) is to **send one notice, before the first public release**, and
not one per release:

- The rule changed on 29 March 2021. Before then the notification was required
  for publicly available encryption source code generally, and some guidance
  still describes the older rule.
- The failure modes are not symmetric. Not notifying when it was required
  cannot be corrected after publication; notifying when it was not costs an
  email.

A notification identifies the internet location of the source code, not a
version, so later releases at the same location need no new notice. Send
another only if:
- the code moves to a new location or a new mirror; or
- IronSocketLayer would ever implement non-standard (proprietary or
  unpublished) cryptography, which is not planned.

**Commercial distribution is a different question.** If IronSocketLayer is
also distributed under a commercial licence, as object code or source that is
not publicly available, it is ECCN 5D002 under License Exception ENC
(§740.17), not §742.15(b). That needs its own classification with counsel
before any such sale.

---

## 2. The notification

Send it from an address that will still receive mail in a year. Send to both
recipients in one message, so the record is one artefact.

**To:** `crypt@bis.doc.gov`, `enc@nsa.gov`
**Subject:** `Notification of publicly available encryption source code — 15 CFR 742.15(b) — IronSocketLayer`

```text
To the Bureau of Industry and Security and the ENC Encryption Request
Coordinator:

This is a notification under 15 CFR 742.15(b) of the internet location of
publicly available encryption source code.

SUBMITTER
  Entity:          Nervosys
  Contact:         <name>, <title>
  Email:           <address that will remain monitored>
  Telephone:       <number>
  Postal address:  <address>

ITEM
  Name:            IronSocketLayer (crates ironsocketlayer, isl-ontology,
                   isl-cli)
  Description:     An open-source TLS 1.3 and QUIC-TLS protocol library
                   written in Rust, distributed as source code. It implements
                   no cryptographic primitive; all cryptography is provided by
                   the separately notified IronCrypto library
                   (https://github.com/nervosys/IronCrypto).
  Classification:  ECCN 5D002 (encryption source code)
  Licence:         AGPL-3.0-or-later

INTERNET LOCATION
  https://github.com/nervosys/IronSocketLayer
  https://crates.io/crates/ironsocketlayer
  https://crates.io/crates/isl-ontology
  https://crates.io/crates/isl-cli

  The source code is or will be publicly available at those URLs without
  restriction on access and without charge.

CRYPTOGRAPHIC FUNCTIONALITY
  IronSocketLayer implements published protocols only, and contains no
  proprietary or unpublished cryptographic functionality.

    TLS                 TLS 1.3 (RFC 8446), including PSK resumption,
                        external PSKs, 0-RTT, post-handshake client
                        authentication and exporters; ALPN (RFC 7301);
                        OCSP stapling (RFC 6066, RFC 6960); record size limit
                        (RFC 8449)
    QUIC                TLS for QUIC (RFC 9001), QUIC version 2 (RFC 9369)
    Encrypted ClientHello  RFC 9849, using HPKE (RFC 9180) from IronCrypto
    Certificates        X.509 path validation and issuance (RFC 5280); CRLs;
                        ML-DSA in X.509 (RFC 9881)
    Post-quantum TLS    ML-KEM key exchange and hybrids
                        (draft-ietf-tls-mlkem, draft-ietf-tls-ecdhe-mlkem);
                        ML-DSA signatures (draft-ietf-tls-mldsa); the
                        algorithms themselves are FIPS 203 and FIPS 204, from
                        IronCrypto

  IronSocketLayer is not FIPS 140-3 validated, holds no CMVP certificate and
  is not DO-178C certified. The standards above are cited to identify what is
  implemented, not to claim validation.

This notification is submitted before the source code is made publicly
available.

<name>
<title>, Nervosys
<date>
```

### Before sending, confirm

- [ ] The URLs are where the code will actually be. Add any mirror here rather
      than sending a second notification later.
- [ ] The protocol list still matches the code. A new protocol or code point
      changes it; `isl ontology export --format json` lists everything implemented.
- [ ] Counsel has reviewed, including the Internet-Draft question in section 1
      and any commercial-distribution plans.
- [ ] The contact address will still be monitored in a year.

---

## 3. What to keep

Commit a record under `docs/export/` (not in this file, which is a template)
with:

| Field | Value |
|---|---|
| Date and time sent | with timezone |
| Sent from | the address used |
| Sent to | both recipients, as addressed |
| Subject line | verbatim |
| Body | verbatim, as sent |
| URLs notified | exactly as given |
| Commit | the repository state at the time of sending |
| Acknowledgement | any reply, or "none received" with the date checked |
| Counsel | who reviewed, and when |

No acknowledgement is expected. §742.15(b) is a notification, not an
application, so silence is the normal outcome. The sender's own record is
therefore the only evidence there will be.

---

## 4. Order of operations

1. Send the notification to both addresses.
2. Commit the record.
3. Only then set `publish = true`, publish to crates.io, or make the
   repository public.

Steps 1 and 3 cannot be undone. A crate yanked from crates.io stays in the
index and in every mirror; a repository that was public has been cloned.

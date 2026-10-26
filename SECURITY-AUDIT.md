# Security Audit — AWA Benefits Redirection Agreement

**Target:** `reeced03/AWA-redirection-agreement` @ `8279bf1` (the source behind
`awaopenenrollment.netlify.app`)
**Date:** 2026-10-26
**Scope:** full source review of the Netlify Functions API, the crypto/storage/roster
libraries, and the client. Two findings were reproduced locally against the app's own
`api.mjs` with a local blob store (no production system was touched; the live site is
behind Netlify team-SSO and was not accessed).

## What the app does, in one line
Employees scan a QR code, prove who they are with **last-4 of SSN + date of birth**, and
e-sign a benefits form; the SSN/DOB match happens server-side and the full roster is
encrypted at rest. The identity check is the entire security boundary, so the findings
below concentrate there.

## The good
The foundations are mostly sound, and worth stating so they aren't "fixed" by accident:

- Rosters, submissions and PDFs are encrypted (AES-256-GCM) before hitting Netlify Blobs.
- Session and admin tokens are HMAC-signed and verified in constant time
  (`crypto.timingSafeEqual`); the admin password compare is constant-time too.
- Only the "yellow" prefill fields reach the browser — never SSN or the full roster.
- Solid HTTP headers set in `netlify.toml`: a real CSP (`script-src 'self'`, no
  `unsafe-inline` for scripts), `X-Frame-Options: DENY`, `nosniff`, HSTS, `no-referrer`.
- The client builds DOM with `textContent`/`createElement` (`el`/`rich` helpers) rather
  than `innerHTML` on user data, so template fields can't inject script. `postMessage`
  handlers check `origin`. No stored XSS sink found.
- Input sizes are capped (request body, signature, upload) and the slug is tightly
  validated (`/^[a-z0-9-]{1,40}$/`), closing off path traversal through the key names.

## Findings

| # | Severity | Issue |
|---|----------|-------|
| 1 | **High** | Verification rate limit resets on any success → SSN brute-force from one IP |
| 2 | **High** | Rate limiter is not atomic (check-then-write) → limit bypassed by concurrent requests |
| 3 | Medium | Identity secret is weak (last-4 SSN + DOB); limiter is the only brake |
| 4 | Medium | `nodemailer ^6.9.16` is years out of date; many advisories, fixed in 10.1.4 |
| 5 | Low | Rate-limit / employee IP keying trusts `x-forwarded-for` as a fallback |
| 6 | Low | No account-/record-level lockout; limiter is purely per-IP |
| 7 | Info | Full plaintext SSN + DOB copied into every stored submission and PDF |

---

### 1. Verification rate limit resets on success — SSN brute-force (High)

`netlify/functions/api.mjs` → `verifyEmployee` and the limiter helpers.

The limiter allows 8 failures per 15 minutes, keyed on `slug|ip`. But a **successful**
verify calls `clearLimit(...)`, wiping the counter:

```js
await clearLimit(store, 'verify', ipKey);   // on success
```

So the counter only ever tracks *consecutive* failures. Any employee who has their own
valid last-4 + DOB (every legitimate user does) can interleave a valid login every few
guesses to reset the brake and brute-force a **co-worker's** last-4 of SSN — the only
unknown once a DOB is known (DOBs are frequently guessable or public). The search space
is just 10,000 values.

**Reproduced locally** against the app's real `api.mjs`:

```
BEFORE fix: reset-with-own-login found victim last4=4321 after 4322 guesses, never blocked
AFTER fix:  attacker got 4 guesses, then HTTP 429 — victim last4 never recovered
```

Impact: disclosure of another employee's SSN last-4, and the ability to open and
e-sign that employee's benefits election. For a form carrying SSNs, that's a serious
confidentiality + integrity break.

**Fix:** don't let success clear a failure budget that's meant to throttle *attempts*.
Track attempts (success or fail) against the window, and additionally key the limit on
the identity being probed, not just the IP. See the patch set in
`fixes/01-02-rate-limit.patch`.

---

### 2. Rate limiter is not atomic — concurrency bypass (High)

Same helpers. `checkLimit` reads the counter, the handler does its work, then
`recordFailure` reads-modifies-writes it. Between read and write there is no lock, so N
requests fired at once all read the same pre-increment value and all pass the gate.

**Reproduced locally:** 500 concurrent wrong guesses from one IP → **all 500 processed
(500 × HTTP 401), zero 429s.** The 8-per-15-min limit never engaged. An attacker can
simply fire the whole 10,000-key space in parallel batches.

**Honest limit of the included patch:** the finding-1 patch makes the limiter count every
attempt (fixing the *serial* bypass), but it does **not** close the concurrency race —
re-running the 500-way burst against the patched code still shows all 500 processed. A
read-modify-write on Netlify Blobs cannot be made atomic from application code, so the
real fix is one of:

- a store with atomic increment (Upstash/Redis `INCR`, or Netlify's own rate-limit
  primitive), or
- conditional writes via `@netlify/blobs` ETags (`onlyIfMatch`) with retry, treating a
  write conflict as "a concurrent attempt happened" and failing closed.

Until then the per-identity lockout (finding 6) and a stronger identity secret (finding 3)
are the defenses that actually bound a concurrent attacker, which is why they're not
optional niceties.

---

### 3. Weak identity secret (Medium)

The whole security boundary is *last-4 SSN (10⁴) + DOB*. Even with a working limiter,
that is low-entropy for an insider who knows a target's birthday. Mitigations:

- Enforce the per-identity + per-IP lockout from finding 1 (raises cost sharply).
- Consider a second factor the employer already holds (employee ID, ZIP, or a per-person
  code printed on the enrollment letter) added to the match.
- Keep the existing "two people share last-4 + DOB → neither can verify online" rule; it
  already prevents the ambiguous-match disclosure.

### 4. Outdated `nodemailer` (Medium)

`package.json` pins `nodemailer ^6.9.16`. The 6.x line is affected by a long list of
reviewed advisories — recipient-domain validation bypass (`GHSA-cc9r-2j5m-2m83`,
affects `>=6.9.16`), several addressparser DoS issues, CRLF/header-injection and
TLS-validation bugs. All are fixed by **10.1.4**.

Exploitability here is limited (the `to:` address is admin-configured, not
attacker-supplied, and content is a fixed template), so this is "patch hygiene" rather
than an open hole — but it's the kind of thing that ages into a real one. Bump to
`^10.1.4` and run `npm audit` in CI. `jszip@3.10.1`, `pdf-lib@1.17.1` and
`@netlify/blobs` show **no** current reviewed advisories.

### 5. `x-forwarded-for` fallback (Low)

`clientIp()` uses `context.ip` first (set by Netlify in production — good), but falls back
to the client-controlled `x-forwarded-for`. In production the fallback shouldn't be
reached, but if it ever is, an attacker rotates the header to get a fresh rate-limit
bucket per request. Prefer `x-nf-client-connection-ip` / `context.ip` only, and treat
absence as `'unknown'` (one shared bucket) rather than trusting XFF.

### 6. No record-level lockout (Low)

The limiter is per-IP only, so a distributed attacker (botnet / proxy pool) sidesteps it
regardless of findings 1–2. Add a counter keyed on the *target identity* (e.g.
`slug|last4|dob` hash) with a hard lockout, so guessing one record is throttled no matter
where the guesses originate. Included in the finding-1 patch.

### 7. Plaintext SSN/DOB fan-out (Info)

Each submission stores `employee: { name, dob, ssn, ... }` **and** a full copy of the
company `template`, then the SSN is also rendered into the exported spreadsheet. It's all
encrypted at rest, so this isn't a vulnerability — but minimizing where full SSNs land
(store last-4 only in the submission; keep the authoritative SSN in the roster record)
shrinks the blast radius if a decryption key ever leaks. Worth considering, not urgent.

## Suggested priority
1. Findings **1 & 2** now — they make the core identity check brute-forceable from a
   single machine. (Patch provided.)
2. Finding **4** (dependency bump) — quick, low-risk.
3. Findings **3 & 6** — design change; plan for the next enrollment cycle.
4. Findings **5 & 7** — hardening / data-minimization when convenient.

## How findings 1 & 2 were verified
A harness imported the app's unmodified `netlify/functions/api.mjs`, `storage.mjs` and
`crypto.mjs`, pointed at a throwaway local blob directory with a two-person roster, and
called the real `/api/verify` handler. No production data, credentials, or hosts were
involved. The three probes (sequential, reset-with-own-login, 500-way concurrent) and
their outputs are quoted inline above.

---
*Prepared with Claude Code. Findings 1 and 2 reproduced locally; the rest are from source
review and the GitHub Advisory Database.*

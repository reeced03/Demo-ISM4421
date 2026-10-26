# Fixes for AWA Benefits Redirection Agreement

These patches apply to `reeced03/AWA-redirection-agreement` (the repo deployed at
`awaopenenrollment.netlify.app`), **not** to this repo. See `../SECURITY-AUDIT.md`.

## `01-rate-limit-and-nodemailer.patch`

Addresses audit findings **1, 2 (partial), 4, 6**:

- `netlify/functions/api.mjs` — replaces the failure-only limiter with one that counts
  **every attempt** in a fixed window, so a valid login can no longer reset an attacker's
  budget (finding 1). Adds a second limit keyed on the probed identity
  (`slug|last4|dob`) so guessing one employee's SSN is throttled across IPs (finding 6).
  Removes the `clearLimit`-on-success calls in both `verifyEmployee` and `adminLogin`.
- `package.json` — bumps `nodemailer` `^6.9.16` → `^10.1.4` (finding 4).

Does **not** fully fix the concurrency race (finding 2) — that needs an atomic counter;
see the audit. The per-identity lockout and a stronger identity check are the real brakes
on a concurrent attacker.

### Apply
```bash
# from a checkout of AWA-redirection-agreement
git checkout -b security-fixes
git apply /path/to/01-rate-limit-and-nodemailer.patch
npm install        # picks up nodemailer 10.x
npm audit
```

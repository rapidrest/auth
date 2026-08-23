# auth — Design Decisions & Session Notes

This file exists so that Claude sessions working in this repo don't re-litigate settled
decisions or re-discover the same issues from scratch. It is local to this repo (not tied to
any one machine's global Claude memory), so it travels with the code.

**Maintenance rule:** when a standing decision changes, update the section below in place
(don't just append a contradiction lower down). When a new investigation/session produces a
decision, finding, or reverted approach worth remembering, add a dated entry under Session Log.
Keep entries terse — this is a reference, not a transcript.

## Standing design decisions & constraints

- **Vulnerability/review threat model: externally-exploitable only.** This library is a power
  tool for developers building their own services, not a hardened black box. When reviewing for
  "vulnerabilities," only count issues reachable from a downstream, untrusted HTTP/WebSocket
  client hitting a service built on the framework (anonymous or low-privilege caller). Do NOT
  flag: developer-only footguns (misusing an API, a decorator applied wrong in your own code),
  internal utilities only the operator touches (build/CLI/startup wiring), or purely theoretical
  races with no concrete external trigger path. Every finding should be able to name the actual
  HTTP route/method or WS message type that reaches the code in question.

- **Commit discipline.** Don't `git commit` unless explicitly asked, even after a full
  review-and-fix cycle with passing tests. Leave changes staged/unstaged and say so.

- **Documentation ownership.** Full documentation lives at rapidrest.dev, not in this repo.
  `README.md`/`RELEASE_NOTES.md` stay as terse, scannable bullet-list feature indexes (strategy/
  model/route class names + one-line descriptions) — do not expand them into guides, tutorials,
  config reference docs, or example projects. When a shipped feature isn't reflected in either
  file's bullet lists, that's worth flagging/fixing; prose beyond that isn't.

- **RBAC is deliberately out of scope**, not an oversight. Considered during the 1.0 gap analysis
  and explicitly deferred — there's no concrete downstream need driving it yet. Don't re-propose
  it unassisted; revisit only if a real requirement shows up.

- **Adversarial review convention.** This repo's reviews use two independent agents in parallel,
  scope split by domain when the surface is broad (e.g. auth/session/strategy vs. account/data/
  ACL/model), each told to name the concrete HTTP route reaching any security finding per the
  threat model above. Before trusting a high-severity claim, re-verify it yourself by tracing into
  the actual `@rapidrest/core`/`@rapidrest/service-core`/TypeORM source it depends on (not just
  the diff) — this caught real framework behavior (TypeORM's `EntityPropertyNotFoundError` on an
  unmapped column, `RepoUtils`/`RedisStore` caching by reference) that a code-only read would have
  missed either way. For small, mechanical scopes (e.g. verifying ~30 thin ORM-binding subclasses
  all wire the right concrete class to the right field) a direct read is faster and just as
  reliable as spinning up agents — don't delegate reflexively.

## Session Log

### 2026-08-22 — 1.0 hardening, event hooks, TOTP encryption, three adversarial review rounds

- **RateLimiter**: reverted to an atomic Redis `INCREX`-based implementation (globally atomic
  across instances) with an in-memory `MemoryStore` fallback; independent per-IP layer added
  (permissive default, `trusted_proxies`-aware IP resolution).
- **1.0 hardening pass**: MFA recovery/backup codes as a first-class secret type, session
  revocation (`BaseAccountRoute.revokeSessions()` / `User.sessionsRevokedAt`, checked on refresh),
  configurable Argon2 cost params, secure cookies by default, OpenAPI doc-decorators completed
  across every route.
- **Post-1.0 features shipped**: security event hooks (`AuthEventType` + `@rapidrest/core`'s
  `EventUtils`, 8 emission sites covering login/registration/elevation/session-revocation/account-
  deletion/MFA-enrollment-removal/rate-limit-exceeded, each carrying the caller's `trusted_proxies`
  -aware source IP) and optional TOTP secret encryption at rest (AES-256-GCM, `enc:v1:` envelope,
  backward-compatible passthrough for pre-existing plaintext secrets).
- **Three rounds of adversarial review** (see convention above) found and fixed real bugs:
  - *New event/encryption diff*: `RateLimiter` itself never got `trusted_proxies` wired in, so its
    per-IP counter collapsed every caller behind a reverse proxy into one shared bucket (DoS);
    TOTP decrypt-for-response mutated the object `RepoUtils.create()`/`update()` may hand to an
    entity cache by reference, which would leak the plaintext secret into a cache read if the
    consuming app enables caching on `Secret`; the decrypt call inside `verifyTOTP()`'s per-
    candidate loop was unguarded, so one undecryptable secret aborted checking a user's other
    valid ones and reopened the timing gap `verifyDummyTOTP()` exists to close;
    `auth.ratelimit.exceeded` re-fired on every retry after the threshold, not just the crossing.
  - *Full repo, split auth/session vs. account/data/ACL*: **alias `type` mass-assignment** —
    `BaseAliasRoute.validateCreate()` only branched on `NAME`/`EMAIL`/`PHONE`, so a client-supplied
    `type: "oauth"` (a real `AliasType`, used internally by `BaseAuthOIDCRoute` via a direct
    `aliasRepo.create({ignoreACL: true})` call that bypasses this route) fell through with a
    client-supplied `verified: true` left untouched — any authenticated user could permanently
    squat an identifier. **`sessionsRevokedAt` unmapped** on both `UserSQL` (TypeORM throws
    `EntityPropertyNotFoundError`) and `UserMongo` (write silently succeeds via raw `$set`, but
    `instantiateObject()`'s selective constructor drops it on every read) — "Revoke All Sessions"
    didn't actually work on either datastore. **TOCTOU race** on TOTP/recovery-code replay
    protection — verification and persisting the anti-replay marker were two independent round
    trips, so two concurrent requests holding the same valid code could both authenticate; closed
    with a fresh-read guard combined with the existing optimistic-locking `version` check (no new
    infra needed). Also: admin-provisioned alias verification checked the *admin's* profile
    instead of the target account's; `DefaultAccounts` never re-synced `roles`/`verified` for an
    already-provisioned account on restart; `OTPStrategy.discovery()` skipped rate limiting
    entirely when `id` was omitted; the shared form-data parser (`getRequestData()`) never
    URL-decoded and split naively on every `=`, silently truncating/mangling values containing
    `&`/`=`/`+`.
  - *Focused pass, SQL/Mongo route subclasses*: read all ~30 files directly rather than
    delegating (see convention above) — clean; found and removed one unused `OIDCProvider` import
    present symmetrically in both `BaseAuthOIDCRouteSQL.ts`/`Mongo.ts`.
- **Docs were stale**: `README.md`/`RELEASE_NOTES.md` didn't mention most of the above (or several
  pre-existing-but-undocumented routes like `BaseAccountRoute`/`BaseRegistrationRoute`/
  `BaseAuthElevationRoute`). Added a `Security Features` list and a `Session & Account Management`
  route subsection to both, in the existing terse bullet style (see doc-ownership decision above).

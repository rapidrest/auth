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

- **Commit discipline.** Don't `git commit` unless explicitly asked for *that specific piece of
  work*. An autonomous-execution/"commit as you go" approval given for one approved plan (e.g. via
  plan mode) is scoped to that plan only — it does not carry forward to later, separate requests in
  the same session, even ones that look similar in kind (a follow-up review-and-fix pass, a
  refactor, a new feature), and even after a full review-and-fix cycle with passing tests. Default
  to leaving changes staged/unstaged and saying so; only commit automatically within the exact
  scope of a plan that was explicitly approved as autonomous. If unsure whether new work falls
  inside that scope, treat it as outside and ask.
  
- **Commit message style: concise, one line per task/bug/feature — no verbose prose.** A commit
  message is a short list of one-line bullets, one per item. This mirrors JP's standing convention
  across his other repos.

- **Documentation ownership.** Full documentation lives at rapidrest.dev, not in this repo.
  `README.md`/`RELEASE_NOTES.md` stay as terse, scannable bullet-list feature indexes (strategy/
  model/route class names + one-line descriptions) — do not expand them into guides, tutorials,
  config reference docs, or example projects. When a shipped feature isn't reflected in either
  file's bullet lists, that's worth flagging/fixing; prose beyond that isn't.

- **Pre-release changelog/release-notes convention.** While `2.0.0` is in pre-release
  (`2.0.0-beta.x`), `CHANGELOG.md` and `RELEASE_NOTES.md` both condense everything toward it into a
  single `[Unreleased]`/`## Unreleased` listing rather than a new section per beta tag. That section
  gets finalized as `[2.0.0]`/`## v2.0.0` only once a real (non-beta) `2.0.0` is tagged. Keep adding
  to the existing listing, don't fork a new one per beta bump.

- **`@rapidrest/auth` never bumps/publishes its own version.** Implementing, testing, and (if asked)
  committing is fine; running the actual `yarn release`/publish step is the user's call to make and
  trigger themselves, every time — don't do it proactively even after a clean build+test pass.

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

### 2026-09-23 (latest) — CSRF protection: `CsrfUtils` + the two special-case routes

Ecosystem-wide CSRF fix, spanning `service-core` (the actual double-submit enforcement,
`RouteUtils.checkCsrf()`, plus `JWTAuthResult.source` so it can tell a cookie-sourced credential
apart from a bearer/API-key one), this repo, `auth-server`, and `react-shared`. This repo's share:

- `CsrfUtils` (`src/auth/CsrfUtils.ts`) issues/rotates a `csrf` cookie alongside `jwt`/`refresh` at
  every point `TokenUtils.createAuthResult()`/`clearToken()` fire — login, refresh, elevation,
  impersonation, logout. Deliberately **host-only** (no `Domain` attribute), unlike `jwt`/`refresh`
  which are commonly `Domain`-scoped for SSO across sibling subdomains: a wildcard-domain
  double-submit cookie can be read via `document.cookie` by *any* same-site sibling subdomain
  (compromised, less-trusted, or just a different app on the same parent domain), which would
  silently defeat the whole scheme. The actual double-submit comparison and Origin/Referer
  allow-list fallback (for a legitimately cross-origin caller like `react-shared`'s
  `authApiFetch()`, whose JS can never read this host-only cookie in the first place) both live in
  `@rapidrest/service-core`'s new `src/http/csrf/csrf.ts` — read that module's doc comment for the
  full design rationale before touching either side of this.
- Two routes needed explicit handling beyond the automatic, `req.auth.source === "cookie"`-gated
  check `RouteUtils.checkCsrf()` installs on every route:
  - `BaseImpersonationRoute`'s `/impersonate/stop` was a `GET` — changed to `POST`. A
    state-changing `GET` is exploitable via a bare cross-site/same-site navigation (no form or
    script needed at all), which bypasses CSRF defenses entirely since they only ever apply to
    non-safe methods. Verified every call site across `react-shared`, `auth-server`'s own
    frontend, and this repo's tests was updated to `POST` — a real breaking change for any client
    still issuing the old `GET`.
  - `BaseOAuthAuthorizeRoute.decideConsent()` authenticates via `req.session.userUid` directly
    (see the class's own doc comment on why — no fixed `@Auth([...])`), so it's never covered by
    the automatic gate, which only fires once `req.auth.source` exists. Added an explicit,
    unconditional `verifyCsrfRequest()` call at the top of the handler. This was arguably the
    highest-value CSRF target in the library: a forged consent could grant a malicious OAuth
    client an authorization code for the victim's account.
- The prior 2026-08-22-era security review (see `auth-server`'s NOTES.md) concluded "no
  CSRF-relevant gaps" — that wasn't wrong given the threat model it evaluated against (classic
  cross-*site* forgery, which `SameSite=Lax` already blocks), it just didn't consider same-site
  cross-*origin* forgery (a sibling subdomain, not a foreign site) or naive double-submit's
  wildcard-domain weakness. Worth remembering next time a "no gaps found" review comes up: the
  threat model matters as much as the review itself.

### 2026-09-22 — `AuditLogUtils`: a separate, durable audit-log mechanism (follow-up to the app-passwords/lastUsedAt work)

Requested as a same-session follow-up, prompted by the consuming app's operator confirming a concrete fact:
no deployment in this monorepo configures `telemetry_services:url` or registers an `EventUtils.on()`
listener, so every `EventUtils.record()` call added by the last two follow-ups is silently discarded end to
end today - fine for telemetry, unacceptable for audit purposes. Built a lean, `MessagingUtils`-style DI
swap point (`AuditLogUtils`) so a consuming app (`auth-server`, built by a parallel agent in that repo) can
plug in real durable persistence with zero changes to this library. Investigated `src/auth/events.ts`, every
`EventUtils.record()` call site, and every `TokenUtils.createAuthResult()` caller first, per this repo's
usual practice, before writing anything - the task's own summary of the caller list held up exactly, except
`BaseOAuthAuthorizeRoute` (matched the `grep -rln createAuthResult` search only because its own doc comment
*mentions* `TokenUtils.createAuthResult()` in prose - it never actually calls it, so it needed zero changes).

- **New `src/auth/AuditLogUtils.ts`**: `AuditLogEntry` = `{ type: string; userUid?: string; actorUid?:
  string; ip?: string; path?: string; method?: string; data?: Record<string, unknown>; }`. `actorUid` unifies
  `BaseAccountRoute`'s pre-existing `deletedBy`/`revokedBy` fields under one name for this mechanism - only
  set when it differs from `userUid`. `AuditLogUtils.record()` just logs via `@Logger` in the base
  implementation and **never throws** (internal try/catch, belt-and-suspenders on top of every call site's
  own guard). A consuming app registers a database-backed subclass under the exact name `AuditLogUtils` -
  `ObjectFactory` then resolves every `@Inject(AuditLogUtils)` in this library to it, identically to how
  `MessagingUtils` is swapped today (see `BaseSecretRoute`'s own `@Inject(MessagingUtils)` for the existing
  precedent this mirrors).
- **Two new `AuthEventType` values, `AuditLogUtils`-only** (not fired via `EventUtils`):
  `SIGNED_IN = "auth.signed_in"` and `IMPERSONATED = "auth.impersonated"`.
- **`TokenUtils.createAuthResult()` gains a trailing `authMethod?: string` parameter** (backward compatible -
  every real call site was updated anyway). After the existing `EventUtils.record({type: SESSION_CREATED,
  ...})` block, fires `SIGNED_IN` **awaited** (not fire-and-forget like `EventUtils`) when
  `!impersonation && authMethod`. **Deliberately gated on `authMethod` being supplied, NOT on `!elevated`**
  - this is a considered deviation from the task's own literal pseudocode (which said `!impersonation &&
  !elevated && authMethod`), made necessary by a real contradiction in the brief: it also explicitly required
  self-registration (`BaseRegistrationRoute`/`BaseUserRoute`, both of which pass `elevated: true`) to fire
  `SIGNED_IN` *in addition to* `REGISTRATION_COMPLETED` - literally impossible under a strict `!elevated`
  gate. Resolution: gate on `authMethod` presence alone. `BaseAuthElevationRoute` simply never passes
  `authMethod` on its own `createAuthResult()` call (unchanged - still 5 positional args), which
  independently achieves "no duplicate SIGNED_IN for a step-up elevation" without needing a hardcoded
  `elevated` check in `TokenUtils` itself. Documented at length in a code comment on the call site precisely
  because it diverges from the brief - re-read that comment before changing this logic again.
- **`authMethod` string per caller** (all lowercase-with-hyphens, threaded as the 7th positional arg -
  callers passing it also had to spell out `false, false` for the unchanged `elevated`/`impersonation`
  params since JS has no way to skip positional args):
  - `BaseAuthBasicRoute`: `"password"` or `"app-password"` - `verify()` has no way to tell `authenticate()`
    which matched (it only returns `user`), so it stashes `(req as any).authMethodUsed` on the app-password
    match branch (mirrors the existing `generatedAppPassword`/`generatedRecoveryCodes` req-stashing
    convention in `BaseSecretRoute`); `authenticate()` reads it back, defaulting to `"password"`. An
    app-password login now fires **both** `APP_PASSWORD_USED` and `SIGNED_IN` - intentional double-fire,
    same accepted pattern as elevation's `SESSION_CREATED` + `ELEVATED`.
  - `BaseAuthElevationRoute`: **omits `authMethod` entirely** (see the gating discussion above) - its
    `createAuthResult()` call is byte-for-byte unchanged from before this session.
  - `BaseAuthFIDO2Route` → `"fido2"`, `BaseAuthPasskeyRoute` → `"passkey"`, `BaseAuthTOTPRoute` → `"totp"`,
    `BaseAuthOTPRoute` → `"otp"`.
  - `BaseAuthMFARoute` → generic `"mfa"`, not per-factor. Investigated whether `MFAStrategy`'s
    session-tracked `req.session.mfaMethodType` could drive a more specific value (`mfa:totp`/`mfa:fido2`/
    etc.) - it can't reliably: `MFAStrategy.verifyTOTP()`/`verifyRecoveryCode()` both `delete
    req.session.mfaMethodType` before returning, but `verifyOTP()`/`verifyFIDO()` don't (pre-existing
    inconsistency in that strategy, not something this task should fix) - so the field's presence/absence at
    the route handler doesn't reliably tell you which factor matched. `RECOVERY_CODE_USED` (already fires
    its own event from `consumeRecoveryCode()`) separately covers that one factor's detail regardless.
  - `BaseAuthOIDCRoute` → `` `oidc:${this.providerConfig.name}` `` (`OIDCProvider.name` is exactly the
    per-deployment provider identifier already used to build the `provider:id` OAuth alias, e.g.
    `"oidc:google"` for a subclass configured with `providerConfig.name = "google"`).
  - `BaseAuthRefreshRoute` → **omitted entirely**, unchanged 4-arg call - the one call site that must never
    fire `SIGNED_IN`. No code change was needed here at all (already correct by omission) - only a
    clarifying comment was added.
  - `BaseRegistrationRoute`/`BaseUserRoute` (the anonymous - i.e. self-registration - branch of `POST
    /users` only; the admin-creates-on-behalf-of-someone-else branch returns before ever reaching
    `createAuthResult()`, so it needed no `authMethod` decision at all) → `"registration"`, fired alongside
    `elevated: true` per the gating resolution above.
  - `BaseOAuthAuthorizeRoute` → **N/A, not a caller at all** (see the investigation note above) - the task
    brief's own instruction to "read this carefully" for it turned out to be moot.
- **The 8 pre-existing `EventUtils.record()` call sites each gained a parallel, awaited
  `AuditLogUtils.record()` call**, reusing the same `AuthEventType` value, rebuilt into the new
  `AuditLogEntry` shape (not a pass-through - field names differ, e.g. `actorUid` not `deletedBy`): `
  BaseAccountRoute.delete()`/`.revokeSessions()` (`ACCOUNT_DELETED`/`SESSIONS_REVOKED`, `actorUid` set only
  when the caller differs from the account acted on), `BaseAuthBasicRoute` (`APP_PASSWORD_USED`),
  `BaseAuthElevationRoute` (`ELEVATED`), `BaseAuthMFARoute.consumeRecoveryCode()` (`RECOVERY_CODE_USED`),
  `BaseRegistrationRoute` (`REGISTRATION_COMPLETED`), and `BaseSecretRoute`'s five (`MFA_ENROLLED`,
  `MFA_REMOVED`, `PASSWORD_CHANGED` ×2 create/update, `APP_PASSWORD_CREATED`, `APP_PASSWORD_REMOVED` - all
  six call sites gained an `actorUid` computed the same way as `BaseAccountRoute`'s, guarded with `user?.uid`
  since a couple of this file's own pre-existing tests call `create()`/`delete()` with no `user` argument at
  all). Every one of these (plus the brand-new `IMPERSONATED` call below) follows "fail open, log loudly":
  `try { await this.auditLogUtils?.record(...) } catch (err) { this.logger?.error(...) }` - never
  `.catch(() => undefined)`.
- **`BaseImpersonationRoute.impersonate()`** gained a new, previously-nonexistent `IMPERSONATED` entry
  (`userUid` = impersonated account, `actorUid` = the trusted-role caller) right after its existing
  `createAuthResult(..., impersonation: true)` call - closes a real, total gap (impersonation had zero audit
  trail via either sink before this). Needed adding `NetUtils`/`trusted_proxies` to this route, which
  previously had neither.
- **Await vs. fire-and-forget, deliberately inconsistent with `EventUtils`'s pattern on purpose**: every
  `AuditLogUtils.record()` call in this session (both the new `SIGNED_IN`/`IMPERSONATED` ones and the 8
  parallel ones) is `await`ed, unlike the neighboring `EventUtils.record().catch(() => undefined)` calls,
  which stay fire-and-forget. Rationale: `EventUtils` is telemetry - a lost event is a shrug; `AuditLogUtils`
  is the entire point of this feature, and a real DB write through `RepoUtils` is typically fast, so the
  latency cost of awaiting it is an acceptable, deliberate tradeoff for actually knowing the write succeeded
  before responding. Verified via a microtask-flushing test on `TokenUtils.createAuthResult()`
  (`test/auth/TokenUtils.test.ts` > "Awaits the AuditLogUtils write before resolving") - a naive fixed
  2-microtask-tick check was insufficient and had to be replaced with a bounded poll-until-called loop, since
  `createAuthResult()` has its own real `await`s (JWT signing) ahead of the `AuditLogUtils` call.
- **Test coverage note**: `BaseSecretRoute.test.ts` already had several pre-existing tests that call
  `create()`/`delete()` with no `@User user` argument at all (`route.create({} as any, req)`, `route.delete(
  "id-1", undefined, undefined, req)`) - the new `actorUid` computation (`user.uid !== obj.userUid`) crashed
  on those with `Cannot read properties of undefined (reading 'uid')` until guarded as `user?.uid && user.uid
  !== obj.userUid`. Caught by running the full suite, not just the new tests, before declaring this done -
  worth remembering as a recurring pattern in this repo (see `BaseUserRoute.create()`'s own optional `user`)
  whenever a new field derived from `user.uid` is added to an existing route method whose `@User` parameter
  is typed non-optional but exercised as optional by existing tests/production self-registration paths.
- Full suite, `npx tsc --noEmit`, `npx eslint ./src ./test`: see this session's own final summary for exact
  pass/fail counts and coverage numbers at the time this was written - re-run before relying on this note if
  it's been a while. `junit.xml` restored via `git checkout -- junit.xml` per the tracked-file convention.
- Updated `README.md` (new "Audit logging" subsection under Route Handlers, plus a new Security Features
  bullet), `RELEASE_NOTES.md`'s `## Unreleased`, and `CHANGELOG.md`'s `## [Unreleased]` `### Added`. Not
  committed - per the commit-approval convention, awaiting explicit ask. Did not touch `auth-server` (a
  parallel agent is building the consuming database-backed `AuditLogUtils` subclass and admin UI for this
  exact mechanism there, in the same session) - this repo only had to produce the DI swap point, the curated
  event set, and the raw `AuditLogEntry` data for that implementation to consume; the exact shape/values
  above are what it needs to line up against.

### 2026-09-22 — `Secret.lastUsedAt` + secret lifecycle/use audit events (follow-up to app passwords)

Requested as a same-day follow-up to app passwords (see the dated entry directly below): standard
security-hygiene additions now that a `requireMFA`-bypassing credential type exists - (1) a `lastUsedAt`
timestamp on every secret, (2) new `AuthEventType`s for security-relevant secret lifecycle/use, (3)
explicitly nothing admin-facing (that's `auth-server`'s job). Read `src/auth/events.ts`'s existing
`EventUtils.record()` call sites and every `updateCredentialCounter()`/`updateSecretTimeStep()` copy across
`BaseAuthMFARoute`/`BaseAuthElevationRoute`/`BaseAuthFIDO2Route`/`BaseAuthPasskeyRoute`/`BaseAuthTOTPRoute`
first, per this repo's usual practice, before writing anything.

- **`Secret.lastUsedAt?: string`** (ISO-8601, like `usedAt` on a `RecoveryCodesSecret` code entry - NOT
  like `BaseEntity.dateCreated`, which is typed `Date`). **Absent/`undefined` for "never used" in a freshly
  constructed object or on Mongo** (an unset field simply isn't stored) **but reads back as `null`, not
  `undefined`, once round-tripped through the SQL tier** - confirmed by a real round-trip test, not
  assumed; this is pre-existing behavior every other optional `Secret` field (e.g. `hint`) already has on
  SQL, not something new this change introduces. Added to `SecretSQL`/`SecretMongo` as a plain nullable
  column, identical to how `hint` is declared/copied in each constructor.
- **`touchSecretLastUsedAt(secretRepo, uid, logger?)`** added to `src/auth/shared.ts` (not duplicated per
  route class, unlike `updateCredentialCounter()`/`updateSecretTimeStep()`, which already exist as ~4/~3
  near-identical per-route copies) - re-`findOne`s by uid (`ignoreACL: true`), writes a minimal
  `{uid, version, lastUsedAt}` patch via `update()` with `{ignoreACL: true, recordEvent: false}`, and
  **swallows every failure internally** (try/catch, optional `logger?.debug()` trace) so it never rejects -
  callers may `.catch(() => undefined)` it purely for lint (`no-floating-promises`)/defense-in-depth, not
  because it can actually throw.
- **lastUsedAt call sites - all confirmed via `grep -n "updateCredentialCounter\|lastTimeStep\|consumeRecoveryCode\|argon.verify" src/routes/*.ts`, matching the task brief's own list exactly (nothing missed):**
  - `BaseAuthBasicRoute.verify()`: both the app-password match branch and the real-password match branch
    call `touchSecretLastUsedAt()` standalone (fire-and-forget) on the one matched secret only.
  - `BaseAuthMFARoute`/`BaseAuthElevationRoute.verify()` (phase-1/elevation password check): same standalone
    fire-and-forget call on the matched password secret.
  - `updateCredentialCounter()` (×4: `BaseAuthMFARoute`/`BaseAuthElevationRoute`/`BaseAuthFIDO2Route`/
    `BaseAuthPasskeyRoute`), `updateSecretTimeStep()` (×3: the same first two plus `BaseAuthTOTPRoute`), and
    `BaseAuthMFARoute.consumeRecoveryCode()`: `lastUsedAt: new Date().toISOString()` **merged into the
    existing single `update()` call** these methods already make, rather than a second independent
    `touchSecretLastUsedAt()` call - a second write would race the first on `version` (stale-`version`
    conflict) since the first write already bumps it. This means these six merged-write call sites inherit
    the *existing*, pre-established all-or-nothing failure semantics of that write (already true before
    this change, e.g. TOTP replay-protection persistence was already required-not-best-effort) - a
    deliberate, documented tradeoff, not an oversight. Only the two genuinely-new standalone call sites
    above (`BaseAuthBasicRoute`, `BaseAuthMFARoute`/`BaseAuthElevationRoute.verify()`) needed the
    best-effort try/catch wrapper, since only they had no pre-existing write to piggyback on.
  - `BaseAuthTOTPRoute` (direct `/auth/totp`) confirmed to independently verify via its own
    `getSecrets()`/`updateSecretTimeStep()` - not merely reachable through MFA - so it's a real, distinct
    call site, not a duplicate of `BaseAuthMFARoute`'s.
- **New `AuthEventType` values** (`src/auth/events.ts`), all best-effort/fire-and-forget
  (`EventUtils.record({...}).catch(() => undefined)`) exactly like the pre-existing ones:
  - `PASSWORD_CHANGED = "auth.password.changed"` - fired from `BaseSecretRoute.create()` for a `password`
    secret, and from `update()` when `"data" in obj` for an existing `password` secret (captured *before*
    `validateUpdate()` runs, since that reassigns `obj.data` in place but never removes the key - so a
    hint-only rename, which never sends a `data` key at all, correctly never fires this). Payload:
    `{userUid, ip}`.
  - `APP_PASSWORD_CREATED = "auth.app_password.created"` / `APP_PASSWORD_REMOVED = "auth.app_password.removed"`
    - fired from `BaseSecretRoute.create()`/`delete()`, gated on `SecretType.APP_PASSWORD` specifically as a
    parallel `else if` alongside the existing `isMFASecretType(obj.type)` branch - **not** added to
    `isMFASecretType()` itself, which stays exactly "counts as a second factor" (app passwords explicitly
    don't). Payload: `{userUid, ip, secretType}`, matching `MFA_ENROLLED`/`MFA_REMOVED`'s own shape.
  - `APP_PASSWORD_USED = "auth.app_password.used"` - fired from `BaseAuthBasicRoute`'s app-password match
    branch, in addition to the generic `SESSION_CREATED` that still fires later via
    `TokenUtils.createAuthResult()` once `authenticate()` runs - intentional, not a duplicate: one says "a
    login happened", this one says specifically "MFA was bypassed for it". Payload:
    `{userUid, ip, secretUid, path}`. Needed threading an optional 3rd `req` parameter through
    `BasicStrategyOptions.verify()`/`BasicStrategy.authenticate()` (backward compatible - optional, and
    `verifySync()`/`authenticateSync()` deliberately left untouched since `BaseAuthBasicRoute` never
    overrides that sync path).
  - `RECOVERY_CODE_USED = "auth.recovery_code.used"` - fired from `BaseAuthMFARoute.consumeRecoveryCode()`
    only (confirmed `BaseAuthElevationRoute` has no recovery-code case at all - recovery codes are
    deliberately excluded from elevation, per its own existing doc comment - so there's only one copy of
    this method in the whole library). Payload: `{userUid, ip}` - `ip` needed threading an optional 3rd
    `req` parameter through `MFAStrategyOptions.consumeRecoveryCode()` and its one call site in
    `MFAStrategy.verifyRecoveryCode()`, which already had `req` in scope right there, so this was a small,
    proportionate addition rather than a disproportionate refactor.
- **Test coverage note**: this repo's `vitest.config.ts` requires 100% statements/functions/lines and 95%
  branches *globally*, not per-file - several `.catch(() => undefined)` arrow callbacks are only
  reachable by mocking the *shared helper itself* to reject (e.g. `vi.spyOn(sharedModule,
  "touchSecretLastUsedAt").mockRejectedValue(...)`), since `touchSecretLastUsedAt()` is designed to never
  actually reject on its own - mocking only the underlying `secretRepo.update()` to throw exercises its
  *internal* catch, not the outer call-site `.catch()`. Mirrors the existing convention of a dedicated
  "Does not throw when EventUtils.record() itself rejects" test per call site. Also fixed ~9 pre-existing
  unit tests across `BaseAuthMFARoute`/`BaseAuthElevationRoute`/`BaseAuthFIDO2Route`/`BaseAuthPasskeyRoute`/
  `BaseAuthTOTPRoute`/`BasicStrategy`/`MFAStrategy`/`BaseSecretRoute` whose exact-object `toHaveBeenCalledWith()`
  assertions on a merged `update()` call, or on the now-3-arg `verify()`/`consumeRecoveryCode()`, broke as a
  direct, expected consequence of this change - not a regression in anything else.
- Full suite (`npx vitest run`): **2162 passed, 1 skipped, 0 failed** across 109 files. Coverage: statements
  100%, functions 100%, lines 100%, branches 95.59% (≥ the 95% gate). `npx tsc --noEmit` and
  `npx eslint ./src ./test` both clean. `junit.xml` restored via `git checkout -- junit.xml` after the run
  per the tracked-file convention.
- Updated `README.md` (`Secret`/`App passwords`/Security Features bullets), `RELEASE_NOTES.md`'s
  `## Unreleased`, and `CHANGELOG.md`'s `## [Unreleased]` `### Added`. Not committed - per the
  commit-approval convention, awaiting explicit ask. Did not touch `auth-server` (a parallel agent owns the
  client-side/admin UI for this same follow-up there) - this repo only had to produce the raw
  `lastUsedAt` field and audit events for that UI to eventually consume.

### 2026-09-22 — App passwords (Basic-auth-only, requireMFA-bypassing credential)

Requested for the auth-server integration (a downstream mail server needs to validate legacy client
credentials via `/auth/basic` without an interactive MFA prompt). Investigated the actual code first
(`types.ts`, `shared.ts`'s `generateRecoveryCodes()`, `BaseSecretRoute.ts`, `BaseAuthBasicRoute.ts`) rather
than trusting the task's own summary, per this repo's usual practice - it held up.

- **Exact `SecretType` value: `"app-password"`** (`SecretType.APP_PASSWORD`, kebab-case like
  `"recovery-codes"`). `data` is a plain argon2 hash string, same shape as `PASSWORD` - no new `auth/types.ts`
  interface needed (unlike `RecoveryCodesSecret`/`TOTPSecret`).
- **Config key: `auth:app_password:enabled`, default `true`.** Declared independently on both
  `BaseSecretRoute` (gates *creating* new ones - `validateAppPasswordCreate()`) and `BaseAuthBasicRoute`
  (gates the `requireMFA` bypass in `verify()`) - two separate `@Config`-bound fields reading the same
  config path, not one shared source, so `BaseAuthBasicRoute` doesn't need `BaseSecretRoute` mounted.
  Disabling it never deletes an existing app password - a disabled-then-reenabled one just works again.
- **One-time plaintext response field: `password`** (top-level, alongside the rest of the `Secret` fields;
  `data` is deleted). Mirrors `RecoveryCodesSecret`'s `codes` field exactly - stashed on
  `(req as any).generatedAppPassword` by `validateAppPasswordCreate()`, consumed once by
  `sanitizeSecretForResponse()`, never persisted, never recoverable after that one response.
- **`hint` is required** (not optional, unlike every other secret type) - trimmed, 1-100 chars after
  trimming - since an account can accumulate several app passwords and the label is the only way to tell
  them apart later. Any caller-supplied `data` is silently discarded and regenerated server-side, same
  reasoning/pattern as `generateRecoveryCodes()`.
- **`generateAppPassword()` in `shared.ts`**: single value (not a batch, unlike recovery codes), Crockford
  Base32 (`RECOVERY_CODE_ALPHABET`, reused not re-declared), 30 characters (150 bits - recovery codes are
  10 chars/50 bits, deliberately much shorter-lived than a standing credential) grouped in dashes of 5 to
  match recovery codes' own readability convention.
- **`BaseAuthBasicRoute.verify()` ordering (the security-critical part): app-password check runs
  immediately after the "user not found" dummy-timing branch and BEFORE the `requireMFA` gate; the existing
  real-password path (requireMFA check + `PASSWORD`-secret loop) is completely unchanged below it.** A
  match returns the user immediately, which is the intentional `requireMFA` bypass - that's the entire
  point of the feature. Verified with a **plain `argon.verify(secret.data, password)`** - never
  `normalizePasswordSubmission()` - since an app password is only ever pasted as literal plaintext by a
  legacy client; there's no client-hashing concept for it. Timing-safety mirrors the existing
  `PASSWORD`-secret loop's own shape exactly: zero app-password secrets burns one `verifyDummyPassword(password)`
  call (no `userUid`/`config` args, since there's no normalization branch to equalize against); one or more
  triggers real per-candidate `argon.verify()` calls, no additional dummy burn. This means the *presence vs.
  absence* of app-password secrets on an account is theoretically a (very weak) timing signal on top of the
  existing `requireMFA`-vs-not signal `verifyDummyPassword()` already protects - deliberately accepted, not
  missed; equalizing it would need a fixed-shape dummy-vs-real burn independent of candidate count, which
  the existing `PASSWORD` loop doesn't do either.
- **`validateUpdate()`'s switch**: added an `APP_PASSWORD` case that throws immutable-data-cannot-be-modified,
  identically to FIDO2/PASSKEY/RECOVERY_CODES. Confirmed (not just assumed) that a hint-only update (no
  `data` key in the request body) bypasses the whole switch via the pre-existing `if ("data" in obj)` gate -
  so renaming an app password without rotating it already works for free, and has a regression test proving
  it (`validateUpdate` > "Allows renaming...").
- **Deliberately NOT built (scope decisions, not oversights - don't rediscover these):**
  - **Not added to `isMFASecretType()`.** An app password must never be offered/counted as a second factor.
    Confirmed `PASSWORD` secrets already fire no `auth.mfa.enrolled`/`auth.mfa.removed` event either (same
    array exclusion), so `APP_PASSWORD` firing none is consistent with existing behavior, not a new gap.
  - **No admin-facing exposure, no usage-count limit, no "last used" timestamp, no new `AuthEventType`.**
    Flagged to JP as possible follow-ups (audit-log visibility into app-password creation/use would be the
    most obviously useful one if this feature sees real adoption), but out of scope for this pass.
    **Superseded 2026-09-22 (later the same day)** - the "last used" timestamp and new `AuthEventType`s were
    built as the very next follow-up; see the dated entry directly above this one (this file's newest-first
    order) for what actually shipped. Admin-facing exposure is still out of scope for this repo (an
    `auth-server` concern).
- Full `yarn test:prod`-equivalent run (`npx vitest run` + `npx tsc --noEmit` + `npx eslint ./src ./test`):
  see this session's own summary for the exact pass/fail counts and coverage numbers at the time this was
  written - re-run before relying on this note if it's been a while.
- Updated `README.md` (new "App passwords" subsection under Route Handlers, plus the `Secret`/`BaseSecretRoute`
  bullet lists and a new Security Features bullet), `RELEASE_NOTES.md`'s `## Unreleased`, and `CHANGELOG.md`'s
  `## [Unreleased]` `### Added` per the doc-ownership/pre-release-changelog conventions above. Not committed -
  per the commit-approval convention, awaiting explicit ask. Did not touch `auth-server` (a parallel agent
  owns the client-side UI for this same feature there).

### 2026-09-21 — WhatsApp as an OTP delivery channel for verified phones

Requested by JP for the auth-server (uses `@rapidrest/core` 6.x `MessagingUtils.sendWhatsApp()`). Decisions:

- **Only offered when configured, decided in one place**: `isWhatsAppConfigured(messagingUtils)` in `shared.ts` —
  the messaging utils' optional `isWhatsAppConfigured(): boolean | Promise<boolean>` hook (authoritative, re-checked
  every call, a throwing hook == false), else core's private `whatsapp` field (`(mu as any).whatsapp`, truthy once
  `init()` accepted the config). Four routes call it; nothing is copy-pasted or cached.
- **Existing SMS/e-mail entries, ids and shapes are untouched** — WhatsApp is always an *extra* entry after the phone's
  SMS one. MFA/Elevation method id is `<alias uid>:whatsapp` (`toWhatsAppMethodId`/`parseWhatsAppMethodId`); `getMethod()`
  resolves it *before* the secret/alias lookups (a secret is never reachable through a suffixed id), re-checks
  configured + ownership + verified + phone, and builds `data.contact` from the alias itself, so the code can only
  ever go to that user's listed phone. The MFA/elevation challenge phase is what sends (`method.data` -> `notifyContact`);
  the verify phase only checks the code, so no channel is re-resolved there.
- **OTP sign-in**: optional `channel: "whatsapp"` beside `id` in the challenge request, forwarded as a new optional
  2nd arg of `OTPStrategyOptions.getContact(id, channel?)`; any other value keeps the default channel. Unverified /
  non-phone / not-configured => `undefined` => the same silent 200 as an unknown contact (anti-enumeration).
- **`BaseAuthDiscoverRoute`** hint shape: extra `{contact, type: "phone", channel: "whatsapp"}` (not a new `type`), so
  an old client's `type`-keyed label lookup keeps working; it now injects `MessagingUtils`.
- **Left as-is on purpose**: `BaseAliasRoute`/`BaseProfileRoute`/`BaseRegistrationRoute` verification and registration
  codes stay e-mail/SMS — they have no request-side channel choice, target *unverified* contacts, and would need their own
  template fields; not trivial/safe to bolt on.
- `peerDependencies["@rapidrest/core"]` still says `5.x` (the devDependency is 6.x); `sendWhatsApp` needs 6.x. Not
  changed here (package.json is the release process's to touch) — flagged to JP.

### 2026-09-10 — Client-side pre-hashed (Argon2id) password support, dual-mode

JP wants clients capable of it to hash a password locally (Argon2id) before ever sending it, so the
real password never reaches the server — while still supporting incapable clients sending plaintext,
with **both accepted for the same account/credential** (JP's explicit choice over locking a credential
to one mode — see plan at `C:\Users\caska\.claude\plans\a-new-use-case-cosmic-eclipse.md`).

- **Key design insight, found during planning**: `argon2.hash()`/`argon2.verify()` are already opaque
  about *what* they're hashing. The whole feature is one shared canonicalization step
  (`normalizePasswordSubmission()` in `shared.ts`) inserted before the existing hash (create/change-
  password) and verify (login) calls — **no new stored fields, no new request fields, no new
  endpoints, no schema changes**. A submitted value already shaped like a real Argon2id PHC string
  (`isClientHashedFormat()`) is used as-is (after a minimum-cost-parameter floor check —
  `PasswordConfig.client_hash_min_*` — closes off a hand-crafted fake-hash smuggling a weak credential
  past plaintext strength rules); anything else is plaintext, hashed here into the same form a capable
  client would have produced (`deriveClientSalt(userUid)` = `SHA-256(uid)` + fixed
  `CLIENT_ARGON2_PARAMS`, exported as the interop contract for downstream client implementations).
  `uid` (not email/username) is the salt input specifically so it's stable across alias changes and
  ambiguity-free when an account has multiple aliases — the tradeoff is a capable client can't
  pre-hash until it has learned the account's `uid` from a prior real login, so first-login-per-device
  naturally/gracefully falls back to plaintext.
- **Initially missed one of three real password-verify call sites**: `BasicRoute`/`ElevationRoute`
  were the obvious ones, but `BaseAuthMFARoute.verify()` (password-as-first-factor before the 2FA
  challenge, wired via `options.verify = this.verify.bind(this)`) is a third, easy to miss because
  `MFAStrategy.ts` (a *different* file) has its own unrelated `argon.verify()` for recovery-code replay
  — don't conflate the two when grepping for "MFA password" call sites again.
  `BaseAuthElevationRoute.verifyPasswordOnly()` needed no separate change — it just delegates to
  `verify()`.
- **`DefaultAccounts.ts` bypasses `BaseSecretRoute` entirely** (calls `argon.hash()` directly, never
  through `validateCreate()`), so it needed the same `normalizePasswordSubmission()` call added
  explicitly or a default-provisioned account's password would silently stop being loginable under the
  new normalize-then-verify login path. Worth re-checking for any *other* direct `secretRepo.create()`
  of a `PASSWORD` secret that bypasses the route layer if this area changes again.
- **Wide, mostly-mechanical integration-test fallout**: any fixture building a `Secret`/`SecretSQL`/
  `SecretMongo` via a raw `argon2.hash(plaintext)` and then exercising a *real* login (Basic/MFA/
  Elevation, or anything that logs in as a prerequisite — refresh tokens, impersonation, OAuth
  authorize/token flows) broke, since login now normalizes the submitted plaintext into a different
  canonical form before comparing. Fixed ~14 files (`test/routes/{sql,mongo}/{AuthBasicRoute,
  AuthMFARoute,AuthElevationRoute,AuthRefreshRoute,ImpersonationRoute,OAuthAuthorizeAndTokenRoute,
  OAuthUserInfoAndDiscoveryRoute}.test.ts` + `SecretRoute.test.ts`'s two password-rotation assertions)
  by routing the fixture's hash through the same `normalizePasswordSubmission()` call (delegated the
  bulk of this sweep to a subagent, verified the diffs myself after). **Did not** need to touch
  `AccountRoute.test.ts` (JWTs minted directly there, no real password login in the flow) or any
  `clientSecretHash` fixture (OAuth *client* secrets — separate `ClientAuthUtils` code path, untouched
  by this feature) — confirms the earlier instinct that not every `argon2.hash("password")` site needed
  fixing, only ones on a path that actually re-verifies through the new normalize step.
- Full `yarn test:prod`: 103/103 files, 1896/1897 tests (1 pre-existing deliberate skip), 100%
  statements/functions/lines, 95.42% branches (≥95% threshold). `yarn build` clean.
- Updated `README.md`/`RELEASE_NOTES.md`/`CHANGELOG.md` per the doc-ownership/pre-release-changelog
  conventions above. Not committed — per the commit-approval convention, awaiting explicit ask.

### 2026-09-08 — Integration tier fixed: a session-local zombie process, plus a real root-caused `@rapidrest/core` bug

Asked to "fix the integration-tier failures" (the 42-file red state documented in the session below).
Found and fixed two entirely separate things - **no changes needed in this repo for either**:

1. **A leftover zombie `node.exe` process (a prior `vitest` worker from earlier in this same session that
   never got torn down) was squatting on port 3000**, silently absorbing every integration test's real HTTP
   requests instead of that test's own freshly-started `Server` (whose own `listen()` on the same fixed
   port - `Server.ts` defaults to `3000` when `config.get("port")` is unset, which `test/config.ts` never
   sets - was failing to bind, but `Server.ts` logs "Listening on ...3000..." unconditionally regardless of
   whether `app.listen()` actually succeeded, so nothing here surfaced the real cause). Every request landed
   on the zombie's own already-torn-down routes, hence a 404 on literally everything, indistinguishable at
   the assertion level from a real routing failure. `netstat -ano | grep :3000` + `Stop-Process` fixed it
   instantly - went from 0/42 integration files passing to 49/56 (all `test/routes/{sql,mongo}` files, once
   counted alongside the OAuth `1-assertion` smoke files not in that original 42 count). **Lesson: if a
   from-scratch, freshly-checked-out-repo integration run 404s on literally everything including routes
   confirmed present in the startup log, check `netstat` for something already squatting on the server's
   port before suspecting the router/framework** - this reproduces identically whether the zombie is truly
   stale or is itself a previous integration test's own leftover process.
2. **The remaining ~7 files (the actual, long-documented "ObjectFactory/ClassLoader flake" - see
   [[project_rapidrest_core_sibling]]) got a real root cause and fix, in `@rapidrest/core`, not here.**
   `ClassLoader.load()` processed a directory's sibling files *concurrently* via `Promise.all`, each one
   independently `import()`-ing its own module. Two sibling route files that both (directly or indirectly)
   import the same not-yet-loaded module (here: `TokenUtils`, imported by both `BaseUserRoute.ts` and
   `BaseImpersonationRoute.ts`) raced to trigger its first evaluation; the loser saw the shared class export
   as `undefined`, then handed that to `ObjectFactory.register()`, which throws reading `.fqn` off it -
   exactly the signature documented in the linked memory across a dozen prior sightings, now reproduced
   deterministically (confirmed 3/3) for a single file (`test/routes/sql/UserRoute.test.ts`) run completely
   alone - the "needs 2+ `Server.start()`s in one process" framing in that memory undersold it: it only takes
   2+ sibling files in the same directory scan, which a single `Server.start()`'s own route directory
   already has plenty of. Root-caused precisely by adding one-off debug logging to `ObjectFactory.initialize()`
   (`core/src/ObjectFactory.ts`) and `BaseUserRoute.ts` confirming `TokenUtils` really was `undefined` at
   import time, then `npx madge --circular src/` ruling out a real circular dependency in this repo's own
   source - the race is in `@rapidrest/core`'s loader, not anything here. Fixed there by loading directory
   entries sequentially instead of via `Promise.all` (order doesn't affect the resulting class map, so this
   is a cold-start-time cost only, not a behavior change) - full `@rapidrest/core` suite still green, its own
   `ClassLoader.test.ts` still green, and **4 consecutive full runs of this repo's entire integration tier
   (`test/routes/sql` + `test/routes/mongo`, 56 files) all passed 56/56**, plus one complete `yarn test:prod`
   equivalent run of the whole 103-file suite (1863/1864, 1 pre-existing deliberate `it.skip`). Verified
   locally by rebuilding `@rapidrest/core` and overlaying its `dist` into this repo's `node_modules` (same
   technique as the `RateLimiter`/`@RateLimit` work below), then flagged to the user rather than committed
   unasked, per standing commit-approval convention. JP committed and published it as `@rapidrest/core@5.2.2`
   same-day (also republished `@rapidrest/service-core@1.7.2`, no functional change noted). This repo's
   devDependencies were re-verified against the real published packages (not the local overlay) via a
   genuine `yarn install`, then re-ran the same checks: full `tsc`/lint clean, 3 more consecutive full
   103-file suite runs all green (1863/1864 - the same 7 total clean runs now span both the local-overlay
   and real-published verification passes).
- **Coverage gap found and fixed (follow-up, same session):** the full coverage-gated `yarn test:prod`
  surfaced a pre-existing, unrelated 99.97%-lines shortfall - `src/auth/shared.ts`'s `verifyPkce()`'s
  `PKCE_VERIFIER_PATTERN.test(verifier)` early-return-false guard (a malformed/wrong-length/wrong-charset
  `code_verifier`) had no test hitting it. `test/routes/BaseOAuthTokenRoute.test.ts` covered "missing" and
  "well-formed but doesn't match the challenge" but not "doesn't even match the RFC 7636 shape" - a
  genuinely distinct code path (returns `false` before ever reaching the hash/compare). Added one sibling
  test alongside the existing two, asserting the same externally-observable `invalid_grant` outcome (the
  three failure modes aren't meant to be distinguishable to the caller). **Confirmed with two consecutive
  full `yarn test:prod` runs, both exit 0: 103/103 files, 1864/1864 tests (1 pre-existing deliberate skip),
  100% statements/functions/lines, 95.59% branches (≥95% threshold).**

Follow-on to the `RateLimiter` move below: JP added `@RateLimit()` directly to `@rapidrest/service-core`
(`RouteDecorators.ts` + `RouteUtils.checkRateLimiter()`) — a method/class-level decorator that throttles a
route via `RateLimiter.checkAndIncrement()`, keyed on the literal `` `${req.method} ${req.path}` `` of the
request. Full design/tradeoff writeup lives in service-core's own NOTES.md (2026-09-08 entry); the short
version: `req.path` includes real resource ids, so this is per-resource for a parameterized route but a
single identifier **shared by every caller** for a fixed-path route — safe only where that global sharing is
actually the intended shape, not a substitute for the existing per-identifier `checkAndIncrement()` calls.

- **Applied `@RateLimit()` to four routes, chosen specifically because none of them fit the existing
  per-identifier scheme**, not as a blanket sweep:
  - `BaseOAuthDiscoveryRoute.discovery()` / `BaseOAuthJwksRoute.jwks()` — public, unauthenticated, no
    identifier available at all (no username/client_id/user-uid in the request). `jwks()` additionally
    does a real repo read per call, unlike discovery's static-ish response.
  - `BaseOAuthClientRoute.regenerateSecret()` — `POST /clients/:id/regenerate-secret`; `req.path` carries
    the real `:id`, so this is effectively per-client, protecting against a caller looping the call and
    repeatedly invalidating that client's live secret out from under it (a self-inflicted DoS this
    operation had no other guard against).
  - `BaseImpersonationRoute.impersonate()` — fixed path, deliberately global despite that: an attacker
    with a compromised trusted-role token would rotate the *target* `userUid` on every request, which a
    counter keyed on the target (the natural per-identifier choice) structurally cannot catch. The
    endpoint's real population (trusted-role holders) is small and legitimately low-volume, so a shared
    cap is a correct fit here in a way it wouldn't be for a public identity endpoint.
- **Deliberately did NOT touch any of the existing manual `checkAndIncrement(identifier, undefined, req)` call
  sites** (Basic/MFA/OTP/TOTP/FIDO2/Passkey/Discover/Elevation auth routes, alias/profile/registration
  contact verification, the three OAuth token/introspect/revoke routes). Swapping any of those to
  `@RateLimit()` would replace a narrow, correct per-identity throttle with one shared bucket for the
  entire caller population at the *same* default config (5 attempts/300s) — the 6th unrelated legitimate
  login anywhere in the deployment within a window would 429, not just an attacker. Also skipped
  `BaseAuthRefreshRoute`/`BaseOAuthAuthorizeRoute`/`BaseOAuthUserInfoRoute` even though they have no
  current rate limiting either: all three are realistically high-traffic for any live deployment (session
  refresh, OAuth login, RP profile fetch), so a shared 5/300 cap there would false-positive under normal
  load, not just abuse — a materially different risk profile from the four picked above, which are all
  either genuinely rare (impersonation, secret regeneration) or cacheable/low-value-per-hit (discovery,
  jwks).
- Verified via full typecheck + lint + the 4 routes' own unit tests + the full 47-file/1368-test unit
  suite (integration tier still red, unrelated — see below) after rebuilding and overlaying service-core's
  dist into this repo's `node_modules` (same unpublished-dependency situation as the `RateLimiter` move).
- **Update once JP published: `@rapidrest/service-core@1.7.0`'s `checkRateLimiter()` middleware never
  called `next()`** — confirmed directly against the real npm tarball, not just source: any route carrying
  `@RateLimit()` would hang before reaching its handler, even on the success path (no limit exceeded).
  JP fixed and published `1.7.1` same-day; re-verified the fix against that real published tarball too
  (`try`/`catch` around `checkAndIncrement()`, `next()` on success / `next(err)` on throw) before bumping
  this repo off the temporary `node_modules` overlay to a real `yarn install`. Both `package.json` ranges
  now read `^1.7.1` (peer was still `^1.7.0` — bumped since `1.7.0` alone is functionally broken for any
  consumer of `@RateLimit()`, not just untested).

### 2026-09-08 — `RateLimiter` moved out to `@rapidrest/service-core`

JP's call: the rate limiter is a general framework utility, not an auth concern. Moved wholesale to
`@rapidrest/service-core` (`src/RateLimiter.ts` + `test/RateLimiter.test.ts`, all 33 tests ported and
passing there), and this repo now imports it from the package.

- **Clean break on naming, chosen deliberately over a compat shim** (JP picked this when asked): the
  class is no longer auth-namespaced. `auth:rateLimit` → `rateLimit` (config path), `auth:ratelimit:*`
  → `ratelimit:*` (cache keys), `auth.ratelimit.exceeded` → `ratelimit.exceeded` (event). The event
  type is now `@rapidrest/service-core`'s exported `RATELIMIT_EXCEEDED_EVENT` const;
  `AuthEventType.RATELIMIT_EXCEEDED` was deleted. Documented under a new `### Breaking Changes`
  heading in `RELEASE_NOTES.md`'s `v2.0.0-beta.4` section.
- **No re-export from this library** (also JP's call). `RateLimiter` was never in `src/auth/index.js`
  anyway, so it was already package-private — downstream code must import it from
  `@rapidrest/service-core`. The 15 route classes that `@Inject(RateLimiter)` now import it from there.
- **Do not reintroduce an auth-side subclass to re-namespace it.** Two dead ends found while designing
  this, both worth not rediscovering:
  - Re-declaring `@Config("auth:rateLimit")` on a subclass property does **not** override the base's
    `@Config`. `ObjectFactory._getOrBuildMetadata()` walks the *whole* prototype chain and `push`es
    every match, then `initialize()` assigns them in collection order — subclass first, base last — so
    the **base** path wins and silently clobbers the override.
  - Two classes both named `RateLimiter` (base in service-core, subclass here) collide in the factory
    registry: instances are keyed `` `${className}:${name}` `` off `_fqn || constructor.name`, so both
    would fight over `RateLimiter:default`. A subclass would have to be renamed.
  If per-consumer namespacing is ever actually needed, the supported route is
  `@Inject(RateLimiter, { name: "...", args: [...] })` — `InstanceOptions` carries both.
- **`@rapidrest/service-core` dep bumped to `^1.7.0`** (peer + dev). That version does not exist yet —
  service-core is at `1.6.0` and the move is unreleased, so `yarn install` here will not resolve until
  JP publishes it. Verified locally by overlaying the freshly-built `dist/lib/RateLimiter.js` +
  `dist/types/RateLimiter.d.ts` (and the index export line) into `node_modules/@rapidrest/service-core`.
- **`yarn build` + lint clean; 788 tests across the 22 affected unit-test files pass.**
- **Pre-existing, unrelated: the entire real-server integration tier is red on `main`.** All 42
  `test/routes/{sql,mongo}/*.test.ts` files fail — every route 404s and
  `BackgroundServiceManager` logs `Failed to start service: DefaultAccountsSQL`. This is **not** the
  known multi-file `ObjectFactory`/`ClassLoader` flake: it reproduces for a single file run in
  isolation. Confirmed pre-existing by stashing this session's changes and re-running the full suite —
  identical 42-file failure set before and after (`comm` diff of the two junit runs was empty; only the
  test *count* moved, 417 → 380, because the 33 RateLimiter tests left this repo). Most likely the
  unpublished `@rapidrest/core` `ClassLoader` fix, since this repo's installed `@rapidrest/core` is
  `5.2.0` and `@rapidrest/service-core` is `1.3.0`. Left untouched — out of scope for the port.

### 2026-09-06 — full test coverage added for the new BaseImpersonationRoute ("login as user")

JP added `BaseImpersonationRoute` (+ SQL/Mongo bindings) and a `TokenUtils.createAuthResult()`
`impersonation` parameter himself; this session added the full 3-tier test suite for it and found two
real bugs along the way — exactly the value of the real-server integration tier over mocked unit tests.

- **Real bug #1 (fixed by this session, approved by JP): `impersonate()`'s target-user lookup had no
  ACL bypass.** `this.userRepo?.findOne(body.userUid)` was called with no `options` at all, so
  `RepoUtils.findOne()`'s ACL check ran with `options.user` undefined - deny-by-default - meaning
  impersonation could never succeed against a real ACL-enabled deployment, regardless of the caller's
  actual trusted role. The isolated unit tests (mocked `userRepo.findOne`) couldn't see this; only the
  real-server integration test, which exercises the real `RepoUtils` permission path, caught it. Fixed
  by adding `{ ignoreACL: true }` - the caller is already authorized by `@RequiresTrustedRole()` at the
  route level, so this internal lookup is exempt from the *target's* own ACL by design.
- **Real bug #2 (found by this session, fixed by JP directly): `stopImpersonating()` was gated by
  `@RequiresTrustedRole()` too, making it unreachable once impersonation started.** By the time you'd
  call it, the caller's active `jwt` cookie has already been overwritten with the impersonated target's
  own (non-trusted) token - so the trusted-role check on the *stop* endpoint always failed. Fixed by
  removing `@RequiresTrustedRole()` from `stopImpersonating()`: it stays behind `@Auth(["jwt"])` (some
  valid session still required), but authorization is really just "do you possess a genuine, signed
  `jwt_impersonator` cookie" - which only a prior, real, trusted-role-gated `impersonate()` call ever
  sets. Matches the class's own doc comment ("if one is present").
- **Test structure**: `test/routes/BaseImpersonationRoute.test.ts` (16 isolated unit tests, mocked
  `userRepo`/`tokenUtils`), `test/auth/TokenUtils.test.ts`'s new `impersonation` describe block (4
  tests: empty refresh token, access-cookie-only, session untouched, no `SESSION_CREATED` event), and
  `test/routes/{sql,mongo}/ImpersonationRoute.test.ts` (6 real-server tests each) - the latter drive the
  actual login -> elevate -> impersonate -> stop flow purely via cookies through a real `agent()`, no
  Authorization header at all for the impersonate/stop calls, proving the cookie-only design actually
  works end-to-end. New `test/server-{sql,mongo}/routes/ImpersonationRoute.ts` mount at `/{sql,mongo}/
  admin`, matching the class doc comment's own `@ApiRoute("admin")` example.
- **`yarn build` clean; all impersonation-specific tests pass reliably across repeated runs.** A full
  `yarn test:prod` run showed the known `ObjectFactory`/`ClassLoader` flake (see
  [[project_rapidrest_core_sibling]]) at an unusually high rate this session - see that memory file's
  latest entry for the investigation (a stray leftover sqlite file was ruled out; suspected
  session-accumulated environmental strain from a very long run of test invocations, not a real
  regression). None of the flaking files were touched by this work.

### 2026-09-06 — `RateLimiter`'s Redis-backed `INCREX` call had no fallback, breaking login outright on any Redis older than 8.8

Traced from a downstream `auth-server` bug report: JP hit a real login failure while testing OAuth
locally (`yarn dev`, which boots a real (if ephemeral) Redis via the `cli` repo's `redis-memory-server`
integration). Once a separate logging bug (masking the real error message - see `auth-server`'s own
`.claude/NOTES.md`, same date, for that fix) was resolved, the real error surfaced: `ERR unknown
command 'INCREX', with args beginning with: 'auth:ratelimit:admin' 'EX' '300' 'ENX'`.

**Root cause, confirmed against Redis's own docs, not guessed**: `INCREX` is a **Redis 8.8+** command
(`since: "8.8.0"` per `redis.io/commands/increx`) - and per that same page's own compatibility table,
it isn't supported yet on **Redis Software or Redis Cloud either**, only vanilla open-source Redis
8.8+. `RateLimiter.incrementRedis()` (see the 2026-08-22 entry below - this is the code that entry's
"reverted to an atomic Redis `INCREX`-based implementation" refers to) called it unconditionally, with
no fallback and no version/capability check. On Windows, `auth-server`'s `yarn dev` doesn't run real
Redis (no official Windows build) - it downloads Memurai via `redis-memory-server`, and the locally
cached Memurai 4.2.3 is "on par with Redis 7.4.9" (confirmed via its own `Release-Notes.txt` and
`memurai.exe --version`); a Redis-8-compatible Memurai build only exists as a release candidate on
Memurai's own site, not their stable channel. **This is not just a Windows-dev-convenience gap**: since
even Redis's own commercial Cloud/Software offerings don't support `INCREX` yet, essentially any real
production deployment of this framework backed by a managed or not-bleeding-edge Redis would hit this
exact "unknown command" `ErrorReply` on every single rate-limited request (login, MFA, OTP, TOTP) -
not a degraded rate limiter, a hard 500 on authentication itself.

**Fixed**: `RateLimiter.incrementRedis()` now catches specifically an `ErrorReply` whose message
matches `/unknown command/i` (any other error - a real connectivity failure, a malformed argument -
still propagates unchanged) and falls back to the existing in-memory counter for the rest of the
process, logging one warning on the transition (not per-request) via the newly-added `@Logger`-injected
`this.logger`. A `redisIncrexUnsupported` flag remembers the fallback so subsequent calls skip straight
to memory instead of paying for (and logging) a failed round trip every time. **Deliberate, documented
tradeoff**: falling back means the per-identifier/per-IP counters stop being atomic/shared across
multiple server instances pointed at the same Redis for as long as that process runs (each instance
falls back independently and counts only its own local attempts) - a real regression from the
cross-instance guarantee `INCREX` exists for, but a working non-atomic limiter beats every login
request 500ing outright. Did **not** touch the `INCREX`-based happy path itself or revert to a
Lua-script/multi-command approach - that was a deliberate, already-reviewed design choice (see
2026-08-22 below), not something to re-litigate as a side effect of adding a compatibility fallback.
Four new tests added to `test/auth/RateLimiter.test.ts` (`INCREX unsupported by the connected Redis
server` describe block): falls back instead of throwing, logs the warning exactly once, stops calling
Redis on subsequent attempts once the fallback is latched, and does not swallow a genuine unrelated
Redis error. `yarn build` clean; `test/auth/RateLimiter.test.ts` 33/33 passing.

**Full-suite note**: a full `vitest run` on `main` (both with and without this fix, confirmed via
`git stash`) has 6-7 test files fail/flake with `TypeError: Cannot read properties of undefined
(reading 'fqn'/'name')` inside `@rapidrest/core`'s `ObjectFactory.register()`/`ModelRoute.ts`, or
otherwise-passing route tests returning `404` instead of their expected status - reproduces identically
with this change stashed out, and the exact set/count of failures varies between runs of the *same*
unchanged code. This is pre-existing parallel-worker flakiness (many `Server` instances booting
concurrently across vitest workers, plausibly a port or shared in-process state collision), not a
regression from this change or anything already investigated this session - worth a dedicated look
some other time, but out of scope here.

**Not published** - per the version standing decision, left for JP to version/publish `auth` himself.
Propagated locally into `auth-server/node_modules/@rapidrest/auth/dist/{lib/auth/RateLimiter.js(.map),
types/auth/RateLimiter.d.ts}` only (confirmed via `diff -rq` against a fresh `auth` build that nothing
else in `dist/` had drifted) so `auth-server`'s local `yarn dev` picks up the fix immediately - reverts
on a clean `yarn install`, bump the real `@rapidrest/auth` constraint once published.

### 2026-09-06 — `Client.clientId` removed entirely; `Client.uid` is now the OAuth `client_id`

While building a real end-to-end integration test in the downstream `auth-server` repo (register a
client → authorize → consent → token exchange → JWKS verify → userinfo), the very first "create a
second client" step failed: `BaseOAuthClientRoute.validateCreate()` (added in Phase A) never actually
generated a `clientId` — it silently persisted the model's own default (`""`) on every create, and
since `ClientSQL`/`ClientMongo`'s `clientId` column had a **unique index**, the *second* client ever
created in a deployment would fail outright on the unique-constraint violation.

The first fix attempt (generate `clientId` server-side, same opaque-token style as `SigningKeyUtils`'s
`kid`) was then **superseded** after the user asked the sharper question: why does `Client` need its
own separate identifier at all, when `BaseEntity.uid` is already unique, auto-generated (`uuid.v4()`),
and exposed in every API response? Unlike `SigningKey.kid` (which must stay valid across a key's
active→retired lifecycle, independent of whether the key row itself is ever renamed) there's no
equivalent lifecycle reason for `Client` to have two identities. **Decision: removed `clientId` from
`Client` entirely; `Client.uid` now serves as the OAuth `client_id` everywhere.**

- Removed the field from `types.ts`'s `Client` interface, `ClientSQL`/`ClientMongo` (including the
  `@Identifier`/`@Index("clientId", {unique:true})` decorators and constructor copy-line), and the
  now-dead clientId-generation block in `BaseOAuthClientRoute.validateCreate()`.
- Every `client.clientId` read across `OAuthTokenUtils` (`sub`/`aud`/`azp`/`client_id` claims),
  `BaseOAuthAuthorizeRoute` (issuing codes, consent tickets/grants), `BaseOAuthTokenRoute` (refresh
  token issuance, authCode/refreshToken ownership checks), and `BaseOAuthRevokeRoute` (ownership
  checks) became `client.uid`. `ClientAuthUtils.authenticateClient()` and `BaseOAuthIntrospectRoute`
  needed **no changes** — both already looked up/echoed the client by whatever value `RepoUtils`
  treats as the identifier, which is `uid` natively.
  The `clientId` *field name* is deliberately **kept** on `AuthorizationCode`/`ConsentGrant`/
  `OAuthRefreshToken` — those are legitimate foreign-key-style references to a client, just now
  populated with the client's `uid` instead of a separate identifier.
- Updated ~20 test files across unit and sql/mongo integration tiers to match (fixture `Client`
  literals no longer set `clientId`; comparisons/query params changed from `client.clientId` to
  `client.uid`). `yarn build` clean; full `yarn test:prod` run: 1789/1789 real tests passed. The only
  failures were 4 suites hit by the known `ObjectFactory`/`ClassLoader` flake (see
  [[project_rapidrest_core_sibling]]), including `UserRoute` (sql+mongo) which this refactor never
  touched — confirmed non-real by isolated re-run of every affected file.
- Added the missing real-database integration test tier this bug exposed in the first place:
  `test/routes/{sql,mongo}/OAuthClientRoute.test.ts` (Phase A had only ever gotten the isolated
  mocked-repo unit test), covering `uid` uniqueness, ownership/ACL (owner vs. admin vs. third party),
  the `firstParty` field-level rule, and secret generation/regeneration against the real persisted
  hash. **Lesson: a route this central to a cross-repo integration deserves the same 3-tier
  convention as everything else in this library from the start.**
- Not published — per standing decision, only the user runs `yarn release`. `auth-server` will need
  its `node_modules/@rapidrest/auth` patched or a fresh publish+bump, plus its own integration tests
  updated (`createClientRes.body.clientId` → `.uid`), before its OAuth integration test can proceed.

### 2026-09-05 — OAuth 2.0/OIDC authorization server (Phases 1-6 + conformance fixes + Phase A client CRUD)

- **Built full OAuth 2.0 / OpenID Connect authorization-server capability** on top of what was
  previously a relying-party-only OAuth/OIDC client library, across 6 phases (see plan saved at
  `C:\Users\caska\.claude\plans\ok-it-s-time-to-majestic-waterfall.md` on the machine this was
  built on): signing keys (RS256, encrypted at rest) + `Client` model + JWKS; Authorization Code +
  PKCE + consent + `/token`; refresh token rotation with reuse/theft detection; `client_credentials`
  grant; `/revoke` + `/introspect`; discovery metadata + `/userinfo` + `OAuthBearerStrategy`.
  Published as `@rapidrest/auth@2.0.0-beta.1`.
- **Three OIDC conformance gaps fixed** after Phase 6: `iss` claim now mandatory (throws if
  `auth:oauth_server:issuer` unconfigured), `prompt` request parameter honored at `/authorize`
  (OIDC Core §3.1.2.1), refresh-token issuance for an `openid`-scoped flow now requires
  `offline_access` (OIDC Core §11).
- **Dynamic Client Registration (RFC 7591/7592) deliberately deferred**, not just reordered — no
  concrete need for third-party self-service onboarding yet; a `Client` row can be hand-provisioned.
  Revisit only if that need actually shows up.
- **Phase A of wiring this into `@rapidrest/auth-server`**: added `BaseOAuthClientRoute` (+ SQL/Mongo
  bindings) giving `Client` real owner/admin CRUD, which it never had before (every other persisted
  model gets a `BaseXRoute`; `Client` was previously only ever consumed internally). Initially
  designed as a hardcoded admin-only gate (`ignoreACL` + in-route role check) — **rejected**: the
  user wants non-admin self-service `Client` ownership supported later without a re-architecture.
  Redesigned around the framework's existing ownership-aware ACL mechanism instead: changed
  `Client`'s `@Protect()` to `Secret`'s shape (`anonymous: []`, `.*: [CREATE]`), which combined with
  `RepoUtils.create()`'s existing auto-owner-CRUD-grant and `ACLUtils.hasPermission()`'s existing
  trusted-role bypass gives "owner manages their own client, admin manages any client" with zero
  per-route hardcoded role logic. `find()`/`count`/`exists` needed a manual ownerUid-scoped +
  `ignoreACL` override (mirroring `Secret.find()`) since `RepoUtils.find()`'s class-level ACL
  fast-fail gate would otherwise 403 a non-admin outright before per-record filtering ever runs.
  40 new unit tests, 100% coverage on the new file; committed, not published (see standing decision
  above — publish is always the user's own call).
- **Known, non-blocking test flake reconfirmed multiple times this session**: a full `yarn
  test:prod` run intermittently fails 3-4 *unrelated* suites (different ones each run — UserRoute,
  OAuthJwksRoute, OAuthAuthorizeAndTokenRoute, etc.) with `TypeError: Cannot read properties of
  undefined (reading 'fqn')` in `ObjectFactory.register`, a load-order race that needs 2+ `Server`
  instances in one process (`fileParallelism:false`). Never reproduces for a single isolated test
  file. Not the new code's fault each time it's checked — verify by running the new/changed test
  file alone before assuming a real regression.
- **`CHANGELOG.md`/`RELEASE_NOTES.md` condensed for pre-release** per the standing decision added
  above — folded the messy, auto-generated-from-verbose-commits `[2.0.0-beta.1]` section into a
  single `[Unreleased]` listing.
- **Process correction (commit approval is per-task, not blanket for the session):** committed a
  `CHANGELOG.md` cleanup unprompted, right after the user had approved committing Phase A's code —
  wrongly treated as still-standing permission. Corrected; now stricter about re-checking per commit
  every time, and about actually reading this file at the start of a session (this exact rule was
  already written above under "Commit discipline" and would have prevented the mistake).

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

### 2026-09-25 - release bump levels follow upstream

When releasing packages that depend on each other (rapidmx: restapi / react-shared -> web-client -> meet-plugin, booking-plugin, autodiscover, mapi, activesync, server; rapidrest: core / service-core -> auth / auth-server / react / cli and the projects built on them), the bump level of a downstream release matches the level of the upstream release it picks up: an upstream **minor** is a downstream **minor**, an upstream patch a downstream patch, major to major. Where a downstream bump crosses several upstream releases, use the highest level among them, and never choose "patch" just because the downstream's own diff is only a `package.json` bump. Betas keep their prerelease line but follow the same idea - say which level was chosen.

Why: meet-plugin 0.4.2 and booking-plugin 0.5.2 were cut as patches after web-client 0.15.x -> 0.16.0 and react-shared 0.17.0 -> 0.18.0 (both minors), and autodiscover 1.1.1 after restapi 0.20.1 -> 0.21.0; the downstream versions then hid additive behaviour. JP accepted those releases as they were (2026-09-25) and asked for the rule going forward. Releases only happen when JP asks for them.

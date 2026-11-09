# Release Notes

## Unreleased

### Fixed

* `DefaultAccounts` no longer fails to start when `auth:password_file` can't be written, for example in a container
  whose working directory is read-only. The accounts and their secrets already exist at that point, so the write is
  now best-effort. A failure logs an error naming the resolved path and the error code, with a hint to set
  `auth:password_file` to a writable path. The job then finishes normally. The password isn't logged in that case,
  as before, so the account's password has to be reset.

## v3.0.0

### Breaking changes

* `generateOTP()`, `verifyOTP()` and `enforceOTPIssueLimit()` have new signatures (`purpose` is required; `counters` replaces a rate limiter). These are exported helpers, so under semver this is a breaking change; choosing the version is left to the maintainer.
* Sent codes are now alphanumeric (the digits 2-9 and the letters A-Z without I, L and O), not 6 digits. Client inputs, validators and wording must accept letters.
* `session.userUid` is no longer set after the MFA password step. The pending user is in `session.mfaPendingUid` until the second factor completes.
* Generic rate limit keys for client-supplied identifiers are now `ratelimit:id:<id>` (were `ratelimit:<id>`). Old counters expire on their own.
* The `cache` connection must be Redis 7.0 or newer. The one-time code counters need `EXPIRE ... NX`; on an older server the code flows would fail, so the startup check (`OTPCounters.checkDeployment()`, now asynchronous and awaited by the routes' `@Init`) refuses to start.
* A throttled authentication strategy call (`/auth/otp`, `/auth/mfa`) answers 401 "Too many attempts. Please try again later.", not 429. Non-strategy routes still answer 429.
* `BaseOAuthSessionTokenRoute` now has an abstract `clientClass` (and a second type parameter, `BaseOAuthSessionTokenRoute<C extends Client, U extends User>`); the Mongo and SQL variants supply it. The route answers 403 unless the access token was issued to a first-party client.
* `/oauth/authorize` and its consent endpoint now require a session that completed a sign-in (`session.signedInUid`, written only by `TokenUtils.createAuthResult()`) for the authenticated user, and refuse an impersonation session. A host that authorized with a bare access token or a session cookie that never signed in through this library's routes must sign the user in first.
* Sessions created before this upgrade have no `session.signedInUid` (or `signedInAt`), so `/oauth/authorize` and its consent endpoint answer `loginRequired` (`login_required` under `prompt=none`) for them until the user signs in again or the session refreshes (a refresh goes through `TokenUtils.createAuthResult()`, which writes both).
* Startup now fails if the `cache` Redis connection is unreachable while the routes' `@Init` runs (`OTPCounters.checkDeployment()`), not only when it is older than Redis 7.0. The error says the connection is unreachable. A Redis outage during a deployment can therefore make the server crash-loop until Redis is back.
* "Sign out everywhere" (`POST /account/:id/revokeSessions`) now also stops `/oauth/authorize` and its consent endpoint: a session whose sign-in (`session.signedInAt`, written by `TokenUtils.createAuthResult()`) is older than the user's `sessionsRevokedAt` answers `loginRequired`, and so does a session whose user no longer exists. The user must sign in again. `BaseOAuthAuthorizeRoute` therefore loads the user and has a new abstract `userClass` (supplied by the Mongo and SQL variants; a host subclass of the base class must add it).
* New configuration keys: `auth:otp` (`length`, `alphabet`, `ttl`, `maxAttempts`, `limits`) with `limits.issue`, `issueTotal`, `verify`, `verifyTotal` and `user`, `userTotal`. All have defaults. `MFAStrategyOptions` has a new optional `checkPendingRateLimit`. A host that builds `MFAStrategy` itself (rather than using `BaseAuthMFARoute`) must supply it: without it phases 2 and 3 fall back to `checkRateLimit(uid)`, which can reopen the unauthenticated lockout fixed below. `BaseAuthMFARoute` wires the safe `mfa:<uid>` key.

### Security

All three problems below affect **2.0.0 and earlier**.

* **"Sign out everywhere" did not stop OAuth authorization.** `BaseAccountRoute.revokeSessions()` only stamps `sessionsRevokedAt` on the user, which the refresh route checks, but `/oauth/authorize` trusted the session's `userUid` and sign-in marker without looking at the user. A session cookie that was stolen or left behind kept being given authorization codes, and from them OAuth refresh tokens, after the owner had revoked all sessions. **Fixed:** `TokenUtils.createAuthResult()` records `session.signedInAt` (logout clears it), and authorize and consent load the user and refuse a session that signed in before `sessionsRevokedAt`, or whose user is gone. This does not revoke OAuth refresh tokens that were already issued; revoke those through the OAuth revoke endpoint.

* **An OAuth access token for any client could be exchanged for a full session.** `BaseOAuthSessionTokenRoute` traded any valid access token this server had issued for a session JWT carrying the account's roles, without checking which client the token was issued to, its audience, or its scope, so a token granted to a third-party application could be turned into the user's own session. **Fixed:** the exchange requires the token to have been issued to a registered, enabled first-party client for the authenticated user; everything else is refused with a 403. A native app signing in through PKCE with a first-party client keeps working.
* **Impersonation and stolen access tokens could obtain OAuth authorization codes.** service-core's `JWTStrategy` copies the uid of any valid access token presented with a session cookie into `session.userUid`, which `/oauth/authorize` and its consent endpoint treated as proof of a sign-in. A token minted by impersonation (which deliberately leaves the session alone), or a stolen access token, could therefore be used to obtain authorization codes, and from them OAuth refresh tokens that outlive the impersonation or the token and are missing from the impersonation audit trail. **Fixed:** `TokenUtils.createAuthResult()` also records `session.signedInUid` on a completed sign-in (logout clears it); authorize and consent require it to equal the authenticated user, and refuse a request that carries the impersonation cookie. A `userUid` written only by `JWTStrategy` no longer counts.

Both multi-factor authentication problems below affect **2.0.0 and earlier**, and **both need the victim's password**: neither lets anyone sign in without it. Each defeats the second factor, which exists to protect an account whose password has been stolen or guessed. TOTP, recovery-code and passkey factors were affected only by the second problem. Upgrade and restart; no data migration is needed. Sessions that were part-way through an MFA sign-in, and codes in flight, stop working and the user starts again.

* **The one-time-code step of multi-factor authentication accepted a code that was not issued for the account being signed in.** It did not check that the code had been issued to the user who had just passed the password step, and a code sent by any other flow in the same session (registration, passwordless sign-in, contact verification) was accepted there. Someone who knew a user's password, and so could start the MFA step for that account, could complete it with a code sent to a contact they control. **Fixed:** the MFA step requires the code to name the same user as the password step, and every one-time code is bound to the flow it was issued for (`purpose`), so a code issued by one flow is rejected, and discarded, by every other.
* **A password was treated as a signed-in session.** The password step of MFA recorded the user in `session.userUid`, the field everything else (the OAuth authorize and consent endpoints in particular) treats as proof that the session is signed in. A session that had passed only the password step could therefore be given an authorization code by `BaseOAuthAuthorizeRoute`, without the second factor. Separately, a failed second-factor attempt deleted `session.userUid`, which signed out a genuinely signed-in session that happened to run the MFA flow. **Fixed:** the password step now records the pending user in its own field, `session.mfaPendingUid`, which every MFA phase uses and which is matched against the request before anything else; the library never puts a partial identity in `session.userUid` (it is set by `TokenUtils.createAuthResult()` on a completed sign-in and by service-core's `JWTStrategy` from a valid access token), and a failed attempt clears only the pending state. Deployments that do not mount the OAuth authorize route were not exposed to the first effect, but the sign-out effect applied to all of them. A new password attempt also discards any pending identity, selected method and challenge left by an earlier one, and logout clears `mfaPendingUid` and `elevateUid` as well. Note for host code: because `JWTStrategy` copies the uid of a valid access token into `session.userUid`, a `jwt` minted by impersonation, or a stolen access token, ends up there too (this predates the change and is tracked separately), so read it as "this session holds a valid access token for that user" rather than as proof of a fresh sign-in.
* **Rate limit counters for one user could be spent by someone else.** Three causes. The generic limiter keyed on whatever identifier the client sent, so a client-chosen id could land on a counter the library keeps for a particular user's elevation attempts and use it up (this part is in 2.0.0 and earlier). The new one-time code counters were keyed by contact or user uid alone, shared by every flow, and `/auth/otp` accepts any `id` without authentication, so naming a victim's uid could have used up their MFA and elevation code allowance. And the second and third phases of MFA were limited on the client-supplied id in the same bucket as `/auth/otp`, before the request had been matched to the user who passed the password step, so anyone who knew a uid could drain it without a password. **Fixed:** every identifier taken from a request is counted under an `id:` prefix (`ratelimit:id:<identifier>`; hashed values under `idh:sha256:`), which no internal key can start with; the one-time code counters are kept under their own `auth:otp:` prefix with the flow in every key, and their contact, uid and address parts are hashed so the key shape is unambiguous; MFA phases 2 and 3 are matched to the session's pending uid first and then counted on a server-side key (`mfa:<uid>`) that no client input reaches. Neither the sign-in route nor a request that never passed the password step can touch the MFA or elevation counters. Existing `ratelimit:<identifier>` counters are not carried over; they expire on their own. Identifiers longer than 256 characters are hashed for use in a key, and a one-time code id longer than that, or not a string, is refused.
* **`auth:otp:maxAttempts` was not enforced with a Redis-backed session store.** Each request got its own copy of the session and the last write won, so parallel guesses all started from the same attempt count, and a wrong guess that finished after a correct one could restore a spent code, which then verified a second time. The per-code guess counter and the one-time claim of a successful redemption are now kept outside the session, in Redis when a `cache` connection is configured. They use only `SET key 1 NX EX`, `INCR` and `EXPIRE key ttl NX` (Redis 7.0 or later), not service-core's `RateLimiter`, whose atomic counter uses `INCREX` (Redis 8.8 or later) and quietly falls back to a per-process counter on anything older, including Redis Software, Redis Cloud and Memurai. They are correct with any number of instances sharing the `cache` connection, and they apply whether or not `rateLimit:enabled` is set. A startup check tries the transaction on a scratch key and refuses to start on a server that cannot run it (older than Redis 7.0), and a counter reply that is not a number throws, so the counters fail closed. Without a `cache` connection they are in-process, in a store of their own that holds at most 100,000 keys and evicts the oldest beyond that, which is correct for one instance but not under a flood of distinct keys. If the session store is Redis but there is no `cache` connection for the counters (a host that supplies its own session store), the routes warn loudly at startup that the protections are per-process. The generic per-identifier and per-IP limits still come from service-core's `RateLimiter` and are per-process on a Redis older than 8.8.
* **Dedicated rate limits for sent codes.** Issuing and verifying shared the generic per-identifier counter (100 per minute by default), and a new code reset the attempt count, which allowed thousands of guesses an hour against an account, multiplied by every alias that reaches it. Codes now have their own limits: 5 codes per 15 minutes per contact and IP address (and 20 per contact across all addresses), 20 verification attempts per hour per contact and IP address (and 60 per contact across all addresses), and 50 per hour per user and IP address (150 across all addresses), each counted per flow. See `auth:otp:limits`. The verification budgets are per address so a single address cannot empty a contact's allowance (5 codes of 5 guesses in an issue window would otherwise do it); the contact-wide caps remain. A verification attempt is counted only when the session holds a pending code for that contact and flow, so spending a contact's verification budget first needs codes to be sent, which is limited and visible to the contact's owner. What remains: someone who can reach `/auth/otp` can still use up a contact's issue or verification allowance by working from enough addresses (the owner is sent every one of those e-mails or messages), and at MFA an attacker with the victim's password can spend the user's issue allowance for MFA codes, which only stops the code factor for an hour and does not let them in. Neither lets anyone sign in. Other second factors remain available. The per-address keys use the address the rate limiter sees: it falls back to `unknown` when it cannot be determined, and a misconfigured `trusted_proxies` makes every user share the proxy's address.
* **Configuration is validated at startup.** An unsafe `auth:otp` block (an alphabet that is not printable ASCII or contains `-`, fewer than 20 bits of entropy, a `ttl` over an hour, `maxAttempts` over 10) stops the server from starting instead of silently weakening the codes. Numbers given as numeric strings, as environment variables are, are accepted; anything else that is not a number is still rejected. Six decimal digits are 19.9 bits and are **below** the 20-bit floor, so `{ alphabet: "0123456789", length: 6 }` is refused; use 7 digits or more.
* A submitted code longer than four times the configured length is rejected without being processed.

### Added

* **`auth:otp` config block** (`length`, `alphabet`, `ttl`, `maxAttempts`, `limits`) for the codes sent by e-mail, SMS and WhatsApp. Defaults: 6 characters, the alphabet below, 600 seconds (a duration string such as `"10m"` also works) and 5 attempts. Valid ranges: `ttl` over 0 and at most 3600 seconds, `maxAttempts` 1 to 10, `length` 4 to 64, at least 20 bits of entropy (`length * log2(alphabet size)`), `alphabet` printable ASCII without `-`.
* **`auth:otp:limits`**: `issue` (default 5 per 900 seconds, per contact and IP address), `issueTotal` (20 per 900 seconds, per contact across all addresses), `verify` (20 per 3600 seconds, per contact and IP address), `verifyTotal` (60 per 3600 seconds, per contact across all addresses), `user` (50 per 3600 seconds, per user the code was issued for and IP address, across every contact) and `userTotal` (150 per 3600 seconds, per user across all addresses). They apply in addition to the generic limits, are shared across instances through the `cache` connection, and are switched off by `rateLimit:enabled: false` (the guess counter and the one-time claim are not). The framework reports an error thrown by an authentication strategy, these limits included, as a 401 carrying the message "Too many attempts. Please try again later."; non-strategy routes (registration, alias and profile verification) answer 429.
* **`OTPCounters`**, exported from `auth`, is the class behind the counters above (`claim()`, `increment()`, `throttle()`, and `checkDeployment()`, which is asynchronous and throws on a `cache` connection older than Redis 7.0). The routes inject it; `OTPStrategyOptions` and `MFAStrategyOptions` have `otpConfig` and `counters` fields, which the routes fill in; `MFAStrategyOptions` also has an optional `checkPendingRateLimit(uid, req)` for phases 2 and 3 (falls back to `checkRateLimit` with the same uid, which can reopen the lockout, so a host that builds `MFAStrategy` itself must supply it; `BaseAuthMFARoute` wires the safe `mfa:<uid>` key). New `OTPConfig`, `OTPLimits`, `OTPPurpose`, `OTPContext` and `CounterLimit` types, `DEFAULT_OTP_*` constants, `isOTPChallengePending()`, `resolveOTPConfig()`, `enforceOTPIssueLimit()` and `clientRateLimitKey()`. `OTPContact` has an optional `userUid`, which `BaseAuthOTPRoute` fills in.
* **A one-time code is bound to a purpose and to the user it was issued for.** `verifyOTP()` accepts a code only for the purpose it was issued for (`login`, `mfa`, `elevate`, `register` or `contact`), and the per-user limit uses the user recorded in the challenge, so sign-in no longer looks the user up before the code has been checked.

### Changed

* **`generateOTP()`, `verifyOTP()` and `enforceOTPIssueLimit()` take new arguments (breaking for code that calls these exported helpers directly).** `generateOTP(req, data, config, purpose, userUid?)`, `verifyOTP(req, payload, config, purpose, { counters }?)` and `enforceOTPIssueLimit(req, id, config, purpose, { counters }?)`. There is deliberately no default purpose: a default would make a caller that forgot it interchangeable with every other flow. Use `"login"` for passwordless sign-in, `"mfa"` for the MFA second factor, `"elevate"` for step-up, `"register"` for new accounts and `"contact"` for alias or profile contact verification. `verifyOTP()` throws a 429 `ApiError` when the per-contact or per-user limit is hit, and `BaseAliasRoute`, `BaseProfileRoute` and `BaseRegistrationRoute` pass that on instead of reporting an invalid code. The strategy and route classes keep their public signatures.
* **Hosts that read the MFA session state:** after the password step of MFA, `session.userUid` is no longer set; the pending user is in `session.mfaPendingUid` until the second factor completes. `session.userUid` is set by a completed sign-in and by service-core's `JWTStrategy` from a valid access token, and is never given a partial identity by this library. The password step's response (`{ uid, methods }`) is unchanged.
* **Sent codes are now 6 characters, case-insensitive and alphanumeric, not 6 digits.** They use the digits 2-9 and the letters A-Z without I, L and O, are generated with `crypto.randomInt` and are shown upper case. Entry ignores case, surrounding whitespace and internal spaces or hyphens. **Anything downstream that validates these codes as digits only must be updated** - for example a numeric-only input (`inputmode="numeric"`, a `[0-9]` filter, a 6-digit `pattern`) or "6-digit code" wording. Authenticator app (TOTP) codes are still 6 digits. The `totp` messaging template variable keeps its name and now holds the sent code.
* **The session no longer holds the code.** `req.session.otp` keeps an HMAC-SHA256 of the code with a per-challenge salt, the purpose, the user (when known), the issue time and an attempt counter; `req.session.id`, `secret` and `token` are no longer written for sent codes. Codes are compared in constant time.
* **A wrong code no longer discards the challenge.** It counts as one of `auth:otp:maxAttempts`; the code is consumed by a successful verification, by expiring, by running out of attempts, or when submitted for a different id. `BaseAuthMFARoute` and `BaseAuthElevationRoute` keep their session-bound identity after a wrong code while the challenge is live, so a typo can be retried there too. Any other outcome clears it, a rate limit (429) included: after a throttled attempt the user starts the MFA or elevation step again.

### Fixed

* **The session-token exchange (`POST /oauth/session-token`) changed the caller's own session.** It ran the full sign-in routine, which overwrote the session's `userUid` and `refreshUid`, minted a refresh token nothing could use, and updated `ip`, `lastAccess` and `lastLogin`, then patched `signedInUid` back. It now only mints the access token (`TokenUtils.createAccessToken()`) and leaves the session exactly as it was. The response is unchanged: `{ token }`, never `refresh`.
* **The `cache` startup check blamed the Redis version for every failure, and was looser than the counters.** It accepted numeric-looking replies that `OTPCounters.increment()` rejects. It now applies the same strict number check, and tells a command or syntax error reply (`ERR ...`, an unsupported version) apart from a connection failure (refused, timed out, closed), which is reported as "the `cache` connection is unreachable".
* **`BaseAuthMFARoute` and `BaseAuthElevationRoute` left their session-bound identity behind when verification threw** (no pending code, a code for a different id, or a rate limit). It is now cleared on every error, including a refusal by the generic rate limit before verification starts. Elevation answers a failed code with 401 rather than an error.
* **E-mail, SMS and WhatsApp codes expired after 0-30 seconds.** Sent codes were generated with TOTP using otplib's defaults (a 30 second step and no tolerance), so a code was valid only until the end of the 30 second step it was issued in, whenever that fell. A message that took longer than that to arrive or be read could never be used. This affected OTP sign-in, registration (`/registration/start` and `/verify`), alias and profile contact verification, e-mail/SMS elevation and the MFA OTP step. Codes now last `auth:otp:ttl` (10 minutes by default). The window was never longer: it has been this way since the initial commit (2026-07-19). What changed on 2026-07-21 (a57be17) is that the challenge started being discarded before the code was checked, so a single typo forced a resend; before that, retrying within the same step worked, which is probably what looked more lenient. That too is fixed.

## v2.0.0

### Changed

* **`@rapidrest/core` peer dependency is now `6.x`** (was `5.x`). Features such as WhatsApp delivery via
  `MessagingUtils` already required 6.x; the declared peer range now says so.

### Fixed

* **Password sign-in failed for every existing account under `argon2` >= 0.45.2.** That release writes Argon2 hash
  parameters as `m,t,p` instead of `m,p,t`, and the server hashes the normalized password string itself, so a
  different order meant a different password. Plaintext and client-hashed submissions are now always normalized to one
  canonical `m,p,t` string, the form all stored passwords were created from. No stored data changes.
* **Client-hashed passwords using the standard `m,t,p` parameter order were treated as plaintext** and hashed again,
  so they never matched. Client hashes are now recognized whatever their parameter order.
* **Default account seeding created a duplicate user on every restart.** The name alias is now created right after
  the user (removing the user if that fails), and the lookup is trimmed and lower-cased to match how aliases are stored.
* **Default account seeding left an orphaned user when a seeded account had an email.** The profile is now read and
  written with the `profile:contacts` and `profile:preferences` scopes, so its contacts are no longer stripped and erased.

## v2.0.0-beta.15

### Added

* **`POST /oauth/session-token`** exchanges a presented OAuth 2.0 access token (`Authorization: Bearer`, verified the same way `/userinfo` does) for one of this library's own ordinary session JWTs - the same shape every other sign-in route (password/MFA/passkey/refresh/OIDC) already hands back. Built for a native app (e.g. `tauri-client`) that signs in through the standard OAuth 2.0 + PKCE flow (`/oauth/authorize`, `/oauth/token`) but also needs to call a deployment's ordinary, `JWTStrategy`-protected `/api/...` routes, which only ever accept a plain session `jwt`. Widening those routes to accept an OAuth bearer token directly was deliberately rejected - they live in `@rapidrest/service-core` (shared far beyond this library) and an OAuth access token carries no `roles` claim, so accepting it directly on a role-gated route would silently authorize as "no roles" instead of failing loudly. This route looks up the real `User` behind the token's `sub` and mints a normal session JWT carrying their actual `roles`. Sets no cookie (a native app has no cookie jar this should write into) and fires no `SIGNED_IN` audit entry (no new credential was actually checked here - see `TokenUtils.createAuthResult()`'s own doc comment).

## v2.0.0-beta.14

### Fixed

* **Passkey sign-in failed on MongoDB with `decodedPublicKey.get is not a function`.** A registered
  credential's public key is a `Uint8Array`, which MongoDB stores as a BSON `Binary` (and a JSON cache stores
  as a base64 string). `toUint8Array()` only understood the index-keyed object TypeORM's `simple-json` column
  returns, so it rebuilt a `Binary` into three garbage bytes and `@simplewebauthn/server` then failed to decode
  it. It now restores the real key from a `Uint8Array`/`Buffer`, a `Binary`, a base64 string, a JSON-serialized
  `Buffer`, an array, or an index-keyed object. Passkeys registered before this fix work again — nothing about
  the stored data changes.
* **A password an administrator set for another account could not be changed by that account.** The admin is a
  trusted role, which is exempt from the implicit "creator gets full access" ACL grant, so the new secret's ACL
  had no record for the account holder and their own `PUT /secrets/:id` was refused with a permission error.

### Added

* **A policy for how many passwords an account can have: `SystemSettings.allowMultiplePasswords`, off by default — one
  password per account.** Configured with `auth:allowMultiplePasswords` (which seeds the stored setting the first time
  it's read), then changeable at runtime by a trusted user via `PUT /settings`, and stored in the database, exactly like
  `allowRegistration`; like `requireMFA` it's only reported to a trusted caller. It's enforced when a `password` secret
  is created, for everyone: with it off, an account that already has a password is refused another (400) — an
  administrator changes the existing one instead. Lowering it later doesn't remove passwords an account already has.
  Sign-in accepts *any* of an account's passwords, so with it on, an administrator can keep a password of their own on an
  account (one its holder can't change) alongside the holder's, which preserves their access to it. New nullable
  `allowMultiplePasswords` column on the system settings table for SQL datastores.
  * **Behavior change:** before this, an account could have any number of passwords. Set `auth.allowMultiplePasswords`
    to `true` (or turn it on in the admin console) to keep that.
* `PUT /secrets/:id?allowUserChange=false`: an administrator taking a password over. Removes the account holder's rights
  on it altogether — including the ones they had on a password they chose themselves — so only an administrator can
  change or remove it from then on. Together with the policy above this is how an administrator keeps control of an
  account's password: with one password, only they can change it; with several, they can hold one of their own.
* `POST /secrets?allowUserChange=true` (and `PUT /secrets/:id?allowUserChange=true`, to reset a password its holder could not change before): when a trusted user creates or resets a `password` for *another* account, also
  grants that account `READ`, `EXISTS` and `UPDATE` on the new secret (not `DELETE`). Ignored for anyone who
  isn't a trusted user, for a caller creating their own secret, for any other secret type, and for bulk creates.
* `User.passwordChangeRequired` — for an account holder who must choose a new password before doing anything
  else, e.g. one provisioned with a temporary password. Only a trusted user can set it (on `POST /users`, or
  `PUT /users/:id`); it's cleared automatically when the account holder changes their own password (not when an
  administrator changes it for them). Sign-in still succeeds and the flag is returned with the user, so a client
  is responsible for prompting; the server does not otherwise restrict a flagged account.
  * While the flag is set, the account holder changing their own `password` (`PUT /secrets/:id` with a new
    `data`) no longer needs an elevated token: they've just signed in with the temporary password, so asking
    them to prove it again to replace it is an empty ceremony. Elevation is not the alternative — it lapses
    after 60 seconds, and an elevated token carries trusted roles. Nothing else is waived: a rename, any other
    secret, another account's password, or the same change once the flag is cleared still needs elevation.
    `PUT /secrets/:id` now makes this check itself instead of through `@RequiresElevation(60)`, which can't be
    waived per request; the requirement is otherwise unchanged (403 `api-104` unless elevated in the last 60s).
  * New nullable `passwordChangeRequired` column on the `User` table for SQL datastores.

## v2.0.0-beta.13

* Added CSRF (double-submit cookie) protection for every cookie-authenticated, state-changing request.
  * `TokenUtils` now issues/rotates a `csrf` cookie alongside `jwt`/`refresh` at login, refresh and
    elevation, and clears it at logout, via a new `CsrfUtils`. Unlike `jwt`/`refresh`, this cookie is
    always host-only (never `Domain`-scoped), even when the session cookie itself is wildcard-domain for
    SSO — a wildcard-domain double-submit cookie can be read via `document.cookie` by any same-site
    sibling subdomain, defeating the whole scheme.
  * Enforcement lives in `@rapidrest/service-core`'s `RouteUtils.checkCsrf()`, wired automatically into
    every route, and applies only to a request whose only credential came from the `jwt` cookie
    (`JWTAuthResult.source === "cookie"`) — a bearer-token/API-key/query-token caller is never affected.
  * `BaseOAuthAuthorizeRoute.decideConsent()` authenticates via `req.session` directly, bypassing the
    automatic jwt-cookie gate entirely, so it now runs the same check explicitly — a forged consent could
    otherwise grant a malicious OAuth client an authorization code for the victim's account.
  * `BaseImpersonationRoute`'s `/impersonate/stop` changed from `GET` to `POST`: a state-changing `GET`
    is exploitable via a bare navigation, bypassing CSRF defenses entirely (they only ever apply to
    non-safe methods).

## v2.0.0-beta.12

* Added app passwords — a user-generated, high-entropy `app-password` secret for a single legacy
  Basic-auth client (e.g. an old mail client) that can't complete an MFA challenge. Unlike a real password,
  it's allowed to authenticate via `BaseAuthBasicRoute` even when the account has `requireMFA` set, since
  it's a distinct, individually-revocable credential scoped to Basic-auth-only flows.
  * Created via `POST /secrets` with `{ type: "app-password", hint: "<label>" }` — a non-empty `hint` is
    required and any client-supplied `data` is discarded. The generated plaintext is returned exactly once,
    as `password`, in the create response.
  * Controlled by `auth:app_password:enabled` (default `true`) on both `BaseSecretRoute` (creation) and
    `BaseAuthBasicRoute` (the `requireMFA` bypass); disabling it does not delete any existing app password.
  * A real password submitted via `BaseAuthBasicRoute` remains subject to `requireMFA` exactly as before —
    the bypass only ever applies to an `app-password` secret.
  * Added `generateAppPassword()` to `src/auth/shared.ts`.
* Added `Secret.lastUsedAt` (an ISO-8601 string, absent/`undefined` until the secret has ever been used —
  though a never-set nullable column round-trips as `null` on the SQL tier, same as every other optional
  `Secret` field like `hint`), updated on every successful authentication against the matching secret:
  a real or app password, a TOTP code, a FIDO2/passkey credential, or a recovery code. Persisted via a new
  `touchSecretLastUsedAt()` helper in `src/auth/shared.ts` (shared by `BaseAuthBasicRoute`/`BaseAuthMFARoute`/
  `BaseAuthElevationRoute`) or merged into an existing per-secret write (`updateCredentialCounter()`/
  `updateSecretTimeStep()`/`consumeRecoveryCode()`) elsewhere — always best-effort, so a failure to persist
  it never fails the authentication response itself.
* Added five new `AuthEventType` values for secret lifecycle/use, each best-effort/fire-and-forget like the
  existing ones: `PASSWORD_CHANGED` (a `password` secret created, or its value changed via update — not a
  hint-only rename), `APP_PASSWORD_CREATED`/`APP_PASSWORD_REMOVED` (kept distinct from `MFA_ENROLLED`/
  `MFA_REMOVED` since an app password is deliberately not MFA), `APP_PASSWORD_USED` (fired in addition to
  the generic `SESSION_CREATED` on a successful app-password login — the signal that `requireMFA` was
  bypassed), and `RECOVERY_CODE_USED`.
* Added a durable audit-log mechanism, `AuditLogUtils` (`src/auth/AuditLogUtils.ts`), separate from
  `EventUtils`: the latter is lossy, best-effort telemetry (silently discarded end to end with no
  `telemetry_services:url`/listener configured), unsuitable for a real audit trail. The base
  `AuditLogUtils.record(entry)` just logs via `@Logger` — already an improvement over `EventUtils`'s silent
  no-op — and a consuming app registers a database-backed subclass under the same class name for a durable,
  queryable trail, the same dependency-injection swap already used for `MessagingUtils`.
  * `AuditLogEntry`: `{ type, userUid?, actorUid?, ip?, path?, method?, data? }` — `type` reuses the
    matching `AuthEventType` string value; `actorUid` is only set when it differs from `userUid` (e.g. a
    trusted-role holder acting on another account), unifying `BaseAccountRoute`'s previously separate
    `deletedBy`/`revokedBy` fields under one name for this mechanism.
  * Added two new `AuthEventType` values, `AuditLogUtils`-only: `SIGNED_IN` (a genuine new sign-in of any
    kind — password, app-password, MFA, passkey, FIDO2, TOTP, OTP, an OIDC provider, or registration —
    fired from `TokenUtils.createAuthResult()` whenever it's given a new `authMethod` argument; deliberately
    excludes a routine token refresh, and excludes elevation/impersonation, which get their own more
    specific entries) and `IMPERSONATED` (an admin began impersonating another account — previously no
    audit trail existed for this at all).
  * A parallel `AuditLogUtils.record()` call was added alongside every existing `EventUtils.record()` call
    site (`ACCOUNT_DELETED`, `SESSIONS_REVOKED`, `ELEVATED`, `APP_PASSWORD_USED`, `RECOVERY_CODE_USED`,
    `REGISTRATION_COMPLETED`, `MFA_ENROLLED`/`MFA_REMOVED`, `PASSWORD_CHANGED`,
    `APP_PASSWORD_CREATED`/`APP_PASSWORD_REMOVED`) — always fail-open (the triggering action still
    succeeds), with a write failure logged loudly rather than silently swallowed.

## v2.0.0-beta.11

* Added WhatsApp as a one-time code (OTP) delivery channel for verified phone contacts, alongside SMS. It is sent through
  `MessagingUtils.sendWhatsApp()` (`@rapidrest/core` 6.x) and only offered while WhatsApp is configured: the
  `MessagingUtils` instance's optional `isWhatsAppConfigured(): boolean | Promise<boolean>` hook decides when it has
  one, otherwise core's own `whatsapp` config being accepted by `init()`. Existing SMS/e-mail entries are unchanged.
  * Added `OTPContactType.WHATSAPP`; `obfuscateContact()` masks it like SMS.
  * `BaseAuthDiscoverRoute` lists an extra hint with `channel: "whatsapp"` for each verified phone. The route now
    injects `MessagingUtils`.
  * `BaseAuthOTPRoute` and `OTPStrategy` accept an optional `channel` (`"whatsapp"`) in the challenge request, passed
    as a new optional second argument of `getContact(id, channel?)`; `getContacts()` also lists a WhatsApp contact for
    each verified phone.
  * `BaseAuthMFARoute` and `BaseAuthElevationRoute` list a WhatsApp method with id `<alias uid>:whatsapp` after a
    verified phone's SMS method (whose id is unchanged), and resolve that id in `getMethod()`.
  * Added the `isWhatsAppConfigured()`, `toWhatsAppMethodId()` and `parseWhatsAppMethodId()` helpers.
  * Contact verification and registration codes are unchanged (e-mail/SMS only).

## v2.0.0-beta.10

## v2.0.0-beta.9

* Added new `SystemSettings` data model for managing common configuration variables at runtime.
* Added new `BaseSettingsRoute` route that exposes endpoints for managing `SystemSettings`.
* Upgraded to service-core v2.1.1

## v2.0.0-beta.8

* Upgraded to service-core v2.1.0

## v2.0.0-beta.7

* Added client-side pre-hashed (Argon2id) password support. A capable client can hash the password locally before sending it, so the real password never reaches the server. A single stored credential accepts either form; server-side strength validation only applies to plaintext.

## v2.0.0-beta.6

`2.0.0` is still in pre-release (`2.0.0-beta.x`). Everything toward it is condensed into this single
listing rather than split per beta tag — it will be finalized as `2.0.0` once officially tagged.

### New Features

* OAuth 2.0 + OpenID Connect Authorization Server. This library can now act as an authorization
  server/OIDC provider, not just a relying party:
  * Authorization Code + PKCE flow, with consent
  * Refresh token grant, with rotation and reuse/theft detection
  * `client_credentials` grant for machine-to-machine access
  * Token revocation (`/revoke`) and introspection (`/introspect`)
  * OIDC discovery metadata, `/userinfo`, and JWKS
  * `BaseOAuthClientRoute` — owner/admin CRUD for registering and managing OAuth `Client`s, including
    one-time secret reveal and secret regeneration. A non-admin caller can register and fully manage
    their own client; an admin can manage any client.
* Endpoint-wide rate limiting, via `@rapidrest/service-core`'s new `@RateLimit()` route decorator, on
  routes with no natural per-caller identifier to key the existing identifier-based `RateLimiter` on:
  OIDC discovery metadata, JWKS, client secret regeneration, and user impersonation.

### Breaking Changes

* `RateLimiter` moved to `@rapidrest/service-core` — it is a general-purpose framework utility, not an
  auth-specific one. Behavior is unchanged, but the names it keys on are no longer auth-namespaced:
  * Config path: `auth:rateLimit` → `rateLimit`
  * Cache keys: `auth:ratelimit:*` → `ratelimit:*`
  * Event type: `auth.ratelimit.exceeded` → `ratelimit.exceeded` (`AuthEventType.RATELIMIT_EXCEEDED`
    is removed; use `@rapidrest/service-core`'s `RATELIMIT_EXCEEDED_EVENT`)

## v1.3.0

* `OIDCStrategy` now supports passing in a `no_redirect=true` query flag to return the authorization URL as a JSON
  payload instead of a `302 REDIRECT`.

## v1.2.0

* BaseAuthOIDCRoute now instantiates OIDCStrategy using the strategy name instead of `default`. This fixes a bug when
  supporting multiple OIDC providers.
* Added new `/authorize` endpoint to `BaseAuthOIDCRoute` for building and returning the OAuth authorization URL.

## v1.1.1

* Fixed bad import of `jsonwebtoken` in `OIDCStrategy`

## v1.1.0

* Fixed `BaseAuthOIDCRoute` hardcoding its registered strategy name to the literal `"oauth"` (both
  at `initialize()`-time registration and in `login()`'s `@Auth(["oauth"])`), which made it
  impossible to wire up more than one OIDC/OAuth provider in the same application — every
  `BaseAuthOIDCRoute` subclass registered under the same shared name in `AuthMiddleware`, so the
  last one loaded silently won for all of them. Added an overridable `strategyName` field
  (defaults to `"oauth"`, so existing single-provider usage is unaffected) — a subclass wiring up
  an additional provider now sets its own `strategyName` and overrides `login()` with a matching
  `@Auth([...])`, delegating to `super.login(...)`. See `BaseAuthOIDCRoute`'s own doc comments for
  the override pattern.

## v1.0.0

### Authentication Strategies:

* `BasicStrategy` - Simple id and password authentication
* `FIDO2Strategy` - FIDO2/WebAuthn hardware based authentication (e.g. YubiKey)
* `MFAStrategy` - Simple id and password + 2FA authentication [fido2|otp|recovery-code|totp]
* `OIDCStrategy` - OAuth 2.0 & OpenID Connect authentication
* `OTPStrategy` - One-Time Password (OTP) authentication (e.g. email, sms)
* `PasskeyStrategy` - WebAuthn based passkey authentication
* `TOTPStrategy` - RFC 6238 Time-Based One Time Password authentication (e.g. Google Authenticator, etc.)

### Security Features

* Rate limiting on every credential-verification endpoint, layered per-identifier and per-source-IP (reverse-proxy aware) — via `@rapidrest/service-core`'s `RateLimiter`
* MFA recovery/backup codes as a first-class secondary authentication method
* Account elevation (`@RequiresElevation`) for step-up re-verification before sensitive actions
* Session revocation ("log out everywhere") that invalidates every outstanding refresh token for an account
* Optional TOTP secret encryption at rest (AES-256-GCM)
* Configurable Argon2 password hashing cost parameters
* Secure, `HttpOnly` cookies by default when cookie-based token issuance is enabled
* Default account provisioning on startup, with configuration-driven role/verification sync

### Data Models

This library provides variants of each of the following data models that can be used against a MongoDB or SQL database. Classes are post-fixed
with either `Mongo` or `SQL` at the end of the name (e.g. `Alias` becomes `AliasMongo` for MongoDB, `AliasSQL` for SQL).

* `User` - Describes a single user account
* `Alias` - Describes an alternate identifying name (aka: alias) for a user account (e.g. email, phone, third-party OAuth ID)
* `Secret` - Stores secrets used to authenticate user accounts (e.g. `fido2`, `passkey`, `password`, `totp`, `recovery-codes` secrets)
* `Profile` - Stores additional, personally identifying, information about a user (e.g. birthdate, legal name, verified contacts, preferences)

### Route Handlers

This library provides variants of each of the following routes that can be used against a MongoDB or SQL database. Classes are post-fixed
with either `Mongo` or `SQL` at the end of the name (e.g. `BaseAliasRoute` becomes `BaseAliasRouteMongo` for MongoDB, `BaseAliasRouteSQL` for SQL).

#### Data Models

* `BaseAliasRoute` - Provides full CRUD operations for the `Alias` data model
* `BaseProfileRoute` - Provides full CRUD operations for the `Profile` data model
* `BaseSecretRoute` - Provides full CRUD operations for the `Secret` data model. Additionally includes endpoints for registration of 
`fido2`, `passkey`, `totp` and `recovery-codes` secrets.
* `BaseUserRoute` - Provides full CRUD operations for the `User` data model

#### Authentication Strategies

* `BaseAuthBasicRoute` - Implements the `BasicStrategy` authentication strategy
* `BaseAuthFIDO2Route` - Implements the `FIDO2Strategy` authentication strategy
* `BaseAuthMFARoute` - Implements the `MFAStrategy` authentication strategy
* `BaseAuthOIDCRoute` - Implements the `OIDCStrategy` authentication strategy
* `BaseAuthOTPRoute` - Implements the `OTPStrategy` authentication strategy
* `BaseAuthPasskeyRoute` - Implements the `PasskeyStrategy` authentication strategy
* `BaseAuthTOTPRoute` - Implements the `TOTPStrategy` authentication strategy

#### Session & Account Management

* `BaseAccountRoute` - Aggregates a user's account data (profile, aliases, secrets) and provides account deletion and session revocation
* `BaseAuthDiscoverRoute` - Lets an anonymous caller discover which sign-in methods are configured for a claimed identifier
* `BaseAuthElevationRoute` - Issues a step-up (elevated) token after re-verifying identity, required for `@RequiresElevation`-gated actions
* `BaseAuthLogoutRoute` - Clears the authentication cookie, if cookie-based token issuance is enabled
* `BaseAuthRefreshRoute` - Issues a new access token from a valid refresh token
* `BaseRegistrationRoute` - Self-service account registration via OTP-verified email or phone

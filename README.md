# RapidREST: Authentication Library

[![CI](https://github.com/rapidrest/auth/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rapidrest/auth/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/rapidrest/auth/badge.svg?branch=main)](https://coveralls.io/github/rapidrest/auth?branch=main)
[![npm version](https://img.shields.io/npm/v/@rapidrest/auth)](https://www.npmjs.com/package/@rapidrest/auth)

A library for implementing a complete authentication server with [RapidREST](https://rapidrest.dev). It
provides the data models, persistence adapters, and HTTP routes needed to register and authenticate users via
password, TOTP, OTP (email/SMS/WhatsApp), WebAuthn passkeys, FIDO2 hardware security keys, multi-factor authentication, and
sign-in through upstream OpenID Connect / OAuth 2.0 providers. It can also act as an OpenID Connect-conformant OAuth 2.0
authorization server for your own applications. Using this library you can stand up a fully featured authorization
server by writing configuration and a handful of one-line route classes.

For complete documentation please visit [RapidREST.dev](https://rapidrest.dev).

## Features

### Authentication Strategies:

* `BasicStrategy` - Simple id and password authentication
* `FIDO2Strategy` - FIDO2/WebAuthn hardware based authentication (e.g. YubiKey)
* `MFAStrategy` - Simple id and password + 2FA authentication [fido2|otp|recovery-code|totp]
* `OAuthBearerStrategy` - Verifies an OAuth 2.0 access token issued by this library's own authorization server (`Authorization: Bearer`)
* `OIDCStrategy` - OAuth 2.0 & OpenID Connect authentication against an upstream identity provider
* `OTPStrategy` - One-Time Password (OTP) authentication (e.g. email, sms, whatsapp)
* `PasskeyStrategy` - WebAuthn based passkey authentication
* `TOTPStrategy` - RFC 6238 Time-Based One Time Password authentication (e.g. Google Authenticator, etc.)

### Security Features

* Rate limiting on every credential-verification endpoint, layered per-identifier and per-source-IP (reverse-proxy aware), with dedicated, stricter limits on sent one-time codes kept in Redis (see "Sent one-time codes") — via `@rapidrest/service-core`'s `RateLimiter` and this library's `OTPCounters`
* App passwords — user-generated, individually-revocable Basic-auth-only credentials for legacy clients that can't complete an MFA challenge
* Secret usage tracking (`Secret.lastUsedAt`) and security event hooks for secret lifecycle/use (password changed, app password created/removed/used, recovery code used), alongside the existing login/registration/elevation/MFA events — see `AuthEventType`
* Durable audit logging (`AuditLogUtils`) for a curated set of security-relevant actions — every genuine sign-in (`SIGNED_IN`, excluding token refresh), impersonation (`IMPERSONATED`), elevation, account deletion, session revocation, and secret lifecycle/use — separate from the best-effort `EventUtils` telemetry above; see "Audit logging" below
* MFA recovery/backup codes as a first-class secondary authentication method
* Account elevation (`@RequiresElevation`) for step-up re-verification before sensitive actions
* Session revocation ("log out everywhere") that invalidates every outstanding refresh token for an account
* One-time codes sent by e-mail, SMS or WhatsApp (sign-in, registration, contact verification, elevation) are short random codes, valid for `auth:otp:ttl` (10 minutes by default) with a limited number of attempts, stored only as a salted hash in the session - see "Sent one-time codes" below
* Optional TOTP secret encryption at rest (AES-256-GCM)
* Configurable Argon2 password hashing cost parameters
* Client-side pre-hashed (Argon2id) password support, alongside plaintext, so a capable client's real password never reaches the server (accepts any Argon2 library's PHC parameter order)
* Password policy: one password per account unless the `allowMultiplePasswords` system setting is on; administrators can require a password change (`User.passwordChangeRequired`) and grant or remove an account holder's rights on a password they set (`allowUserChange`)
* Impersonation, letting a trusted user temporarily act as another account without its credentials, recorded in the audit log
* Secure, `HttpOnly` cookies by default when cookie-based token issuance is enabled
* CSRF protection (`CsrfUtils`) — a host-only double-submit `csrf` cookie rotated alongside `jwt`/`refresh` at login/refresh/elevation and cleared at logout; enforcement is in `@rapidrest/service-core`'s `RouteUtils.checkCsrf()`, applied automatically to every cookie-authenticated, state-changing request
* Default account provisioning on startup, with configuration-driven role/verification sync

### Data Models

This library provides variants of each of the following data models that can be used against a MongoDB or SQL database. Classes are post-fixed
with either `Mongo` or `SQL` at the end of the name (e.g. `Alias` becomes `AliasMongo` for MongoDB, `AliasSQL` for SQL).

* `User` - Describes a single user account
* `Alias` - Describes an alternate identifying name (aka: alias) for a user account (e.g. email, phone, third-party OAuth ID)
* `Secret` - Stores secrets used to authenticate user accounts (e.g. `app-password`, `fido2`, `passkey`, `password`, `totp`, `recovery-codes` secrets). Tracks `lastUsedAt`, the last time the secret successfully authenticated (unset if never)
* `Profile` - Stores additional, personally identifying, information about a user (e.g. birthdate, legal name, verified contacts, preferences)
* `SystemSettings` - Runtime-editable deployment settings (e.g. `allowRegistration`, `allowMultiplePasswords`, `requireMFA`)
* `Client` - A registered OAuth 2.0 / OpenID Connect application this server issues tokens to
* `AuthorizationCode` - A short-lived authorization code issued by the `/authorize` endpoint
* `ConsentGrant` - A user's recorded consent to the scopes a client requested
* `OAuthRefreshToken` - A refresh token issued to an OAuth client
* `SigningKey` - A rotating key used to sign OAuth access and ID tokens, published via the JWKS endpoint

### Route Handlers

This library provides variants of each of the following routes that can be used against a MongoDB or SQL database. Classes are post-fixed
with either `Mongo` or `SQL` at the end of the name (e.g. `BaseAliasRoute` becomes `BaseAliasRouteMongo` for MongoDB, `BaseAliasRouteSQL` for SQL).

#### Data Models

* `BaseAliasRoute` - Provides full CRUD operations for the `Alias` data model
* `BaseProfileRoute` - Provides full CRUD operations for the `Profile` data model
* `BaseSecretRoute` - Provides full CRUD operations for the `Secret` data model. Additionally includes endpoints for registration of 
`app-password`, `fido2`, `passkey`, `totp` and `recovery-codes` secrets.
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
* `BaseImpersonationRoute` - Lets a trusted user start and stop impersonating another account
* `BaseRegistrationRoute` - Self-service account registration via OTP-verified email or phone
* `BaseSettingsRoute` - Reads and updates `SystemSettings`

#### OAuth 2.0 / OpenID Connect Authorization Server

* `BaseOAuthAuthorizeRoute` - The `/authorize` endpoint (authorization code flow with PKCE) and the consent decision that may follow it
* `BaseOAuthTokenRoute` - The `/token` endpoint (`authorization_code`, `refresh_token` and `client_credentials` grants)
* `BaseOAuthClientRoute` - Owner/admin CRUD for registered `Client` applications
* `BaseOAuthDiscoveryRoute` - Authorization server metadata (RFC 8414 / OIDC Discovery)
* `BaseOAuthJwksRoute` - The public JSON Web Key Set (RFC 7517)
* `BaseOAuthUserInfoRoute` - The OIDC `/userinfo` endpoint
* `BaseOAuthIntrospectRoute` - Token introspection (RFC 7662)
* `BaseOAuthRevokeRoute` - Token revocation (RFC 7009)
* `BaseOAuthSessionTokenRoute` - Exchanges an OAuth access token for an ordinary session JWT, for native apps that sign in through OAuth but call ordinary API routes

#### App passwords

A user can generate a standing `app-password` secret (`SecretType.APP_PASSWORD`) for a single legacy
Basic-auth client — e.g. an old mail client — that can't complete an MFA challenge, without disabling MFA
for the account as a whole:

* Created via `POST /secrets` with `{ type: "app-password", hint: "<label>" }` - a `hint` is required (an
  account may have several) and any client-supplied `data` is discarded; the server generates a
  high-entropy value and returns it once, as `password`, in the create response. It is never returned
  again by any later read.
* Controlled by `auth:app_password:enabled` (default `true`) on both `BaseSecretRoute` (gates creating new
  ones) and `BaseAuthBasicRoute` (gates the bypass below). Disabling it does not delete any existing app
  password.
* `BaseAuthBasicRoute` checks an account's app passwords before its `requireMFA` gate, so a matching app
  password authenticates even when the account requires MFA - a real password remains subject to
  `requireMFA` exactly as before. A downstream Basic-auth consumer (e.g. a mail server validating
  credentials against this authorization server) gets this for free just by calling `/auth/basic` as today.
* Revoked independently of the account's password/MFA by deleting the `Secret` (`DELETE /secrets/:id`); its
  `data` cannot be changed once created (`PUT` on it 400s) - delete and create a new one to rotate it. A
  hint-only `PUT` (renaming it) is unaffected.
* A successful match updates the secret's `lastUsedAt` and records an `auth.app_password.used` event
  (`AuthEventType.APP_PASSWORD_USED`) - the signal that `requireMFA` was bypassed for that login - in
  addition to the generic `auth.session.created` event every successful login fires.

#### Audit logging

`EventUtils.record()` (`@rapidrest/core`) is lossy, best-effort telemetry: with no `telemetry_services:url`
configured and no `EventUtils.on()` listener registered, every event it records is silently discarded end
to end - fine for telemetry, unacceptable for a real audit log. `AuditLogUtils` (`src/auth/AuditLogUtils.ts`)
is a separate, dedicated mechanism for that:

* The base `AuditLogUtils.record(entry: AuditLogEntry)` just logs (`@Logger`) - a real improvement over
  `EventUtils`'s silent no-op today, visible in server logs with zero extra configuration. A consuming app
  that wants a real, durable, queryable audit trail (strongly recommended for production) registers a
  database-backed subclass under the same class name (`AuditLogUtils`), so `ObjectFactory` resolves every
  `@Inject(AuditLogUtils)` in this library to that richer implementation - the same dependency-injection
  swap already used for `MessagingUtils` - with zero code changes needed here.
* `AuditLogEntry`: `{ type, userUid?, actorUid?, ip?, path?, method?, data? }` - `type` reuses the matching
  `AuthEventType` string value; `actorUid` is only set when it differs from `userUid` (e.g. a trusted-role
  holder impersonating, deleting, or revoking sessions for another account).
* A curated set of security-relevant actions record to `AuditLogUtils`, always fail-open (a write failure
  is logged loudly, never fails the caller's actual action): every genuine new sign-in
  (`AuthEventType.SIGNED_IN`, fired from `TokenUtils.createAuthResult()` whenever it's given an
  `authMethod` - deliberately excludes a routine token refresh, and excludes elevation/impersonation, which
  get their own more specific entries below), impersonation (`AuthEventType.IMPERSONATED`, previously with
  no audit trail at all), plus a parallel entry alongside every existing `EventUtils`-recorded event
  (`ACCOUNT_DELETED`, `SESSIONS_REVOKED`, `ELEVATED`, `APP_PASSWORD_USED`, `RECOVERY_CODE_USED`,
  `REGISTRATION_COMPLETED`, `MFA_ENROLLED`/`MFA_REMOVED`, `PASSWORD_CHANGED`,
  `APP_PASSWORD_CREATED`/`APP_PASSWORD_REMOVED`).

#### Sent one-time codes

The codes `BaseAuthOTPRoute`, `BaseAuthMFARoute`, `BaseAuthElevationRoute`, `BaseRegistrationRoute`, `BaseAliasRoute` and
`BaseProfileRoute` send by e-mail, SMS or WhatsApp (`generateOTP()`/`verifyOTP()`) are not TOTP. Authenticator app
factors (`TOTPStrategy`, `BaseAuthTOTPRoute`, `totp` secrets) are unchanged and still use RFC 6238.

* A code is 6 characters from the digits 2-9 and the letters A-Z without I, L and O (so nothing is mistaken for 0, 1 or
  O), shown upper case and generated with `crypto.randomInt`. Entry is case-insensitive and ignores surrounding
  whitespace and internal spaces or hyphens.
* Only an HMAC-SHA256 of the code (keyed by a per-challenge random salt), the flow and user it was issued for, the
  issue time and an attempt counter are kept in the session (`req.session.otp`) - never the code. It is compared in
  constant time.
* A code is bound to the flow that issued it (`login`, `mfa`, `elevate`, `register` or `contact`) and to the identity it
  was sent for: a code from one flow is rejected, and discarded, by every other. The MFA one-time-code step additionally
  requires the code to name the user who just passed the password step.
* A code is single use. It stops working after `auth:otp:ttl` seconds, after `auth:otp:maxAttempts` wrong tries, or once
  it is used. A wrong code on a live challenge only counts an attempt, so a typo does not force a resend. Issuing a new
  code replaces the pending one. The code cannot outlive its session, so keep `session.ttl` at or above `auth:otp:ttl`.
* Submitted codes longer than four times the configured length are counted as a wrong guess without being processed.
* The messaging template variable stays `totp` (it now holds the sent code), so existing templates keep working.

| Config key | Default | Description |
| --- | --- | --- |
| `auth:otp:length` | `6` | Number of characters in a code (4-64) |
| `auth:otp:alphabet` | `23456789ABCDEFGHJKMNPQRSTUVWXYZ` | Characters codes are drawn from (case-insensitive, no whitespace or `-`) |
| `auth:otp:ttl` | `600` | Seconds a code is valid for, or a duration such as `"10m"` |
| `auth:otp:maxAttempts` | `5` | Wrong tries before the code is invalidated (1-10) |
| `auth:otp:limits:issue` | `{ maxAttempts: 5, windowSeconds: 900 }` | Codes sent to one contact from one IP address |
| `auth:otp:limits:issueTotal` | `{ maxAttempts: 20, windowSeconds: 900 }` | Codes sent to one contact from all addresses together |
| `auth:otp:limits:verify` | `{ maxAttempts: 20, windowSeconds: 3600 }` | Verification attempts against one contact, across every code (a success counts as one) |
| `auth:otp:limits:user` | `{ maxAttempts: 50, windowSeconds: 3600 }` | Verification attempts against the user a code was issued for, across every contact |

The configuration is validated when the server starts and an unsafe one stops it: `alphabet` must be printable ASCII
(`!` to `~`) without `-`, `ttl` must be over 0 and at most 3600 seconds, `maxAttempts` 1 to 10, `length` 4 to 64, and
`length * log2(alphabet size)` at least 20 bits. That last floor is **above** six decimal digits (6 * log2(10) = 19.9
bits), so an all-numeric configuration needs a `length` of 7 or more; the default alphabet gives 29.7 bits at 6
characters. Numbers may be given as numeric strings, as they are when they come from environment variables
(`auth__otp__maxattempts=3`); anything else that is not a number is rejected.

##### Where the counters live

Three things must hold across parallel requests and across server instances, and none of them can be kept in the
session: a Redis-backed session store gives every request its own copy of the session with the last write winning. They
are therefore counted by `OTPCounters` (see `src/auth/OTPCounters.ts`), directly on the Redis `cache` connection:

* the number of guesses made against one code (`auth:otp:attempts:<salt>`);
* the one-time claim of a successful redemption (`auth:otp:used:<salt>`), so a code cannot be redeemed twice even if a
  slow request writes the old session back afterwards;
* the throttles above (`auth:otp:issue:<flow>:<contact>:<ip>`, `auth:otp:issue-total:<flow>:<contact>`,
  `auth:otp:verify:<flow>:<contact>:<ip>`, `auth:otp:verify-total:<flow>:<contact>`,
  `auth:otp:user:<flow>:<uid>:<ip>`, `auth:otp:user-total:<flow>:<uid>`). The flow is in every key, so one flow can
  never spend another's allowance. The contact, uid and address parts are SHA-256 hashes (an IPv6 address contains the
  `:` that separates the fields, so raw values could spell the same key from two different pairs).

They use only `SET key 1 NX EX ttl`, and `MULTI`/`INCR`/`EXPIRE key ttl NX`/`EXEC`, so they need the **Redis 7.0 or
later** command set and nothing else, which Redis Software, Redis Cloud and Memurai provide at the time of writing.
Every route that uses them runs `OTPCounters.checkDeployment()` at startup, which tries that transaction on a scratch key
and **refuses to start** (logs an error and throws) if the `cache` connection is older than Redis 7.0 or otherwise does
not support it, and also if the connection is unreachable at that moment (the error then says so rather than blaming the
version), so a Redis outage during a deployment can make the server crash-loop until it is back. If a reply is ever not a number the counter throws, so a broken server fails closed (the request errors)
rather than letting guesses through. (service-core's own `RateLimiter`, used for
the generic per-identifier and per-IP limits, relies on `INCREX`, which needs Redis 8.8; on an older server it quietly
keeps those two limits per process. The one-time code counters do not depend on it.) The guess counter and the claim are
security controls and apply whether or not rate limiting is enabled; the throttles follow `rateLimit:enabled`. Without a
`cache` connection the counters are in-process, in a store of their own (not the shared cache that the rate limiter,
sessions and access token denylist use). That is correct for a single instance, with one caveat: the store holds at most
100,000 keys and evicts the oldest beyond that, so a flood of distinct keys can reset a counter or free a spent code.
Use the `cache` connection wherever that matters. If the sessions are in Redis
but there is no `cache` connection for the counters (a host that supplies its own session store), each route logs a
warning at startup: with several instances the guesses allowed against one code, and the redemptions of one code, would
multiply with the number of instances.

The generic limiter's keys for anything a client types (a login id, an e-mail address, a contact, a claimed uid) are
built with `clientRateLimitKey()`, which puts them under `ratelimit:id:` so a crafted value can never land on an
internal key such as `elevate:<uid>`. Values longer than 256 characters are hashed under a different prefix
(`ratelimit:idh:sha256:<hex>`), so no literal value can spell a hashed key. Use it when you add routes that rate limit on
client input.

The second and third phases of multi-factor authentication are counted separately, on the uid that passed the password
step, under `ratelimit:mfa:<uid>` (unprefixed like `elevate:<uid>`, so no client input reaches it), and only once the
request has been matched to that session-held uid. A host that builds `MFAStrategy` itself (not through
`BaseAuthMFARoute`) **must supply `MFAStrategyOptions.checkPendingRateLimit`**: without it phases 2 and 3 fall back to
`checkRateLimit(uid)`, which can share a counter with other flows and reopen the lockout. `BaseAuthMFARoute` wires the safe
`mfa:<uid>` key. A request that never passed the password step, whatever `id` it
names, and the sign-in route `/auth/otp` therefore cannot spend a user's second-factor allowance. (The password step
itself is still limited by the identifier typed, as is `/auth/otp`, which is how guessing at those is slowed.)

##### Limits and what they do not stop

A request over a limit fails with a 429; when the failing call is made inside an authentication strategy (`/auth/otp`,
`/auth/mfa`) the framework reports it as a 401 with the message "Too many attempts. Please try again later.".

The issue limit is checked before the contact is looked up, so a contact that does not exist is throttled exactly like
one that does. The verification budgets (`verify`, `verifyTotal`, `user`, `userTotal`) are counted only when the session
holds a pending code for that contact and flow, so a stranger cannot use up a contact's budget by guessing at it: they
would first have to have codes sent, which is limited per address and is visible to the contact's owner. `verify` and
`user` are per contact (or user) **and IP address**, so one address cannot drain the allowance of everyone else
(5 codes x 5 guesses an issue window would otherwise empty a shared 20-per-hour budget from a single address); the
looser `verifyTotal` and `userTotal` cap the contact or user across all addresses, mirroring `issue` and `issueTotal`.
The remaining trade-offs:

* **Sign-in codes.** Someone who knows a contact can still send it codes, from several addresses, up to the contact-wide
  `issueTotal` allowance, which stops the owner requesting a code for that window (and the owner receives every message).
  Sign-in with another contact, a password or another factor is unaffected. Lower `issueTotal` and raise `issue` to
  trade one risk for the other.
* **Verification budgets.** Several addresses together can still use up `verifyTotal` (60 per hour by default) against
  one contact, or `userTotal` (150 per hour) against one user, after sending codes to it, which blocks code sign-in for
  that contact for the rest of the hour. Sign-in with another contact, a password or another factor is unaffected.
* **Addresses.** The per-address keys use the address as the rate limiter sees it. If it cannot be determined it falls
  back to `unknown`, and everyone without an address shares one allowance. If `trusted_proxies` is not set correctly for
  your proxy or load balancer, every user appears to come from the proxy's address and shares one per-address allowance
  (and, behind a proxy you list too broadly, a client can pick its own address with a forged header). Check this
  setting before relying on any per-address limit.
* **MFA and elevation.** The code counters there are per user. Someone who holds a user's password can start the MFA
  step and use up that user's allowance for MFA codes, which blocks the e-mail/SMS factor for a while (not the
  authenticator app, recovery codes or passkeys) and does not let them in. Elevation is only reachable with a valid
  session.

If you call the helpers directly: `generateOTP(req, data, config, purpose, userUid?)`, `verifyOTP(req, payload, config,
purpose, { counters }?)` and `enforceOTPIssueLimit(req, id, config, purpose, { counters }?)` are exported; `purpose` is
required, and `counters` is an `OTPCounters` (the routes get theirs by injection). Without `counters` only the
session-held attempt count applies.

Client input fields for these codes must accept letters as well as digits.

##### Session identity during multi-factor authentication

`session.userUid` is set by `TokenUtils.createAuthResult()` on a completed sign-in, and also by service-core's
`JWTStrategy` from any valid access token presented with the session cookie. The library never puts a partial identity
in it. Because of the second writer it does **not** prove that anyone signed in, so the OAuth authorize and consent
endpoints do not use it alone: they require `session.signedInUid`, which only `TokenUtils.createAuthResult()` writes (on a
completed sign-in; `BaseAuthLogoutRoute` clears it), to equal the authenticated user, and they refuse a request that
carries the impersonation cookie (`jwt_impersonator`). The OAuth session-token exchange does not set it (it leaves the session alone). `createAuthResult()` also records
`session.signedInAt` (milliseconds), and authorize and consent load the user and refuse a session that signed in before
the user's `sessionsRevokedAt` (set by "sign out everywhere", `BaseAccountRoute.revokeSessions()`) or whose user no longer
exists, so revoking all sessions also stops `/oauth/authorize`. Sessions that predate `signedInUid`/`signedInAt` must sign in
again or refresh. Already-issued OAuth refresh tokens are not revoked by this. The password
step of `BaseAuthMFARoute` does not sign the session in, so it records the pending user in `session.mfaPendingUid`
instead, which phases 2 and 3 use and clear (a failed or throttled attempt clears it, and so does a request naming a
different uid; a wrong one-time code on a live challenge keeps it so a typo can be retried). Starting a new password
attempt also clears the method and challenge an earlier attempt selected. The elevation route keeps its own
`session.elevateUid` in the same way.

Because `JWTStrategy` copies the uid of a valid access token into the session, a `jwt` minted by impersonation, or a
stolen access token, ends up in `session.userUid` too. Host code that reads it should treat it as "this session holds a
valid access token for that user"; use `session.signedInUid` where a completed sign-in is what you need to know. A host
that authenticates `/oauth/authorize` by some other means than a sign-in through this library's routes will now be
told the user is not logged in.

#### OAuth session-token exchange

`BaseOAuthSessionTokenRoute` trades an OAuth access token for a full session JWT carrying the account's roles. It only
accepts a token issued by this deployment (signature, issuer, expiry and revocation are verified) to a registered,
enabled **first-party** client (`Client.firstParty`), whose id is both the token's `client_id` and its sole audience, for
the authenticated user. Anything else is a 403. A native app signing in through PKCE with a first-party client is
unaffected. The route now needs a `clientClass` (the Mongo and SQL variants provide it). It only mints the access token:
the caller's own session (its `userUid`, `signedInUid`, refresh token and activity fields) is left untouched, and the
response is just `{ token }`.

#### WhatsApp one-time codes

A verified phone can receive its sign-in (`BaseAuthOTPRoute`), second-factor (`BaseAuthMFARoute`) and elevation
(`BaseAuthElevationRoute`) one-time codes over WhatsApp as well as SMS, sent through `MessagingUtils.sendWhatsApp()`
from `@rapidrest/core` 6.x using the same `login-otp` template (give it a `whatsapp`/`whatsapp_template`). WhatsApp is
only offered while it is configured, and existing SMS/e-mail entries are unchanged:

* Configured means the `MessagingUtils` instance's optional `isWhatsAppConfigured(): boolean | Promise<boolean>` hook
  returns `true` - checked on every request, so a subclass whose WhatsApp settings change at runtime stays current - or,
  when it has no such hook, that core's own `whatsapp` config was accepted by `init()`. See `isWhatsAppConfigured()`.
* `BaseAuthDiscoverRoute` adds a hint with `channel: "whatsapp"` after each verified phone's hint, and
  `BaseAuthOTPRoute` accepts an optional `channel: "whatsapp"` beside `id` in the challenge request to use it.
* `BaseAuthMFARoute` and `BaseAuthElevationRoute` add a method with id `<alias uid>:whatsapp` (data type `whatsapp`) after
  the phone's SMS method, whose id stays the plain alias uid.
* Contact verification (`BaseAliasRoute`, `BaseProfileRoute`) and registration codes remain e-mail/SMS only.

## Installation

### NPM

```
npm i @rapidrest/auth
```

### Yarn

```
yarn add @rapidrest/auth
```

## Requirements

This package targets Node.js `>=24.0.0` and is published as an ESM-only package.

It declares `@rapidrest/core` and `@rapidrest/service-core` as required peer dependencies. The remaining peer
dependencies are optional and only need to be installed if you use the corresponding feature:

| Peer dependency | Required for |
| --- | --- |
| `@rapidrest/core` | Always |
| `@rapidrest/service-core` | Always |
| `argon2` | Password, app password and recovery code secrets — hashing |
| `otplib` | `TOTP`, `OTP`, and `MFA` secrets/strategies |
| `@simplewebauthn/server` | `Passkey` and `FIDO2` strategies |
| `jwks-rsa` | Verifying `OIDC` providers that publish a JWKS endpoint |

Strategies dynamically `import()` their optional dependency the first time they're used and throw a descriptive
error (naming the missing package) if it isn't installed, rather than failing at package install time.

## License

MPL v2.0 — see [LICENSE](./LICENSE).

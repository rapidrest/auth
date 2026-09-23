# Release Notes

## Unreleased

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

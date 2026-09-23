# RapidREST: Authentication Library

[![CI](https://github.com/rapidrest/auth/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rapidrest/auth/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/rapidrest/auth/badge.svg?branch=main)](https://coveralls.io/github/rapidrest/auth?branch=main)
[![npm version](https://img.shields.io/npm/v/@rapidrest/auth)](https://www.npmjs.com/package/@rapidrest/auth)

A library for implementing a complete authentication server with [RapidREST](https://rapidrest.dev). It
provides the data models, persistence adapters, and HTTP routes needed to register and authenticate users via
password, TOTP, OTP (email/SMS/WhatsApp), WebAuthn passkeys, FIDO2 hardware security keys, multi-factor authentication, and
OpenID Connect / OAuth 2.0. Using this library you can stand up a fully featured authorization server by writing
configuration and a handful of one-line route classes.

For complete documentation please visit [RapidREST.dev](https://rapidrest.dev).

## Features

### Authentication Strategies:

* `BasicStrategy` - Simple id and password authentication
* `FIDO2Strategy` - FIDO2/WebAuthn hardware based authentication (e.g. YubiKey)
* `MFAStrategy` - Simple id and password + 2FA authentication [fido2|otp|recovery-code|totp]
* `OIDCStrategy` - OAuth 2.0 & OpenID Connect authentication
* `OTPStrategy` - One-Time Password (OTP) authentication (e.g. email, sms, whatsapp)
* `PasskeyStrategy` - WebAuthn based passkey authentication
* `TOTPStrategy` - RFC 6238 Time-Based One Time Password authentication (e.g. Google Authenticator, etc.)

### Security Features

* Rate limiting on every credential-verification endpoint, layered per-identifier and per-source-IP (reverse-proxy aware) — via `@rapidrest/service-core`'s `RateLimiter`
* App passwords — user-generated, individually-revocable Basic-auth-only credentials for legacy clients that can't complete an MFA challenge
* Secret usage tracking (`Secret.lastUsedAt`) and security event hooks for secret lifecycle/use (password changed, app password created/removed/used, recovery code used), alongside the existing login/registration/elevation/MFA events — see `AuthEventType`
* Durable audit logging (`AuditLogUtils`) for a curated set of security-relevant actions — every genuine sign-in (`SIGNED_IN`, excluding token refresh), impersonation (`IMPERSONATED`), elevation, account deletion, session revocation, and secret lifecycle/use — separate from the best-effort `EventUtils` telemetry above; see "Audit logging" below
* MFA recovery/backup codes as a first-class secondary authentication method
* Account elevation (`@RequiresElevation`) for step-up re-verification before sensitive actions
* Session revocation ("log out everywhere") that invalidates every outstanding refresh token for an account
* Optional TOTP secret encryption at rest (AES-256-GCM)
* Configurable Argon2 password hashing cost parameters
* Client-side pre-hashed (Argon2id) password support, alongside plaintext, so a capable client's real password never reaches the server
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
* `BaseRegistrationRoute` - Self-service account registration via OTP-verified email or phone

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
| `argon2` | Password (`Basic`, `MFA`) secrets — password hashing |
| `otplib` | `TOTP`, `OTP`, and `MFA` secrets/strategies |
| `@simplewebauthn/server` | `Passkey` and `FIDO2` strategies |
| `jwks-rsa` | Verifying `OIDC` providers that publish a JWKS endpoint |

Strategies dynamically `import()` their optional dependency the first time they're used and throw a descriptive
error (naming the missing package) if it isn't installed, rather than failing at package install time.

## License

MPL v2.0 — see [LICENSE](./LICENSE).

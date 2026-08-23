# Release Notes

## Unreleased

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

* Rate limiting on every credential-verification endpoint, layered per-identifier and per-source-IP (reverse-proxy aware)
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

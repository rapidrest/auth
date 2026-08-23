# RapidREST: Authentication Library

[![CI](https://github.com/rapidrest/auth/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rapidrest/auth/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/rapidrest/auth/badge.svg?branch=main)](https://coveralls.io/github/rapidrest/auth?branch=main)
[![npm version](https://img.shields.io/npm/v/@rapidrest/auth)](https://www.npmjs.com/package/@rapidrest/auth)

A library for implementing a complete authentication server with [RapidREST](https://rapidrest.dev). It
provides the data models, persistence adapters, and HTTP routes needed to register and authenticate users via
password, TOTP, OTP (email/SMS), WebAuthn passkeys, FIDO2 hardware security keys, multi-factor authentication, and
OpenID Connect / OAuth 2.0. Using this library you can stand up a fully featured authorization server by writing
configuration and a handful of one-line route classes.

For complete documentation please visit [RapidREST.dev](https://rapidrest.dev).

## Features

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

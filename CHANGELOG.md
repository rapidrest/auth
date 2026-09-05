# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0-beta.2] - 2026-09-05

### Added
- Added BaseOAuthClientRoute for owner/admin Client CRUD
- Added regenerate-secret action and one-time secret reveal on create
- Added BaseOAuthClientRoute entry to the changelog

### Changed
- Change Client ACL to allow self-service creation (Secret's pattern)
- Wire up SQL/Mongo bindings and test-server routes
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Condense pre-release changelog into a single Unreleased listing
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>

While `2.0.0` is in pre-release (`2.0.0-beta.x`), all changes toward it are condensed into this single
listing rather than split per beta tag. This section will be finalized as `[2.0.0]` once it's officially
tagged.

### Added
- OAuth 2.0 / OpenID Connect authorization server: signing keys, `Client` model, and JWKS endpoint
- Authorization Code + PKCE flow with consent, and the `/token` endpoint (`authorization_code` grant)
- Refresh token grant with rotation and reuse/theft detection
- `client_credentials` grant
- Token revocation (`/revoke`) and introspection (`/introspect`) endpoints
- OIDC `/userinfo`, discovery metadata, and `OAuthBearerStrategy`
- `BaseOAuthClientRoute`: owner/admin CRUD for registering and managing `Client`s, including one-time secret reveal and secret regeneration

### Changed
- `Client`'s ACL now lets any authenticated caller register and manage their own client, the same ownership pattern `Secret` already uses (previously admin/internal-only)
- Bumped `@rapidrest/core` to `5.2.0` for its `JWTUtils` asymmetric-signing fix
- Switched to the `@rapidrest/cli` release tooling

### Fixed
- `iss` claim is now mandatory on every issued token, per OIDC Core
- `/authorize` now honors the `prompt` parameter (`none`/`login`/`select_account`/`consent`) per OIDC Core §3.1.2.1
- Refresh tokens issued for an OIDC flow now require the `offline_access` scope, per OIDC Core §11
- Fixed a circular-import hazard across every `Base*RouteSQL`/`Mongo` file
- Fixed `getPublicJwks()` returning an empty set on a fresh deployment
- Fixed `RepoUtils.findOne()`/`find()` silently stripping `@RequiresScope`-gated fields needed by `/userinfo`
- Fixed `BaseOAuthDiscoveryRoute` missing `@Inject`/`@Init`/`@Model` metadata, which broke route registration for it and any route sharing its mount point

### Removed
- Removed the custom `/authorize` endpoint from `BaseAuthOIDCRoute`, superseded by the `no_redirect=true` flag on `login()`

## [1.3.0] - 2026-08-28

### Added
- `OIDCStrategy` now supports passing in a `no_redirect=true` query flag to return the authorization URL as a JSON payload instead of a `302` redirect

## [1.2.0] - 2026-08-27

### Fixed
- Fixed `BaseAuthOIDCRoute` instantiating `OIDCStrategy` using the literal `default` name instead of the configured strategy name, which broke support for multiple OIDC providers

### Added
- Added new `/authorize` endpoint to `BaseAuthOIDCRoute` for building and returning the OAuth authorization URL

## [1.1.1] - 2026-08-27

### Fixed
- Fixed bad import of `jsonwebtoken` in `OIDCStrategy`

## [1.1.0] - 2026-08-27

### Fixed
- Fixed `BaseAuthOIDCRoute` hardcoding its registered strategy name to the literal `oauth`, which made it impossible to wire up more than one OIDC/OAuth provider in the same application

### Added
- Added an overridable `strategyName` field to `BaseAuthOIDCRoute` so subclasses can register additional OIDC/OAuth providers under their own name

## [1.0.0] - 2026-08-22

### Added
- Initial release
- `BasicStrategy` - Simple id and password authentication
- `FIDO2Strategy` - FIDO2/WebAuthn hardware based authentication (e.g. YubiKey)
- `MFAStrategy` - Simple id and password + 2FA authentication [fido2|otp|recovery-code|totp]
- `OIDCStrategy` - OAuth 2.0 & OpenID Connect authentication
- `OTPStrategy` - One-Time Password (OTP) authentication (e.g. email, sms)
- `PasskeyStrategy` - WebAuthn based passkey authentication
- `TOTPStrategy` - RFC 6238 Time-Based One Time Password authentication (e.g. Google Authenticator, etc.)

[Unreleased]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.2...HEAD
[2.0.0-beta.2]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.1...v2.0.0-beta.2
[1.3.0]: https://github.com/rapidrest/auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rapidrest/auth/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/rapidrest/auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rapidrest/auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rapidrest/auth/commit/ab1a7df478c9c75a5af490ffee031fd33db97afc

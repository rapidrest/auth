# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0-beta.1] - 2026-09-05

### Added
- Added OAuth 2.0 authorization server foundation: signing keys and client model
- Added OAuth 2.0 Authorization Code + PKCE flow, consent, and token endpoint
- Added OAuth 2.0 refresh token grant with rotation and reuse detection
- Added OAuth 2.0 client_credentials grant
- Added OAuth 2.0 token revocation and introspection endpoints
- Added OIDC /userinfo, discovery metadata, and OAuthBearerStrategy
- added where none was needed.

### Changed
- Reverting custom /authorize endpoint in BaseAuthOIDCRoute for returning the authorization URL
- Updated CHANGELOG to conform to the 'keep-a-changelog' standard
- Updated release script to write changelog with new format
- Phase 1 of authorization-server support (see plan): introduces the `Client`
- and `SigningKey` models (Mongo+SQL), `SigningKeyUtils` for RSA key
- generation/rotation/encrypted-at-rest storage, `ClientAuthUtils` for
- token-endpoint client authentication, and a `BaseOAuthJwksRoute` exposing
- the public JWK set. This is the foundation every later grant-type/endpoint
- phase builds on.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Fix: getPublicJwks() returned an empty set on a fresh deployment
- getActiveSigningKey() only lazily generates a key when called directly;
- getPublicJwks() queried the SigningKey table without ever calling it, so a
- deployment's very first /jwks.json request returned {keys: []} instead of
- generating the deployment's first signing key. Surfaced by re-running the
- Phase 1 JWKS integration tests once the sandboxed network issue blocking
- them was resolved.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Phase 2 of authorization-server support: BaseOAuthAuthorizeRoute (/authorize
- + consent decision, session-based resource-owner resolution so federation
- through an upstream IdP like Entra needs zero RP-side changes) and
- BaseOAuthTokenRoute (authorization_code grant, PKCE verification, one-time
- code enforcement, RFC 6749 §5.2 error shape). New AuthorizationCode and
- ConsentGrant models (Mongo+SQL), OAuthTokenUtils for RS256 access/ID token
- issuance, and PKCE/opaque-token helpers in shared.ts.
- Also fixes a pre-existing circular-import hazard across every
- Base*RouteSQL/Mongo file in this package: each imported its concrete model
- types via this package's own top-level barrel (e.g. "../../mongo.js")
- instead of the model files directly, creating a cycle back through
- routes/mongo.js. Switched all of them (including this phase's own new
- files) to import from models/{mongo,sql}/index.js directly.
- Bumps @rapidrest/core to 5.2.0 for its JWTUtils asymmetric-signing fix,
- required for RS256 token issuance here.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Implements Phase 3: the /token refresh_token grant (RFC 6749 §6), backed
- by a new OAuthRefreshToken model (opaque, SHA-256-hashed at rest). Every
- successful redemption rotates the token within its family and narrows
- scope on request; presenting an already-rotated-out token is treated as
- theft and revokes the whole family (RFC 9700 §4.14.2). The authorization_code
- grant now also issues a refresh token whenever the client's grantTypes
- includes refresh_token.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Implements Phase 4: the /token client_credentials grant (RFC 6749 §4.4)
- for machine-to-machine access, restricted to confidential clients whose
- grantTypes includes client_credentials. Scope is limited to the client's
- own registered scope (down-selected, never widened), and no refresh_token
- or id_token is ever issued since there is no resource owner.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Implements Phase 5: /revoke (RFC 7009) and /introspect (RFC 7662).
- Refresh tokens are revoked in place; access tokens (stateless RS256
- JWTs) are "revoked" by recording their jti in a new AccessTokenDenylist
- (Redis-backed with an in-memory fallback, same pattern as RateLimiter)
- until natural expiry. Adds OAuthTokenUtils.verifyAccessToken() to
- verify a token's signature against the signing key named by its kid
- (including a retired one still in its grace period), shared by both
- new endpoints. /revoke always returns 200 without revealing whether a
- token existed; /introspect requires a confidential-client caller and
- returns {active:false} rather than an error for anything invalid,
- expired, or revoked. The RFC 6749 §5.2 OAuthError/toOAuthError helper
- used by /token is factored out to auth/OAuthError.ts so /revoke and
- /introspect can share it.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Implements Phase 6. /userinfo (OIDC Core §5.3) authenticates via the
- access token itself through a new OAuthBearerStrategy (verifying via
- OAuthTokenUtils.verifyAccessToken + AccessTokenDenylist, both reused
- unchanged from Phase 5), gated by @RequiresScope(["openid"]), and
- returns claims scoped to profile/email/phone sourced from the
- resource owner's existing Profile record - no User fetch, no new
- persistence path, and no redundant endpoint for data BaseUserRoute
- already exposes, since this route's auth model and response shape are
- both protocol-mandated and distinct from that CRUD surface.
- BaseOAuthDiscoveryRoute serves RFC 8414 / OIDC Discovery metadata; a
- single instance covers both well-known paths since the document is
- identical for this deployment's purposes, so no SQL/Mongo split was
- Fixes two real bugs found while integration-testing this phase:
- - RepoUtils.findOne()/find() silently strips any @RequiresScope-gated
- model field (e.g. Profile.contacts) based on options.user.scopes,
- independent of ignoreACL. /userinfo's own OIDC-scope check is a
- different, unrelated vocabulary, so the Profile read now explicitly
- grants the internal scopes those fields require.
- - BaseOAuthDiscoveryRoute was the only route in this library with no
- @Inject/@Init/@Model metadata at all, which broke ObjectFactory's
- route-scanning for it and any other route sharing its mount point.
- route already follows.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- - OAuthTokenUtils now requires auth:oauth_server:issuer to be
- configured, throwing a clear 500 instead of silently omitting `iss`
- from every signed token (OIDC Core mandates it be present).
- - BaseOAuthAuthorizeRoute now honors the OIDC Core §3.1.2.1 `prompt`
- parameter: `none` fails fast with a login_required/consent_required
- error redirect instead of the usual interactive-response shape;
- `login`/`select_account` force fresh interaction even with an
- active session; `consent` forces the consent screen even with a
- sufficient existing grant. `none` combined with any other value is
- rejected with invalid_request per spec.
- - Refresh-token issuance for an OIDC flow (openid in scope) now also
- requires the offline_access scope, per OIDC Core §11 - a plain
- OAuth flow (no openid) is unaffected and still governed solely by
- the client's registered grant types.
- Dynamic Client Registration (RFC 7591/7592) and Session/Front/Back-
- channel Logout remain out of scope for now - both are optional OIDC
- extensions, not required for Basic-profile conformance.
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Switched to cli's release script

### Fixed
- Fixed by adding the same _objectFactory/@Init shape every other
- Fixed three OIDC conformance gaps: iss, prompt, offline_access

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

[Unreleased]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.1...HEAD
[2.0.0-beta.1]: https://github.com/rapidrest/auth/compare/v1.3.0...v2.0.0-beta.1
[1.3.0]: https://github.com/rapidrest/auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rapidrest/auth/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/rapidrest/auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rapidrest/auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rapidrest/auth/commit/ab1a7df478c9c75a5af490ffee031fd33db97afc

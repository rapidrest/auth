# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0-beta.14] - 2026-09-25

### Changed
- Document that a downstream package's release bump level follows its upstream dependency's, minor for minor, patch for patch and major for major, in NOTES

### Fixed
- Fixed passkey sign-in on MongoDB, where toUint8Array() turned the stored BSON Binary public key into three garbage bytes and @simplewebauthn/server then failed with "decodedPublicKey.get is not a function", by restoring the real key from a Binary, a base64 string, a JSON-serialized Buffer, an array or an index-keyed object Add User.passwordChangeRequired, settable only by a trusted user and cleared when the account holder changes their own password Add allowUserChange to POST and PUT /secrets so a trusted user can give the account holder rights on a password it set for them (true), which an admin-created password never granted, or take them away for good (false), which nothing could do before Waive the elevation requirement on PUT /secrets/:id for an account holder changing their own password while passwordChangeRequired is set, checked in the handler because @RequiresElevation(60) can't be waived per request Add the allowMultiplePasswords system setting (auth:allowMultiplePasswords, off by default, changeable at runtime via PUT /settings and stored like allowRegistration), enforced when a password secret is created, so an account has one password unless an administrator allows several; this changes behavior for anyone relying on several Add tests for each, including integration tests against a real server, and document the changes in the changelog and release notes

### Added
- Added the `allowMultiplePasswords` system setting (`auth:allowMultiplePasswords`, default `false`, editable via `PUT /settings` like `allowRegistration`): unless it's on, an account can have only one `password` secret, enforced when one is created
- Added `allowUserChange=false` to `PUT /secrets/:id`, which removes the account holder's rights on the password so only an administrator can change or remove it
- Added `User.passwordChangeRequired`, set only by a trusted user, and cleared when the account holder changes their own password via `PUT /secrets/:id`
- Added an `allowUserChange=true` query parameter to `POST /secrets`, which lets a trusted user creating a `password` for another account grant that account READ/EXISTS/UPDATE on it
- Extended `allowUserChange=true` to `PUT /secrets/:id`, so a trusted user resetting a password its holder could not change can make it changeable
- Exported `toUint8Array()` from the shared auth helpers

### Changed
- Waived the elevation requirement on `PUT /secrets/:id` for an account holder changing their own password while `passwordChangeRequired` is set; the check is now made in the handler rather than by `@RequiresElevation(60)`, and applies unchanged in every other case

### Fixed
- Fixed passkey sign-in always failing on MongoDB with `decodedPublicKey.get is not a function`: the stored public key comes back as a BSON `Binary` (or a base64 string via a JSON cache), which `toUint8Array()` turned into garbage bytes instead of the key
- Fixed a password an administrator set for another account being impossible for that account to change, since the admin, a trusted role, is exempt from the implicit creator ACL grant and the account holder had no rights on the record

## [2.0.0-beta.13] - 2026-09-23

### Added
- Added CsrfUtils, issuing/rotating a host-only, non-HttpOnly csrf double-submit cookie alongside jwt/refresh at login, refresh and elevation, and clearing it at logout via TokenUtils
- Added an explicit CSRF check to BaseOAuthAuthorizeRoute.decideConsent(), which authenticates via req.session directly and is never covered by the framework's automatic jwt-cookie-keyed CSRF gate
- Added regression tests for each of the above and document the findings in NOTES.md

### Changed
- Inject CsrfUtils into TokenUtils.createAuthResult()/clearToken() so the CSRF cookie's lifecycle tracks the session cookies it protects, without changing behavior for anyone who hasn't opted into auth:csrf.enabled
- Change BaseImpersonationRoute's GET /impersonate/stop to POST, since a state-changing GET is exploitable via a bare cross-site/same-site navigation and bypasses CSRF defenses entirely
- Export CsrfUtils from the package root, the same pattern as AuditLogUtils
- Document the changes in the README, CHANGELOG, release notes and NOTES
- Upgraded deps

### Added
- Added CsrfUtils, issuing/rotating a host-only, non-HttpOnly `csrf` double-submit cookie alongside the `jwt`/`refresh` cookies at login/refresh/elevation, and clearing it at logout, as CSRF protection for cookie-authenticated requests (the enforcement itself lives in `@rapidrest/service-core`'s `RouteUtils.checkCsrf()`)
- Added an explicit CSRF check to BaseOAuthAuthorizeRoute.decideConsent(), which authenticates via req.session directly and bypasses the framework's automatic jwt-cookie-keyed CSRF gate entirely

### Changed
- Changed BaseImpersonationRoute's `/impersonate/stop` from GET to POST — a state-changing GET is exploitable via a bare cross-site/same-site navigation, bypassing even CSRF defenses that only ever apply to non-safe methods
- Document the changes in the README, CHANGELOG, release notes and NOTES

## [2.0.0-beta.12] - 2026-09-22

### Added
- Added SecretType.APP_PASSWORD, a user-generated high-entropy secret for a single legacy Basic-auth client that can't complete an MFA challenge
- Added generateAppPassword and validateAppPasswordCreate, requiring a non-empty hint since an account may accumulate several, discarding any caller-supplied data, and returning the plaintext exactly once
- Added auth:app_password:enabled, read independently by BaseSecretRoute and BaseAuthBasicRoute, to turn app passwords off deployment-wide without deleting any that already exist
- Added Secret.lastUsedAt, updated on every successful authentication against the matching secret, through a new best-effort touchSecretLastUsedAt helper or merged into an existing per-secret write where one already happens
- Added PASSWORD_CHANGED, APP_PASSWORD_CREATED, APP_PASSWORD_REMOVED, APP_PASSWORD_USED and RECOVERY_CODE_USED audit events, fired the same fire-and-forget way as the existing ones
- Added AuditLogUtils, a durable audit log mechanism separate from EventUtils, which is lossy best-effort telemetry never intended to guarantee anything is actually recorded
- Added SecretType-adjacent AuthEventType.SIGNED_IN and IMPERSONATED, the two curated actions that had no event of their own before now
- Added a parallel AuditLogUtils.record call at every existing EventUtils.record call site, awaited and logged loudly on failure rather than swallowed, so the triggering action still succeeds even when the write does not
- Added junit.xml to gitignore

### Changed
- Let an app password authenticate through BaseAuthBasicRoute even when requireMFA is set, checked before that gate, while a real password remains subject to it exactly as before
- Refuse changing an app password's data on update, same as FIDO2 and passkey secrets, since rotating one means deleting and creating a new one
- Document the changes in the README, CHANGELOG, release notes and NOTES
- Give TokenUtils.createAuthResult an optional authMethod argument, threaded through every caller with its own descriptive string, so a real sign-in can be told apart from a routine token refresh, which never passes one and so never fires SIGNED_IN
- Fire IMPERSONATED from BaseImpersonationRoute with the admin as actorUid and the target account as userUid, closing what was previously a total gap in that route's audit trail
- Export AuditLogUtils and AuditLogEntry from the package root, the one thing a consuming app's database-backed subclass actually needs to import
- Document the changes in the README, CHANGELOG, release notes and NOTES

### Added
- Added SecretType.APP_PASSWORD, a user-generated high-entropy credential for a single legacy Basic-auth client that can't complete an MFA challenge
- Added generateAppPassword to src/auth/shared.ts, a single Crockford Base32 value grouped with dashes for readability
- Added validateAppPasswordCreate to BaseSecretRoute, requiring a non-empty hint, discarding any caller-supplied data, and returning the generated plaintext exactly once as password in the create response
- Added auth:app_password:enabled (default true) to BaseSecretRoute and BaseAuthBasicRoute, gating creation and the requireMFA bypass independently
- Added an app-password bypass to BaseAuthBasicRoute.verify(), checked before the requireMFA gate, so a matching app password authenticates regardless of that flag while a real password remains subject to it unchanged
- Added Secret.lastUsedAt (ISO-8601 string, unset until first use), persisted on every successful authentication against the matching secret (password, app password, TOTP, FIDO2/passkey credential, recovery code) via a best-effort, non-blocking write that never fails the authentication response
- Added touchSecretLastUsedAt to src/auth/shared.ts, a shared best-effort helper used by BaseAuthBasicRoute/BaseAuthMFARoute/BaseAuthElevationRoute for a matched secret with no write of its own already in flight
- Added AuthEventType.PASSWORD_CHANGED, fired from BaseSecretRoute when a password secret is created or its data is changed via update (not on a hint-only rename)
- Added AuthEventType.APP_PASSWORD_CREATED and APP_PASSWORD_REMOVED, fired from BaseSecretRoute.create()/delete() for the app-password type, kept separate from MFA_ENROLLED/MFA_REMOVED since app passwords are deliberately not MFA
- Added AuthEventType.APP_PASSWORD_USED, fired from BaseAuthBasicRoute on a successful app-password match, in addition to the generic SESSION_CREATED event, since it specifically signals that requireMFA was bypassed for that login
- Added AuthEventType.RECOVERY_CODE_USED, fired from BaseAuthMFARoute.consumeRecoveryCode() on a successful recovery-code use
- Added an optional req parameter to BasicStrategyOptions.verify and MFAStrategyOptions.consumeRecoveryCode so the source IP can be recorded on the new app-password/recovery-code events
- Added AuditLogUtils (src/auth/AuditLogUtils.ts), a separate durable audit-log mechanism for security-relevant actions - the base implementation logs via @Logger, and a consuming app registers a database-backed subclass under the same class name to make it durable, the same DI-swap pattern MessagingUtils already uses
- Added the AuditLogEntry interface ({type, userUid?, actorUid?, ip?, path?, method?, data?}), recorded in parallel with every existing EventUtils.record() call site (ACCOUNT_DELETED, SESSIONS_REVOKED, ELEVATED, APP_PASSWORD_USED, RECOVERY_CODE_USED, REGISTRATION_COMPLETED, MFA_ENROLLED/MFA_REMOVED, PASSWORD_CHANGED, APP_PASSWORD_CREATED/APP_PASSWORD_REMOVED), always fail-open with the failure logged loudly rather than swallowed
- Added AuthEventType.SIGNED_IN, fired from TokenUtils.createAuthResult() via AuditLogUtils whenever it's given an authMethod - a genuine new sign-in of any kind, deliberately excluding token refresh, elevation and impersonation
- Added AuthEventType.IMPERSONATED, fired from BaseImpersonationRoute.impersonate() via AuditLogUtils with actorUid/userUid distinguishing the impersonator from the impersonated account - previously impersonation had no audit trail at all
- Added an authMethod parameter to TokenUtils.createAuthResult(), threaded through every sign-in route (password, app-password, mfa, passkey, fido2, totp, otp, oidc:<provider>, registration) to drive the new SIGNED_IN entry; BaseAuthRefreshRoute deliberately omits it

## [2.0.0-beta.11] - 2026-09-22

### Added
- Added OTPContactType.WHATSAPP and mask it like SMS in obfuscateContact
- Added a WhatsApp discover hint (channel: "whatsapp") after a verified phone's SMS hint in BaseAuthDiscoverRoute
- Added an optional channel argument to OTPStrategy.getContact and the /auth/otp challenge request, honored only for a verified phone with WhatsApp configured
- Added a WhatsApp OTP method (id "<alias uid>:whatsapp") alongside a verified phone's SMS method in BaseAuthMFARoute and BaseAuthElevationRoute, resolved by getMethod
- Added isWhatsAppConfigured, toWhatsAppMethodId and parseWhatsAppMethodId to src/auth/shared.ts, offering WhatsApp only when a MessagingUtils instance's optional isWhatsAppConfigured() hook says so, or its whatsapp field is set

### Changed
- Upgraded @rapidrest/core dep
- Send the WhatsApp OTP through MessagingUtils.sendWhatsApp, with the same catch-and-log pattern SMS uses
- Leave contact verification and registration codes on e-mail/SMS only
- Document the change in the README, CHANGELOG, release notes and NOTES

### Added
- Add WhatsApp as a one-time code delivery channel for verified phone contacts, alongside SMS, offered only while WhatsApp is configured

## [2.0.0-beta.10] - 2026-09-20

### Added
- Added an optional domain to the auth cookie configuration so the jwt and refresh cookies can be shared with sibling subdomains, on the clearing headers as well as the ones that set them

### Changed
- Upgraded @rapidrest/cli

### Fixed
- Fixed restoring an impersonated session writing a host-only jwt cookie beside the domain-scoped one when a cookie domain is configured

## [2.0.0-beta.9] - 2026-09-17

### Added
- Added a runtime-togglable SystemSettings for registration and MFA policy, and a dedicated BaseSettingsRoute to expose it
- Added BaseSettingsRoute (GET public, PUT trusted-role-only) to serve and update SystemSettings, with requireMFA gated behind @RequiresScope so only a trusted admin (or a token carrying the "system" scope) sees it in the response. Deliberately don't put that same @RequiresScope on the persistence models (SystemSettingsSQL/Mongo): RepoUtils applies it to every internal read/write regardless of caller, and since SystemSettingsUtils never passes a user, doing so there silently stripped requireMFA from every entity it read back, making the stored value permanently unreadable to the code enforcing it.

### Changed
- Introduce SystemSettings (allowRegistration, requireMFA) as a single persisted record read/written through SystemSettingsUtils, seeded from @Config the first time it's read and authoritative from then on; unlike the auth:allowRegistration/auth:requireMFA config it replaces as the source of truth, it has no "revert to config" null sentinel, so update() rejects null and any non-boolean value outright rather than silently accepting either. Wire it into every path that can create a User: BaseUserRoute.validateCreate/validateUpdate, BaseRegistrationRoute's OTP start/verify, and BaseAuthOIDCRoute's first-time OAuth sign-in all now consult the stored setting, closing registration server-wide without a restart. Fix BaseUserRoute.validateCreate forcing requireMFA to the stored value even when the mandate is off, discarding a caller's own opt-in, and validateUpdate reading the static config snapshot instead of the same runtime setting validateCreate uses. Seed both fields (not just allowRegistration) when the record is first created.
- Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
- Updated service-core and release notes

## [2.0.0-beta.8] - 2026-09-15

### Changed
- Upgraded service-core to 2.1.0

### Fixed
- Fixed unit tests
- Fixed peer dependency range for service-core

## [2.0.0-beta.7] - 2026-09-10

### Added
- Added client-side pre-hashed (Argon2id) password support

### Added
- Client-side pre-hashed (Argon2id) password support, alongside plaintext

## [2.0.0-beta.6] - 2026-09-09

### Changed
- Upgraded @rapirest/service-core dep

## [2.0.0-beta.5] - 2026-09-09

### Changed
- Move RateLimiter to @rapidrest/service-core, import it from there instead
- Apply the new @RateLimit() decorator to OIDC discovery, JWKS, client secret regeneration, and impersonation
- Bump @rapidrest/service-core dependency to ^1.7.1
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Bump @rapidrest/core to ^5.2.2 and @rapidrest/service-core to ^1.7.2
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
- Updated CI workflows

### Removed
- Removed AuthEventType.RATELIMIT_EXCEEDED in favor of service-core's RATELIMIT_EXCEEDED_EVENT

## [2.0.0-beta.4] - 2026-09-07

### Added
- Added new user impersonation feature

### Changed
- RateLimiter now gracefully falls back to in-memory incrementor when redis cache server does not support the INCREX command
- Preparing release_notes for release

## [2.0.0-beta.3] - 2026-09-06

### Added
- Added real-DB integration tests for BaseOAuthClientRoute (sql/mongo)
- Added commit message rules for Claude

### Changed
- Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>

### Removed
- Removed Client.clientId; use Client.uid as the OAuth client_id

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

[Unreleased]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.14...HEAD
[2.0.0-beta.14]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.13...v2.0.0-beta.14
[2.0.0-beta.13]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.12...v2.0.0-beta.13
[2.0.0-beta.12]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.11...v2.0.0-beta.12
[2.0.0-beta.11]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.10...v2.0.0-beta.11
[2.0.0-beta.10]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.9...v2.0.0-beta.10
[2.0.0-beta.9]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.8...v2.0.0-beta.9
[2.0.0-beta.8]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.7...v2.0.0-beta.8
[2.0.0-beta.7]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.6...v2.0.0-beta.7
[2.0.0-beta.6]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.5...v2.0.0-beta.6
[2.0.0-beta.5]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.4...v2.0.0-beta.5
[2.0.0-beta.4]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.3...v2.0.0-beta.4
[2.0.0-beta.3]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.2...v2.0.0-beta.3
[2.0.0-beta.2]: https://github.com/rapidrest/auth/compare/v2.0.0-beta.1...v2.0.0-beta.2
[1.3.0]: https://github.com/rapidrest/auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rapidrest/auth/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/rapidrest/auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rapidrest/auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rapidrest/auth/commit/ab1a7df478c9c75a5af490ffee031fd33db97afc

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/rapidrest/auth/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/rapidrest/auth/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rapidrest/auth/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/rapidrest/auth/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rapidrest/auth/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rapidrest/auth/commit/ab1a7df478c9c75a5af490ffee031fd33db97afc

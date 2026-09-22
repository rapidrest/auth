////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////

/**
 * The security-relevant event types this library emits, shared across two separate sinks:
 * `@rapidrest/core`'s `EventUtils.record()` (lossy, best-effort telemetry - silently discarded end to end
 * unless the consuming app configures `telemetry_services:url` and registers its own `EventUtils.on()`
 * listener) and this library's own `AuditLogUtils.record()` (see `./AuditLogUtils.ts`) - a separate,
 * durable-by-default mechanism meant for real audit-log purposes. Most values below are recorded through
 * both sinks in parallel at their existing call site; `SIGNED_IN`/`IMPERSONATED` are `AuditLogUtils`-only,
 * since routine token refresh already makes `SESSION_CREATED` unsuitable as a "real sign-in" signal, and
 * impersonation previously had no audit trail via either sink.
 */
export enum AuthEventType {
    /**
     * A JWT access token was issued for a user. This covers every successful login (any strategy), token refresh,
     * self-registration, and elevation. Fired from `TokenUtils.createAuthResult()`, the single chokepoint
     * every one of those flows already calls through. Recorded via `EventUtils` only - see `SIGNED_IN` for
     * the `AuditLogUtils` equivalent that excludes token refresh (and elevation/impersonation, which get
     * their own dedicated entries).
     */
    SESSION_CREATED = "auth.session.created",
    /**
     * A genuine new authentication of any kind (password, app-password, an MFA second factor, passkey,
     * FIDO2, direct TOTP/OTP, an OAuth/OIDC provider, or self-registration). Fired from
     * `TokenUtils.createAuthResult()` whenever it's given an `authMethod` - deliberately NOT fired for a
     * token refresh, and NOT fired for elevation (see `ELEVATED`) or impersonation (see `IMPERSONATED`),
     * which each get their own more specific entry instead. Recorded via `AuditLogUtils` only.
     */
    SIGNED_IN = "auth.signed_in",
    /**
     * A trusted-role holder began impersonating another account (`BaseImpersonationRoute.impersonate()`).
     * Recorded via `AuditLogUtils` only - previously this action had no audit trail at all.
     */
    IMPERSONATED = "auth.impersonated",
    /** A new account finished self-registration (OTP-verified email/phone). */
    REGISTRATION_COMPLETED = "auth.registration.completed",
    /** A caller successfully re-verified their identity to obtain an elevated (trusted-role-bearing) token. */
    ELEVATED = "auth.elevated",
    /** Every outstanding refresh token for an account was revoked ("log out everywhere"). */
    SESSIONS_REVOKED = "auth.sessions.revoked",
    /** An account and all of its associated data was deleted. */
    ACCOUNT_DELETED = "auth.account.deleted",
    /** A secondary-auth-capable secret (FIDO2/passkey/TOTP/recovery codes - not a plain password) was created. */
    MFA_ENROLLED = "auth.mfa.enrolled",
    /** A secondary-auth-capable secret was deleted. */
    MFA_REMOVED = "auth.mfa.removed",
    /** A `password`-type secret was created, or an existing one's value (not just its `hint`) was changed. */
    PASSWORD_CHANGED = "auth.password.changed",
    /** A new `app-password` secret (see `SecretType.APP_PASSWORD`) was created. */
    APP_PASSWORD_CREATED = "auth.app_password.created",
    /** An `app-password` secret was deleted. */
    APP_PASSWORD_REMOVED = "auth.app_password.removed",
    /**
     * An `app-password` secret was used to successfully authenticate at `/auth/basic` - the single most
     * security-relevant signal of the three `app-password` events, since a match there means `requireMFA`
     * was bypassed for this login. Fired in addition to `SESSION_CREATED`, which fires generically for
     * every successful login regardless of method.
     */
    APP_PASSWORD_USED = "auth.app_password.used",
    /** A `recovery-codes` secret's code was successfully used to authenticate, consuming that one code. */
    RECOVERY_CODE_USED = "auth.recovery_code.used",
}

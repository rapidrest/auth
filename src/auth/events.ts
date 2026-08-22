////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////

/**
 * The security-relevant event types this library emits via `@rapidrest/core`'s `EventUtils.record()`.
 */
export enum AuthEventType {
    /**
     * A JWT access token was issued for a user. This covers every successful login (any strategy), token refresh,
     * self-registration, and elevation. Fired from `TokenUtils.createAuthResult()`, the single chokepoint
     * every one of those flows already calls through.
     */
    SESSION_CREATED = "auth.session.created",
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
    /**
     * A rate limit was exceeded (either the per-identifier or the per-source-IP layer - see `layer` on the
     * event). A brute-force/abuse signal covering every rate-limited route from one call site, rather than
     * instrumenting each strategy's individual "wrong password"/"invalid code" branches.
     */
    RATELIMIT_EXCEEDED = "auth.ratelimit.exceeded",
}

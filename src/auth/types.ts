////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////

/**
 * The different types of supported contact methods.
 */
export enum OTPContactType {
    EMAIL = "email",
    SMS = "sms",
}

/**
 * Describes a single verified contact that can be used to send a OTP code to the user.
 */
export interface OTPContact {
    /** The contact that the OTP can be sent to. */
    contact: string;
    /** The method type of contact (e.g. email, sms). */
    type: OTPContactType;
    /** Indicates if the contact has been verified. */
    verified?: boolean;
}

/**
 * Configuration for a WebAuthn/Passkey relying party.
 */
export interface PasskeyConfig {
    /** The human-readable name of the relying party, shown to the user by the authenticator UI. */
    rpName: string;
    /** The relying party ID — a valid domain name (no scheme/port), e.g. `"example.com"`. */
    rpID: string;
    /**
     * The exact scheme+host+port expected in the client's `clientDataJSON.origin` (e.g.
     * `"https://example.com"`). May be a list to support multiple valid frontend origins.
     */
    origin: string | string[];
    /**
     * Requested user verification behavior at options-generation time. Set to `"discouraged"` for a
     * 2FA-style flow, `"required"`/`"preferred"` otherwise. Default is `"preferred"`.
     */
    userVerification?: "required" | "preferred" | "discouraged";
    /**
     * Whether user verification is *enforced* at response-verification time. This is a distinct
     * knob from `userVerification` above (which only shapes what's requested from the client).
     * Default is `true`.
     */
    requireUserVerification?: boolean;
    /** How long (in ms) the user has to complete the ceremony. Default is `60000`. */
    timeout?: number;
    /**
     * Restricts which category of authenticator may be used to create a new credential during
     * registration. Set to `"cross-platform"` to steer users toward roaming/hardware security keys
     * (e.g. a YubiKey), or `"platform"` for built-in authenticators (Face ID, Windows Hello, etc).
     * Leave unset to allow either — the appropriate default for passkey registration.
     */
    authenticatorAttachment?: "platform" | "cross-platform";
    /**
     * Whether a newly registered credential must be discoverable (usable in a "usernameless" flow).
     * Default is `"preferred"`. A hardware security key used purely as a known-account credential
     * typically doesn't need this and can use `"discouraged"`.
     */
    residentKey?: "discouraged" | "preferred" | "required";
}

/**
 * The transport hints an authenticator can report supporting. Mirrors `@simplewebauthn/server`'s
 * `AuthenticatorTransportFuture` union without a compile-time dependency on that optional package.
 */
export type PasskeyTransport = "ble" | "cable" | "hybrid" | "internal" | "nfc" | "smart-card" | "usb";

/**
 * Configuration for enforcing password strength.
 */
export class PasswordConfig {
    // The minimum length that a password must be
    public readonly min_length: number = 8;
    // The recommended length that a password should be
    public readonly recommended_length: number = 32;
    // Set to true to require at least one lowercase letter
    public readonly require_lowercase: boolean = true;
    // Set to true to require at least one uppercase letter
    public readonly require_uppercase: boolean = true;
    // Set to true to require at least one number
    public readonly require_numeral: boolean = true;
    // Set to true to require at least one special character. If set to true, specialChars must be defined.
    public readonly require_special: boolean = true;
    // The set of special characters that will be used to validate passwords. Kept with `-` last so it's
    // safe to interpolate directly into a regex character class (`[...]`) without being misread as a range.
    public readonly special_chars: string = "!@#$%^&*_+?-";
    // The argon2 memory cost, in KiB, used when hashing a password. Defaults match argon2's own library
    // defaults, so leaving this unconfigured is a no-op — raise it to scale hashing cost with server capacity.
    public readonly hash_memory_cost: number = 65536;
    // The argon2 time cost (number of iterations) used when hashing a password.
    public readonly hash_time_cost: number = 3;
    // The argon2 parallelism (number of threads/lanes) used when hashing a password.
    public readonly hash_parallelism: number = 4;
}

/**
 * A previously-registered WebAuthn credential as persisted by the consuming application.
 */
export interface StoredPasskeyCredential {
    /** The base64url-encoded credential ID. */
    id: string;
    /** The uid of the user this credential belongs to. */
    uid: string;
    /** The credential's public key, as returned by the registration ceremony. */
    publicKey: Uint8Array;
    /** The last-known signature counter for this credential, used to detect cloned authenticators. */
    counter: number;
    /** The transports the authenticator reported supporting, if any (e.g. `["internal", "hybrid"]`). */
    transports?: PasskeyTransport[];
}

/**
 * The HMAC hash algorithms supported for TOTP token generation, per RFC 6238 §1.2.
 */
export type TOTPAlgorithm = "sha1" | "sha256" | "sha512";

/**
 * Configuration for a TOTP (RFC 6238) issuer. Used both to generate the `otpauth://` provisioning
 * URI (the "Key URI Format" companion convention supported by virtually every TOTP authenticator
 * app, e.g. Google Authenticator/Authy/1Password) for enrolling a new secret, and as the default
 * token parameters for newly registered secrets.
 */
export interface TOTPConfig {
    /** The human-readable name of the issuing service, shown to the user by the authenticator app. */
    issuer: string;
    /** The number of digits each generated token contains. Default is `6`. */
    digits?: number;
    /** The time step, in seconds, that each generated token remains valid for. Default is `30`. */
    period?: number;
    /**
     * The HMAC hash algorithm used to generate tokens. Default is `"sha1"` — the only algorithm
     * universally supported by authenticator apps despite RFC 6238 permitting SHA-256/SHA-512.
     */
    algorithm?: TOTPAlgorithm;
    /**
     * Specifies a tolerance window around the current time. It does not represent a strict duration in seconds
     * (e.g., "±N seconds"), but rather dictates which periods overlap with the tolerance window `[currentTime -
     * tolerance, currentTime + tolerance]`. Default value is `[1, 0]`.
     */
    epochTolerance?: number | number[];
}

/**
 * Describes a secret used for TOTP authentication. The `digits`/`period`/`algorithm` parameters are
 * captured at registration time (rather than always deferring to the current `TOTPConfig`) so a
 * secret keeps verifying correctly even if the relying party's configured defaults change later.
 */
export interface TOTPSecret {
    secret: string;
    /** The number of digits the associated token contains, if it differs from the library default. */
    digits?: number;
    /** The time step, in seconds, that the associated token remains valid for, if it differs from the library default. */
    period?: number;
    /** The HMAC hash algorithm used to generate the associated token, if it differs from the library default. */
    algorithm?: TOTPAlgorithm;
    /**
     * Specifies a tolerance window around the current time. It does not represent a strict duration in seconds
     * (e.g., "±N seconds"), but rather dictates which periods overlap with the tolerance window `[currentTime -
     * tolerance, currentTime + tolerance]`. Default value is `[1, 0]`.
     */
    epochTolerance?: number | number[];
    /**
     * The RFC 6238 time step at which a token was last successfully verified for this secret, if
     * any. Used for replay protection: a token that matches at or before this time step is
     * rejected, so an intercepted request can't be replayed for as long as the code remains within
     * its validity window. Populated and persisted by the consuming application.
     */
    lastTimeStep?: number;
    /**
     * The unique id of the underlying stored secret this data belongs to, if attached by the
     * caller. Used internally to identify which specific secret to persist `lastTimeStep` onto when
     * more than one TOTP secret is checked for a user in a single verification.
     */
    uid?: string;
}

/**
 * A single generated MFA recovery/backup code, as persisted on a `RecoveryCodesSecret`. The plaintext code
 * is never persisted - only its argon2 hash - so it can only ever be shown to the user once, at generation
 * time (see `BaseSecretRoute.validateRecoveryCodesCreate()`).
 */
export interface RecoveryCodeEntry {
    /** The argon2 hash of this code's plaintext value. */
    hash: string;
    /** ISO-8601 timestamp at which this code was consumed, if it has been. Unused codes omit this field. */
    usedAt?: string;
}

/**
 * The `data` shape of a `recovery-codes` type `Secret`: a fixed batch of single-use backup codes generated
 * when the secret is created, for authenticating when a user has lost access to their other secondary (MFA)
 * methods. See `MFAStrategy.verifyRecoveryCode()` for how a submitted code is checked against this list, and
 * `BaseAuthMFARoute.consumeRecoveryCode()` for how a matched entry gets marked used.
 */
export interface RecoveryCodesSecret {
    codes: RecoveryCodeEntry[];
}

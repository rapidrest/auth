////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
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
}

/**
 * The transport hints an authenticator can report supporting. Mirrors `@simplewebauthn/server`'s
 * `AuthenticatorTransportFuture` union without a compile-time dependency on that optional package.
 */
export type PasskeyTransport = "ble" | "cable" | "hybrid" | "internal" | "nfc" | "smart-card" | "usb";

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
}

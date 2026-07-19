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
 * Describes a secret used for TOTP authentication.
 */
export interface TOTPSecret {
    secret: string;
}

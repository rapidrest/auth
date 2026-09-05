////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import * as crypto from "crypto";
import { ApiError } from "@rapidrest/core";
import { ApiErrors, HttpRequest } from "@rapidrest/service-core";
import {
    OTPContactType,
    PasskeyConfig,
    PasskeyTransport,
    PasswordConfig,
    StoredPasskeyCredential,
    TOTPConfig,
    TOTPSecret,
} from "./types.js";

const headerSchemeRegExps: Map<string, RegExp> = new Map();

/**
 * Attempts to decode the request for authentication Basic request data
 * (e.g. `Authorization: basic base64("<id>:<password>")).
 *
 * @param req The request to return auth request data for.
 * @param headerKey The name of a header to look for request data in. Set to an empty string to skip
 * the header search entirely — passing `undefined` has no effect, since that just triggers the
 * default value. Default is 'Authorization'.
 * @param headerScheme The header scheme to look for. Default is 'basic'.
 * @returns An object with format `{id: <username>, password: <password> }, otherwise `undefined`.
 */
export const getBasicData = function (
    req: HttpRequest,
    headerKey: string = "authorization",
    headerScheme: string = "basic",
): any {
    let result: any = undefined;

    // Check the headers. It's possible there is more than one header value defined. Loop through each of
    // them until we have verified auth request data.
    if (headerKey in req.headers) {
        const value: string | string[] | undefined = req.headers[headerKey];
        const headers: string[] = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];

        // Loop throught through the headers looking for a value with a matching scheme
        for (const header in headers) {
            const parts: string[] = headers[header].split(" ");
            if (parts.length !== 2) {
                continue;
            }

            const regexHeaderScheme: RegExp =
                headerSchemeRegExps.get(headerScheme) ?? new RegExp("^" + headerScheme + "$", "i");
            if (!headerSchemeRegExps.has(headerScheme)) {
                headerSchemeRegExps.set(headerScheme, regexHeaderScheme);
            }

            if (!parts[0].match(regexHeaderScheme)) {
                continue;
            }

            result = Buffer.from(parts[1], "base64").toString("utf-8");
        }
    }

    if (typeof result === "string") {
        const obj: any = {};
        const parts: string[] = result.split(":");
        obj.id = parts[0];
        obj.password = parts[1];
        result = obj;
    }

    return result;
};

/**
 * Decodes a single `application/x-www-form-urlencoded` key or value: `+` is form-encoding's space, and
 * `%XX` sequences are percent-encoded bytes. Falls back to the raw value on a malformed escape sequence
 * rather than throwing, so a client can't turn a parse edge case in `getRequestData()` into an unhandled
 * error.
 */
function decodeFormValue(value: string): string {
    try {
        return decodeURIComponent(value.replace(/\+/g, " "));
    } catch (err) {
        return value;
    }
}

/**
 * Attempts to decode the request for authentication request data. The auth request data may be in a header, a query
 * parameter or the request body itself. It may either be JSON encoded or form-data encoded. We want to return a
 * regular object.
 *
 * @param req The request to return auth request data for.
 * @param headerKey The name of a header to look for request data in. Set to an empty string to skip
 * the header search entirely — passing `undefined` has no effect, since that just triggers the
 * default value. Default is 'Authorization'.
 * @param headerScheme The header scheme to look for. Default is 'basic'.
 * @returns The found request data and its decoded payload object.
 */
export const getRequestData = function (
    req: HttpRequest,
    headerKey: string | undefined = "authorization",
    headerScheme: string = "basic",
): { data: any; payload: any } {
    let data: any = undefined;
    let payload: any = undefined;

    // The request body may have the form of JSON (`{ id: "...", password: "" }`) or form-data (`id=...&code=...`)
    if (typeof req.body === "object") {
        data = payload = req.body;
    } else if (typeof req.body === "string") {
        // First try to see if this is actually JSON
        try {
            payload = JSON.parse(req.body);
        } catch (err: any) {
            // The body is probably form-data. It'll be processed later
        }
        data = req.body;
    }

    // Check the headers. It's possible there is more than one header value defined. Loop through each of
    // them until we have verified auth request data.
    if (!data && headerKey && headerKey in req.headers) {
        const value: string | string[] | undefined = req.headers[headerKey];
        const headers: string[] = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];

        // Loop throught through the headers looking for a value with a matching scheme
        for (const header in headers) {
            const parts: string[] = headers[header].split(" ");
            if (parts.length !== 2) {
                continue;
            }

            const regexHeaderScheme: RegExp =
                headerSchemeRegExps.get(headerScheme) ?? new RegExp("^" + headerScheme + "$", "i");
            if (!headerSchemeRegExps.has(headerScheme)) {
                headerSchemeRegExps.set(headerScheme, regexHeaderScheme);
            }

            if (!parts[0].match(regexHeaderScheme)) {
                continue;
            }

            data = Buffer.from(parts[1], "base64").toString("utf-8");
        }
    }

    // A string body that already parsed as JSON above has a real payload object — don't clobber it
    // by re-parsing the same raw string as form-data/colon-delimited below.
    if (typeof data === "string" && typeof payload !== "object") {
        const obj: any = {};

        // The string value may be ':' delimited (e.g. Basic auth) or form-data encoded.
        // Detect which one it is and decode accordingly
        if (data.includes("&")) {
            const formParts: string[] = data.split("&");
            for (const part of formParts) {
                // Split on the *first* '=' only - a value containing its own '=' (e.g. base64-padded)
                // would otherwise be silently truncated by a naive `part.split("=")`. `+` is form-encoding's
                // space, and `%XX` sequences must be percent-decoded - without this, a value containing
                // '&'/'='/'+'/non-ASCII characters (e.g. a password) is silently mangled or truncated rather
                // than reconstructed, and the wrong (truncated) value is what actually gets rate-limited/
                // verified. Falls back to the raw value on a malformed escape rather than throwing, so a
                // client can't turn a parse edge case into an unhandled 500.
                const eqIndex = part.indexOf("=");
                const rawKey = eqIndex >= 0 ? part.slice(0, eqIndex) : part;
                const rawValue = eqIndex >= 0 ? part.slice(eqIndex + 1) : undefined;
                obj[decodeFormValue(rawKey)] = rawValue !== undefined ? decodeFormValue(rawValue) : undefined;
            }
        } else if (data.includes(":")) {
            // This is dirty making assumptions like the following. Should really do
            // something differently probably but I want to reduce the number of times
            // this gets decoded.
            const parts: string[] = data.split(":");
            obj.id = parts[0];
            obj.password = parts[1];
        }

        payload = obj;
    }

    return { data, payload };
};

export const isOTPResponse = function (response: any): boolean {
    return response.id && response.token;
};

export const isPasskeyResponse = function (response: any): boolean {
    if (
        typeof response.id !== "string" ||
        typeof response.response?.clientDataJSON !== "string" ||
        typeof response.response?.authenticatorData !== "string" ||
        typeof response.response?.signature !== "string"
    ) {
        return false;
    }

    return true;
};

/**
 * Determines if the given value has the shape of a WebAuthn `RegistrationResponseJSON`, as produced by
 * `navigator.credentials.create()` and submitted to finish a passkey registration ceremony.
 *
 * @param response The value to check.
 */
export const isPasskeyRegistrationResponse = function (response: any): boolean {
    if (
        typeof response?.id !== "string" ||
        typeof response.response?.clientDataJSON !== "string" ||
        typeof response.response?.attestationObject !== "string"
    ) {
        return false;
    }

    return true;
};

/**
 * Obfuscates the given contact and returns the obfuscated value.
 * @param contact The contact to obfuscate.
 */
export const obfuscateContact = function (contact: string, type: OTPContactType): string {
    let result: string = contact;

    switch (type) {
        case OTPContactType.EMAIL:
            result = result.replace(/^(.).*(.{2})(@)/, "$1***$2$3");
            break;
        case OTPContactType.SMS:
            result = result.replace(/.(?=.{4})/g, "*");
            break;
    }

    return result;
};

///////////////////////////////////////////////////////////////////////////////
// OTP
///////////////////////////////////////////////////////////////////////////////

/**
 * Generates and returns a new OTP token for authentication. This function stores relevant data for
 * validation of the OTP token in the request's session.
 * @param req The HTTP request to use for storing session data.
 * @returns The generated OTP token.
 */
export const generateOTP = async function (req: HttpRequest, requestData?: any): Promise<string> {
    if (!req.session) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    requestData = requestData ?? getRequestData(req).payload;

    const otplib = await importOTPLib();
    const secret = otplib.generateSecret();
    const token: string = await otplib.generate({ secret });

    // Store the OTP data in the session for later verification
    req.session.id = requestData.id;
    req.session.secret = secret;
    req.session.token = token;

    return token;
};

/**
 * Validates the provided token against the data stored in the request session.
 * @param token The OTP token to validate.
 * @param req The HTTP request with OTP session data.
 */
export const verifyOTP = async function (req: HttpRequest, payload?: any): Promise<boolean> {
    if (!req.session) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    payload = payload ?? getRequestData(req).payload;

    // The challenge is single-use regardless of outcome — cleared as soon as it's read, before
    // verification is even attempted, so a captured/replayed token can never be verified twice.
    const sessionId: any = req.session.id;
    const sessionSecret: any = req.session.secret;
    delete req.session.id;
    delete req.session.secret;
    delete req.session.token;

    if (!isOTPResponse(payload)) {
        throw new Error("Invalid authentication request.");
    }

    if (sessionId !== payload.id) {
        throw new Error("Invalid authentication request.");
    }

    const otplib = await importOTPLib();
    const result = await otplib.verify({
        secret: sessionSecret,
        token: payload.token,
    });
    return result.valid;
};

///////////////////////////////////////////////////////////////////////////////
// OAUTH
///////////////////////////////////////////////////////////////////////////////

/** RFC 7636 §4.1: a PKCE `code_verifier` must be 43-128 characters from the unreserved character set. */
export const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * Verifies a PKCE (RFC 7636) `code_verifier` presented at the token endpoint against the `code_challenge`
 * recorded at the authorization endpoint. For `S256`, hashes `verifier` with SHA-256 and compares the
 * base64url digest to `challenge`; for `plain`, compares the values directly.
 *
 * @param verifier The `code_verifier` presented at `/token`.
 * @param challenge The `code_challenge` recorded when the authorization code was issued.
 * @param method The `code_challenge_method` recorded alongside `challenge`.
 */
export const verifyPkce = function (verifier: string, challenge: string, method: "S256" | "plain"): boolean {
    if (!PKCE_VERIFIER_PATTERN.test(verifier)) {
        return false;
    }

    if (method === "plain") {
        return verifier === challenge;
    }

    const computed = crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
    return computed === challenge;
};

/**
 * Hashes an opaque, single-presentation secret (an authorization code or refresh token) for storage — SHA-256
 * hex, so the raw value is never persisted and a database read alone can never recover it.
 *
 * @param raw The raw opaque value to hash.
 */
export const hashOpaqueToken = function (raw: string): string {
    return crypto.createHash("sha256").update(raw, "utf8").digest("hex");
};

/**
 * Extracts the raw token from an `Authorization: Bearer <token>` header (RFC 6750 §2.1), or `undefined` if
 * the header is absent or uses a different scheme. Unlike `getBasicData()`, the value is returned as-is —
 * a bearer token is opaque to this function, not base64-encoded `id:password` credentials.
 *
 * @param req The request to extract the bearer token from.
 */
export const getBearerToken = function (req: HttpRequest): string | undefined {
    const value: string | string[] | undefined = req.headers["authorization"];
    const headers: string[] = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];

    for (const header of headers) {
        const parts = header.split(" ");
        if (parts.length === 2 && /^bearer$/i.test(parts[0])) {
            return parts[1];
        }
    }

    return undefined;
};

///////////////////////////////////////////////////////////////////////////////
// PASSWORD
///////////////////////////////////////////////////////////////////////////////

const PASSWORD_LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
const PASSWORD_UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PASSWORD_NUMERAL_CHARS = "0123456789";

/**
 * Generates a cryptographically random password that satisfies the given password requirements.
 * Used to provision a default account when no explicit password has been configured for it.
 *
 * @param config The password requirements the generated password must satisfy.
 * @returns A randomly generated password meeting every requirement enabled in `config`.
 */
export const generatePassword = function (config: PasswordConfig): string {
    const requiredCharSets: string[] = [];
    if (config.require_lowercase) {
        requiredCharSets.push(PASSWORD_LOWERCASE_CHARS);
    }
    if (config.require_uppercase) {
        requiredCharSets.push(PASSWORD_UPPERCASE_CHARS);
    }
    if (config.require_numeral) {
        requiredCharSets.push(PASSWORD_NUMERAL_CHARS);
    }
    if (config.require_special) {
        requiredCharSets.push(config.special_chars);
    }

    // A password still needs characters to draw from even if no category is required.
    const allChars: string = requiredCharSets.length > 0 ? requiredCharSets.join("") : PASSWORD_LOWERCASE_CHARS;
    const length: number = Math.max(config.recommended_length, config.min_length);

    // Guarantee at least one character from each required category first, then fill the remaining
    // length randomly from the combined pool so the guaranteed characters don't skew the distribution.
    const chars: string[] = requiredCharSets.map((set) => set[crypto.randomInt(set.length)]);
    while (chars.length < length) {
        chars.push(allChars[crypto.randomInt(allChars.length)]);
    }

    // Shuffle (Fisher-Yates) so the guaranteed category characters aren't always the leading ones.
    for (let i = chars.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join("");
};

///////////////////////////////////////////////////////////////////////////////
// RECOVERY CODES
///////////////////////////////////////////////////////////////////////////////

/** Crockford Base32 alphabet - excludes `I`/`L`/`O`/`U` to avoid visual ambiguity with `1`/`1`/`0`/`V`. */
const RECOVERY_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_LENGTH = 10;

/**
 * Generates a fixed batch of plaintext MFA recovery/backup codes (see `RecoveryCodesSecret`). Each code is
 * shown to the user exactly once, at creation time (see `BaseSecretRoute.validateRecoveryCodesCreate()`) -
 * only their hashes are ever persisted.
 */
export const generateRecoveryCodes = function (): string[] {
    const codes: string[] = [];
    for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
        let raw = "";
        for (let j = 0; j < RECOVERY_CODE_LENGTH; j++) {
            raw += RECOVERY_CODE_ALPHABET[crypto.randomInt(RECOVERY_CODE_ALPHABET.length)];
        }
        codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
    }
    return codes;
};

///////////////////////////////////////////////////////////////////////////////
// PASSKEY
///////////////////////////////////////////////////////////////////////////////

export const generatePasskeyChallenge = async function (
    config: PasskeyConfig,
    req: HttpRequest,
    allowCredentials?: any,
) {
    if (!req.session) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    const { generateAuthenticationOptions } = await importSimpleWebAuthn();
    const result = await generateAuthenticationOptions({
        rpID: config.rpID,
        allowCredentials,
        userVerification: config.userVerification,
        timeout: config.timeout,
    });

    // Store the challenge in the session so it can be verified
    req.session.challenge = result.challenge;

    return result;
};

/**
 * Coerces a stored credential public key back into a `Uint8Array`.
 *
 * `StoredPasskeyCredential.publicKey` is a `Uint8Array` when it's first produced by the
 * registration ceremony, but by the time it's read back here it's been round-tripped through
 * whatever the `Secret` datastore uses to persist `data` (e.g. TypeORM's `simple-json` column,
 * which serializes via `JSON.stringify`/`JSON.parse`). That round-trip doesn't preserve typed
 * arrays — a `Uint8Array` comes back as a plain object keyed by numeric index
 * (`{"0":1,"1":2,...}`). Passed as-is to `@simplewebauthn/server`, that plain object has no
 * `byteLength`, so its CBOR/COSE key decoder treats it as zero-length input and fails with an
 * opaque "No data" error. Reconstruct a real `Uint8Array` regardless of which shape it comes in
 * as, so verification always sees the actual key bytes.
 */
function toUint8Array(value: Uint8Array | ArrayLike<number>): Uint8Array {
    return value instanceof Uint8Array ? value : Uint8Array.from(Object.values(value));
}

export const verifyPasskeyChallenge = async function (
    credential: StoredPasskeyCredential,
    config: PasskeyConfig,
    expectedChallenge: string,
    payload: any,
): Promise<any> {
    const { verifyAuthenticationResponse } = await importSimpleWebAuthn();

    if (!Number.isFinite(credential.counter)) {
        throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Stored passkey credential has an invalid counter.");
    }

    return await verifyAuthenticationResponse({
        response: payload,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
            id: credential.id,
            counter: credential.counter,
            publicKey: toUint8Array(credential.publicKey),
            transports: credential.transports,
        },
        requireUserVerification: config.requireUserVerification ?? true,
    });
};

/**
 * Begins a registration ceremony: generates a set of `PublicKeyCredentialCreationOptions` and stores the
 * challenge in the session for later verification. The result is meant to be returned directly to the
 * client for use with `navigator.credentials.create()`.
 *
 * @param config The relying party configuration to use for this ceremony.
 * @param req The source HTTP request. Used to persist the generated challenge in the session.
 * @param user The user the new credential will be associated with.
 * @param excludeCredentials The user's already-registered credentials, if any, so that the authenticator
 * can avoid creating a duplicate credential for one it already holds.
 */
export const generatePasskeyRegistrationOptions = async function (
    config: PasskeyConfig,
    req: HttpRequest,
    user: { id: string; name: string; displayName?: string },
    excludeCredentials?: { id: string; transports?: PasskeyTransport[] }[],
): Promise<any> {
    if (!req.session) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    const { generateRegistrationOptions } = await importSimpleWebAuthn();
    const result = await generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpID,
        userName: user.name,
        userID: new TextEncoder().encode(user.id),
        userDisplayName: user.displayName,
        timeout: config.timeout,
        authenticatorSelection: {
            userVerification: config.userVerification ?? "preferred",
            authenticatorAttachment: config.authenticatorAttachment,
            residentKey: config.residentKey,
        },
        excludeCredentials,
    });

    // Store the challenge in the session so it can be verified once the ceremony finishes.
    req.session.challenge = result.challenge;

    return result;
};

/**
 * Finishes a registration ceremony: verifies the client-submitted attestation response against the
 * stored challenge and relying party configuration.
 *
 * @param config The relying party configuration to verify the response against.
 * @param expectedChallenge The challenge previously stored in the session by
 * `generatePasskeyRegistrationOptions()`.
 * @param payload The client-submitted `RegistrationResponseJSON`.
 */
export const verifyPasskeyRegistrationResponse = async function (
    config: PasskeyConfig,
    expectedChallenge: string,
    payload: any,
): Promise<any> {
    const { verifyRegistrationResponse } = await importSimpleWebAuthn();

    return await verifyRegistrationResponse({
        response: payload,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: config.requireUserVerification ?? true,
    });
};

///////////////////////////////////////////////////////////////////////////////
// TOTP
///////////////////////////////////////////////////////////////////////////////

const TOTP_ENCRYPTION_PREFIX = "enc:v1:";
const TOTP_ENCRYPTION_ALGORITHM = "aes-256-gcm";
const TOTP_ENCRYPTION_IV_LENGTH = 12;
const TOTP_ENCRYPTION_AUTH_TAG_LENGTH = 16;

/**
 * Decodes `key` (a 64-character hex string per `TOTPConfig.encryption_key`) into the 32-byte buffer
 * `aes-256-gcm` requires, throwing a deployment-misconfiguration error rather than silently encrypting/
 * decrypting with the wrong key length.
 */
function parseTOTPEncryptionKey(key: string): Buffer {
    const buf = Buffer.from(key, "hex");
    if (buf.length !== 32) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "`auth:totp:encryption_key` must be a 64-character hex string (32 bytes) for AES-256-GCM.",
        );
    }
    return buf;
}

/**
 * Encrypts a TOTP shared secret for storage, using AES-256-GCM with a fresh random IV per call. Stores the
 * result as `"enc:v1:" + base64(iv[12] + authTag[16] + ciphertext)`. A no-op (returns `secret` unchanged)
 * when `key` is unset, so leaving `auth:totp:encryption_key` unconfigured is exactly today's plaintext
 * behavior.
 *
 * @param secret The plaintext TOTP shared secret to encrypt.
 * @param key The 64-character hex encryption key (`TOTPConfig.encryption_key`). Omit to store as plaintext.
 */
export const encryptTOTPSecret = function (secret: string, key?: string): string {
    if (!key) {
        return secret;
    }

    const keyBuf = parseTOTPEncryptionKey(key);
    const iv = crypto.randomBytes(TOTP_ENCRYPTION_IV_LENGTH);
    const cipher = crypto.createCipheriv(TOTP_ENCRYPTION_ALGORITHM, keyBuf, iv);
    const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return TOTP_ENCRYPTION_PREFIX + Buffer.concat([iv, authTag, ciphertext]).toString("base64");
};

/**
 * Decrypts a TOTP shared secret previously encrypted by `encryptTOTPSecret()`. Anything lacking the
 * `enc:v1:` envelope prefix is treated as legacy (or never-encrypted) plaintext and returned unchanged -
 * this is what lets `auth:totp:encryption_key` be enabled without a forced migration of already-stored
 * secrets.
 *
 * @param secret The persisted `TOTPSecret.secret` value, encrypted or plaintext.
 * @param key The 64-character hex encryption key (`TOTPConfig.encryption_key`) that encrypted it.
 * @throws `ApiError` (500) if `secret` is encrypted but `key` is unset, or `key` is malformed.
 */
export const decryptTOTPSecret = function (secret: string, key?: string): string {
    if (!secret.startsWith(TOTP_ENCRYPTION_PREFIX)) {
        return secret;
    }
    if (!key) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This TOTP secret is encrypted but no `auth:totp:encryption_key` is configured.",
        );
    }

    const keyBuf = parseTOTPEncryptionKey(key);
    const raw = Buffer.from(secret.slice(TOTP_ENCRYPTION_PREFIX.length), "base64");
    const iv = raw.subarray(0, TOTP_ENCRYPTION_IV_LENGTH);
    const authTag = raw.subarray(
        TOTP_ENCRYPTION_IV_LENGTH,
        TOTP_ENCRYPTION_IV_LENGTH + TOTP_ENCRYPTION_AUTH_TAG_LENGTH,
    );
    const ciphertext = raw.subarray(TOTP_ENCRYPTION_IV_LENGTH + TOTP_ENCRYPTION_AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(TOTP_ENCRYPTION_ALGORITHM, keyBuf, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return plaintext.toString("utf8");
};

/**
 * Generates and returns a new OTP token for authentication. This function stores relevant data for
 * validation of the OTP token in the request's session.
 * @param req The HTTP request to use for storing session data.
 * @returns The generated OTP token.
 */
export const generateTOTP = async function (req: HttpRequest, requestData?: any): Promise<string> {
    if (!req.session) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    requestData = requestData ?? getRequestData(req).payload;

    const otplib = await importOTPLib();
    const secret = otplib.generateSecret();
    const token: string = await otplib.generate({ secret });

    // Store the OTP data in the session for later verification
    req.session.id = requestData.id;
    req.session.secret = secret;
    req.session.token = token;

    return token;
};

/**
 * Validates the provided token against the specified TOTP secret(s).
 *
 * Enforces replay protection: a token that matches at or before the secret's `lastTimeStep` is
 * rejected, so an intercepted request (proxy, malicious extension, server logs) can't be replayed
 * to authenticate a second time for as long as the code remains within its validity window. The
 * caller is responsible for persisting the returned `timeStep` back onto the matched secret (via
 * its `uid`, if supplied) after a successful verification.
 *
 * @param token The OTP token to validate.
 * @param secret The stored TOTP secret(s) to validate the token against.
 * @param encryptionKey The 64-character hex encryption key (`TOTPConfig.encryption_key`) to decrypt each
 * candidate's `secret` with before verifying, if it was encrypted at rest. Omit if secrets are stored as
 * plaintext (the default).
 * @returns The otplib verification result (plus the matched secret's `uid`, if any) if successful,
 * otherwise `undefined`.
 */
export const verifyTOTP = async function (
    token: string,
    secret: TOTPSecret | TOTPSecret[],
    encryptionKey?: string,
): Promise<any> {
    const otplib = await importOTPLib();

    // Check against all provided TOTP secrets. If at least one of the TOTP
    // secrets is valid then we return success.
    const secrets: TOTPSecret[] = Array.isArray(secret) ? secret : [secret];
    for (const secret of secrets) {
        const { uid, lastTimeStep, secret: rawSecret, ...otpOptions } = secret;

        // otplib throws (rather than returning `{valid: false}`) for a token that isn't exactly the
        // expected number of digits — a malformed/empty client-supplied token must fail cleanly like
        // any other wrong code, not surface as an unhandled error.
        const expectedDigits: number = otpOptions.digits ?? 6;
        if (typeof token !== "string" || !new RegExp(`^\\d{${expectedDigits}}$`).test(token)) {
            continue;
        }

        // A candidate that can't be decrypted under the current key (e.g. a stale secret left behind by a
        // key rotation that didn't re-encrypt every record) must not abort checking the caller's other
        // candidates - skip it exactly like a malformed token above, rather than letting the throw escape
        // and turn one bad secret into a hard failure for a user who has other, perfectly valid ones.
        let decryptedSecret: string;
        try {
            decryptedSecret = decryptTOTPSecret(rawSecret, encryptionKey);
        } catch (err) {
            continue;
        }

        const result = await otplib.verify({
            ...otpOptions,
            secret: decryptedSecret,
            token,
            afterTimeStep: lastTimeStep,
        });

        if (result.valid) {
            return { ...result, uid };
        }
    }

    return undefined;
};

/**
 * A fixed, non-secret TOTP secret used only to burn an equivalent amount of CPU time as a real
 * TOTP verification via `verifyDummyTOTP()`. Never derived from any real credential.
 */
export const DUMMY_TOTP_SECRET: TOTPSecret = {
    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};

/**
 * Performs a TOTP verification against a fixed dummy secret, discarding the result. Used to
 * equalize the response time of a "user/secret not found" path with a "secret found, code
 * checked" path so that an attacker can't enumerate valid accounts by measuring response latency.
 * @param token The value to verify against the dummy secret. Never actually a real code of anyone.
 */
export const verifyDummyTOTP = async function (token: string): Promise<void> {
    await verifyTOTP(token, DUMMY_TOTP_SECRET);
};

/**
 * Determines if the given value is usable as a TOTP secret: a Base32-encoded string decoding to at
 * least 128 bits, the minimum shared secret length mandated by RFC 4226 §4 (R6) (which RFC 6238
 * TOTP secrets must also satisfy, per RFC 6238 §5.1).
 *
 * @param secret The value to check.
 */
export const isValidTOTPSecret = async function (secret: any): Promise<boolean> {
    if (typeof secret !== "string" || secret.length === 0) {
        return false;
    }

    try {
        const { ScureBase32Plugin } = await importOTPLib();
        const decoded: Uint8Array = new ScureBase32Plugin().decode(secret);
        // RFC 4226 §4 (R6): the shared secret MUST be at least 128 bits (16 bytes).
        return decoded.length >= 16;
    } catch (err: any) {
        return false;
    }
};

/**
 * Generates an `otpauth://` provisioning URI for the given TOTP secret — the "Key URI Format"
 * convention (https://github.com/google/google-authenticator/wiki/Key-Uri-Format) that, while not
 * itself an RFC, is the de facto standard virtually every TOTP authenticator app (Google
 * Authenticator, Authy, 1Password, etc.) relies on to enroll a secret via QR code or manual entry.
 *
 * @param config The relying party configuration to generate the URI for.
 * @param label The account label to embed in the URI (typically a username or email).
 * @param secret The TOTP secret to encode into the URI.
 */
export const generateTOTPURI = async function (config: TOTPConfig, label: string, secret: TOTPSecret): Promise<string> {
    const { generateURI } = await importOTPLib();

    return generateURI({
        issuer: config.issuer,
        label,
        secret: secret.secret,
        algorithm: secret.algorithm ?? config.algorithm,
        digits: secret.digits ?? config.digits,
        period: secret.period ?? config.period,
    });
};

///////////////////////////////////////////////////////////////////////////////
// LIBRARY IMPORTS
///////////////////////////////////////////////////////////////////////////////

/**
 * Dynamically imports the optional peer dependency `argon2`, throwing a helpful
 * error if it is not installed.
 */
export const importArgon2 = async function (): Promise<any> {
    try {
        return await import("argon2");
    } catch (err: any) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This feature requires the optional peer dependency 'argon2'. Install it with: yarn add argon2",
        );
    }
};

/**
 * A precomputed Argon2id hash of a fixed, non-secret placeholder value. Never derived from any real
 * credential — used only to burn an equivalent amount of CPU time as a real password verification via
 * `verifyDummyPassword()`.
 */
export const DUMMY_ARGON2_HASH: string =
    "$argon2id$v=19$m=65536,t=3,p=4$VhOypn3oSSxvFgmOrlj1qA$sM5afO0NyaRoZ+0tTdE8EOt7XRG8hSGlLOX+035fQFI";

/**
 * Performs an Argon2 verification against a fixed dummy hash, discarding the result. Used to equalize the
 * response time of a "user not found" path with a "user found, password checked" path so that an attacker
 * can't enumerate valid usernames/emails by measuring response latency (a nonexistent user would otherwise
 * short-circuit before ever running the deliberately-slow Argon2 verify).
 * @param password The value to verify against the dummy hash. Never actually a real password of anyone.
 */
export const verifyDummyPassword = async function (password: string): Promise<void> {
    const argon = await importArgon2();
    await argon.verify(DUMMY_ARGON2_HASH, password);
};

/**
 * Dynamically imports the optional peer dependency `otplib`, throwing a helpful
 * error if it is not installed.
 */
export const importOTPLib = async function (): Promise<any> {
    try {
        return await import("otplib");
    } catch (err: any) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This feature requires the optional peer dependency 'otplib'. Install it with: yarn add otplib",
        );
    }
};

/**
 * Dynamically imports the optional peer dependency `@simplewebauthn/server`, throwing a helpful
 * error if it is not installed.
 */
export const importSimpleWebAuthn = async function (): Promise<any> {
    try {
        return await import("@simplewebauthn/server");
    } catch (err: any) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "This feature requires the optional peer dependency '@simplewebauthn/server'. Install it with: " +
                "yarn add @simplewebauthn/server",
        );
    }
};

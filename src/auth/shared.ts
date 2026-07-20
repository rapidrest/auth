////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { HttpRequest } from "@rapidrest/service-core";
import {
    OTPContactType,
    PasskeyConfig,
    PasskeyTransport,
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
                const parts: string[] = part.split("=");
                obj[parts[0]] = parts[1] ?? undefined;
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
        throw new Error(
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
        throw new Error(
            "This function requires session support. Configure the `session` config " +
                "block so the session middleware is registered.",
        );
    }

    payload = payload ?? getRequestData(req).payload;

    if (!isOTPResponse(payload)) {
        throw new Error("Invalid authentication request.");
    }

    if (req.session.id !== payload.id) {
        throw new Error("Invalid authentication request.");
    }

    const otplib = await importOTPLib();
    const result = await otplib.verify({
        secret: req.session.secret,
        token: payload.token,
    });
    return result.valid;
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
        throw new Error(
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

export const verifyPasskeyChallenge = async function (
    credential: StoredPasskeyCredential,
    config: PasskeyConfig,
    expectedChallenge: string,
    payload: any,
): Promise<any> {
    const { verifyAuthenticationResponse } = await importSimpleWebAuthn();

    if (!Number.isFinite(credential.counter)) {
        throw new Error("Stored passkey credential has an invalid counter.");
    }

    return await verifyAuthenticationResponse({
        response: payload,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
            id: credential.id,
            counter: credential.counter,
            publicKey: credential.publicKey,
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
        throw new Error(
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

/**
 * Generates and returns a new OTP token for authentication. This function stores relevant data for
 * validation of the OTP token in the request's session.
 * @param req The HTTP request to use for storing session data.
 * @returns The generated OTP token.
 */
export const generateTOTP = async function (req: HttpRequest, requestData?: any): Promise<string> {
    if (!req.session) {
        throw new Error(
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
 * Validates the provided token against the specified TOTP secret.
 * @param token The OTP token to validate.
 * @param secret The stored TOTP secret to validate the token against.
 * @returns The otplib verification result if successful, otherwise `undefined`.
 */
export const verifyTOTP = async function (token: string, secret: TOTPSecret | TOTPSecret[]): Promise<any> {
    const otplib = await importOTPLib();

    // Check against all provided TOTP secrets. If at least one of the TOTP
    // secrets is valid then we return success.
    const secrets: TOTPSecret[] = Array.isArray(secret) ? secret : [secret];
    for (const secret of secrets) {
        const result = await otplib.verify({
            ...secret,
            token,
        });

        if (result.valid) {
            return result;
        }
    }

    return undefined;
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
        throw new Error(
            "This feature requires the optional peer dependency 'argon2'. Install it with: yarn add argon2",
        );
    }
};

/**
 * Dynamically imports the optional peer dependency `otplib`, throwing a helpful
 * error if it is not installed.
 */
export const importOTPLib = async function (): Promise<any> {
    try {
        return await import("otplib");
    } catch (err: any) {
        throw new Error(
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
        throw new Error(
            "This feature requires the optional peer dependency '@simplewebauthn/server'. Install it with: " +
                "yarn add @simplewebauthn/server",
        );
    }
};

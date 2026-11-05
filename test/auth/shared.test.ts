///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for the shared.ts auth helpers. otplib is real (it's already exercised this
// way throughout the auth test suites); @simplewebauthn/server is mocked since its own cryptographic
// correctness is that library's tested responsibility, not ours.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
    generateRegistrationOptions: vi.fn(),
    verifyRegistrationResponse: vi.fn(),
}));

import { Binary, deserialize, serialize } from "bson";
import { ApiError } from "@rapidrest/core";
import type { HttpRequest } from "@rapidrest/service-core";
import * as otplib from "otplib";
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { FakeRedisClient } from "../helpers/FakeRedis.js";
import { OTPCounters } from "../../src/auth/OTPCounters.js";
import {
    CLIENT_ARGON2_PARAMS,
    clientRateLimitKey,
    counterKeyPart,
    DEFAULT_OTP_ALPHABET,
    DEFAULT_OTP_LENGTH,
    DEFAULT_OTP_ISSUE_LIMIT,
    DEFAULT_OTP_ISSUE_TOTAL_LIMIT,
    DEFAULT_OTP_MAX_ATTEMPTS,
    DEFAULT_OTP_USER_LIMIT,
    DEFAULT_OTP_USER_TOTAL_LIMIT,
    DEFAULT_OTP_VERIFY_LIMIT,
    DEFAULT_OTP_VERIFY_TOTAL_LIMIT,
    DUMMY_ARGON2_HASH,
    DUMMY_TOTP_SECRET,
    decryptTOTPSecret,
    deriveClientSalt,
    encryptTOTPSecret,
    enforceOTPIssueLimit,
    generateOTP,
    generatePasskeyChallenge,
    generatePasskeyRegistrationOptions,
    generatePassword,
    generateTOTP,
    generateTOTPURI,
    getBasicData,
    getBearerToken,
    getRequestData,
    isClientHashedFormat,
    isOTPChallengePending,
    isOTPResponse,
    isPasskeyRegistrationResponse,
    isPasskeyResponse,
    isValidTOTPSecret,
    isWhatsAppConfigured,
    normalizePasswordSubmission,
    obfuscateContact,
    parseWhatsAppMethodId,
    resolveOTPConfig,
    toWhatsAppMethodId,
    toUint8Array,
    touchSecretLastUsedAt,
    verifyDummyPassword,
    verifyDummyTOTP,
    verifyOTP,
    type OTPContext,
    verifyPasskeyChallenge,
    verifyPasskeyRegistrationResponse,
    verifyTOTP,
    WeakClientHashError,
} from "../../src/auth/shared.js";
import {
    OTPConfig,
    OTPContactType,
    OTPPurpose,
    PasskeyConfig,
    PasswordConfig,
    StoredPasskeyCredential,
    TOTPConfig,
    TOTPSecret,
} from "../../src/auth/types.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as any;
const mockVerifyAuthenticationResponse = verifyAuthenticationResponse as any;
const mockGenerateRegistrationOptions = generateRegistrationOptions as any;
const mockVerifyRegistrationResponse = verifyRegistrationResponse as any;

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "GET",
        path: "/auth",
        url: "/auth",
        headers: {},
        params: {},
        query: {},
        body: undefined,
        cookies: {},
        signedCookies: {},
        session: {},
        socket: {},
        ...overrides,
    };
}

function makePasskeyConfig(overrides: Partial<PasskeyConfig> = {}): PasskeyConfig {
    return {
        rpName: "Test RP",
        rpID: "example.com",
        origin: "https://example.com",
        ...overrides,
    };
}

beforeEach(() => {
    mockGenerateAuthenticationOptions.mockReset();
    mockVerifyAuthenticationResponse.mockReset();
    mockGenerateRegistrationOptions.mockReset();
    mockVerifyRegistrationResponse.mockReset();
});

describe("getBasicData", () => {
    it("Returns undefined when the header key is not present.", () => {
        const req = makeReq({ headers: {} });
        expect(getBasicData(req)).toBeUndefined();
    });

    it("Returns undefined when the header key is present but its value is nullish.", () => {
        const req = makeReq({ headers: { authorization: undefined } });
        expect(getBasicData(req)).toBeUndefined();
    });

    it("Parses a single matching header into {id, password}.", () => {
        const req = makeReq({ headers: { authorization: `basic ${Buffer.from("user1:pass1").toString("base64")}` } });
        expect(getBasicData(req)).toEqual({ id: "user1", password: "pass1" });
    });

    it("Finds the matching header among an array of header values.", () => {
        const req = makeReq({
            headers: {
                authorization: [
                    `bearer ${Buffer.from("irrelevant").toString("base64")}`,
                    `basic ${Buffer.from("user1:pass1").toString("base64")}`,
                ],
            },
        });
        expect(getBasicData(req)).toEqual({ id: "user1", password: "pass1" });
    });

    it("Skips a malformed header value (not exactly scheme + credentials).", () => {
        const req = makeReq({ headers: { authorization: "malformed-no-space-here" } });
        expect(getBasicData(req)).toBeUndefined();
    });

    it("Skips a header whose scheme does not match.", () => {
        const req = makeReq({ headers: { authorization: `bearer ${Buffer.from("user1:pass1").toString("base64")}` } });
        expect(getBasicData(req)).toBeUndefined();
    });

    it("Supports a custom headerKey/headerScheme.", () => {
        const req = makeReq({ headers: { "x-auth": `custom ${Buffer.from("user1:pass1").toString("base64")}` } });
        expect(getBasicData(req, "x-auth", "custom")).toEqual({ id: "user1", password: "pass1" });
    });
});

describe("getBearerToken", () => {
    it("Returns undefined when the authorization header is not present.", () => {
        const req = makeReq({ headers: {} });
        expect(getBearerToken(req)).toBeUndefined();
    });

    it("Returns undefined when the authorization header is present but its value is nullish.", () => {
        const req = makeReq({ headers: { authorization: undefined } });
        expect(getBearerToken(req)).toBeUndefined();
    });

    it("Extracts the raw token from a single matching header.", () => {
        const req = makeReq({ headers: { authorization: "Bearer abc123.def456.ghi789" } });
        expect(getBearerToken(req)).toBe("abc123.def456.ghi789");
    });

    it("Is case-insensitive on the scheme name.", () => {
        const req = makeReq({ headers: { authorization: "bearer abc123" } });
        expect(getBearerToken(req)).toBe("abc123");
    });

    it("Finds the matching header among an array of header values.", () => {
        const req = makeReq({
            headers: {
                authorization: [`basic ${Buffer.from("user1:pass1").toString("base64")}`, "Bearer abc123"],
            },
        });
        expect(getBearerToken(req)).toBe("abc123");
    });

    it("Skips a malformed header value (not exactly scheme + token).", () => {
        const req = makeReq({ headers: { authorization: "malformed-no-space-here" } });
        expect(getBearerToken(req)).toBeUndefined();
    });

    it("Skips a header whose scheme is not bearer.", () => {
        const req = makeReq({ headers: { authorization: `basic ${Buffer.from("user1:pass1").toString("base64")}` } });
        expect(getBearerToken(req)).toBeUndefined();
    });
});

describe("getRequestData", () => {
    it("Uses the request body directly when it is an object.", () => {
        const req = makeReq({ body: { id: "user1", password: "pass1" } });
        const { data, payload } = getRequestData(req);
        expect(data).toEqual({ id: "user1", password: "pass1" });
        expect(payload).toEqual({ id: "user1", password: "pass1" });
    });

    it("Parses a JSON string body.", () => {
        const req = makeReq({ body: JSON.stringify({ id: "user1", token: "123456" }) });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user1", token: "123456" });
    });

    it("Falls back to form-data parsing when the body is a non-JSON string.", () => {
        const req = makeReq({ body: "id=user1&token=123456" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user1", token: "123456" });
    });

    // Regression: a naive `part.split("=")`/no-decode form-data parser silently truncated any value
    // containing its own '=' (e.g. base64 padding) at the first occurrence, left '+' as a literal plus
    // instead of the space it represents in form-encoding, and never percent-decoded at all - so the
    // *wrong* (mangled/truncated) value is what actually got rate-limited/verified against.
    it("URL-decodes form-data keys/values, preserving '=' inside a value (only the first '=' is a delimiter).", () => {
        const req = makeReq({ body: "id=user%201&password=a%3Db%2Bc" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user 1", password: "a=b+c" });
    });

    it("Decodes '+' as a space in form-data values.", () => {
        const req = makeReq({ body: "id=hello+world&token=123456" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "hello world", token: "123456" });
    });

    it("Falls back to the raw value (rather than throwing) for a malformed percent-escape in form-data.", () => {
        const req = makeReq({ body: "id=100%25off&token=123456" });
        const { payload: decoded } = getRequestData(req);
        expect(decoded).toEqual({ id: "100%off", token: "123456" });

        const req2 = makeReq({ body: "id=broken%escape&token=123456" });
        expect(() => getRequestData(req2)).not.toThrow();
        expect(getRequestData(req2).payload).toEqual({ id: "broken%escape", token: "123456" });
    });

    it("Falls back to colon parsing when the non-JSON string body has no '&'.", () => {
        const req = makeReq({ body: "user1:pass1" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user1", password: "pass1" });
    });

    it("Returns an empty payload object for a non-JSON string body with neither '&' nor ':'.", () => {
        const req = makeReq({ body: "justastring" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({});
    });

    it("Reads from the header when there is no body.", () => {
        const req = makeReq({ headers: { authorization: `basic ${Buffer.from("user1:pass1").toString("base64")}` } });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user1", password: "pass1" });
    });

    it("Finds the matching header among an array of header values.", () => {
        const req = makeReq({
            headers: {
                authorization: [
                    `bearer ${Buffer.from("irrelevant").toString("base64")}`,
                    `basic ${Buffer.from("id=user1&token=123456").toString("base64")}`,
                ],
            },
        });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ id: "user1", token: "123456" });
    });

    it("Skips a malformed header value.", () => {
        const req = makeReq({ headers: { authorization: "malformed-no-space" } });
        const { payload } = getRequestData(req);
        expect(payload).toBeUndefined();
    });

    it("Finds no data when the header key is present but its value is nullish.", () => {
        const req = makeReq({ headers: { authorization: undefined } });
        const { data, payload } = getRequestData(req);
        expect(data).toBeUndefined();
        expect(payload).toBeUndefined();
    });

    it("Treats a form-data key with no '=value' part as undefined.", () => {
        const req = makeReq({ body: "flag&id=user1" });
        const { payload } = getRequestData(req);
        expect(payload).toEqual({ flag: undefined, id: "user1" });
    });

    it("Skips a header whose scheme does not match.", () => {
        const req = makeReq({ headers: { authorization: `bearer ${Buffer.from("user1:pass1").toString("base64")}` } });
        const { payload } = getRequestData(req);
        expect(payload).toBeUndefined();
    });

    it("Skips the header search entirely when headerKey is an empty string.", () => {
        const req = makeReq({ headers: { authorization: `basic ${Buffer.from("user1:pass1").toString("base64")}` } });
        const { data, payload } = getRequestData(req, "");
        expect(data).toBeUndefined();
        expect(payload).toBeUndefined();
    });

    it("Compiles and caches the scheme regex on first use of a not-yet-seen headerScheme.", () => {
        // Uses a scheme unique to this test so the module-level regex cache is genuinely empty for
        // it, regardless of what earlier tests in this file (or getBasicData's own copy of the same
        // cache) have already warmed up.
        const req = makeReq({
            headers: { authorization: `never-before-seen-scheme ${Buffer.from("user1:pass1").toString("base64")}` },
        });
        const { payload } = getRequestData(req, "authorization", "never-before-seen-scheme");
        expect(payload).toEqual({ id: "user1", password: "pass1" });
    });
});

describe("isOTPResponse", () => {
    it("Returns true when both id and token are present.", () => {
        expect(isOTPResponse({ id: "user1", token: "123456" })).toBeTruthy();
    });

    it("Returns false when token is missing.", () => {
        expect(isOTPResponse({ id: "user1" })).toBeFalsy();
    });
});

describe("isPasskeyResponse", () => {
    function makeAssertionBody(overrides: any = {}) {
        return {
            id: "cred-id-1",
            rawId: "cred-id-1",
            response: {
                clientDataJSON: "clientDataJSON-base64",
                authenticatorData: "authenticatorData-base64",
                signature: "signature-base64",
            },
            type: "public-key",
            clientExtensionResults: {},
            ...overrides,
        };
    }

    it("Returns true for a well-formed assertion response.", () => {
        expect(isPasskeyResponse(makeAssertionBody())).toBe(true);
    });

    it("Returns false when id is not a string.", () => {
        expect(isPasskeyResponse(makeAssertionBody({ id: 123 }))).toBe(false);
    });

    it("Returns false when clientDataJSON is missing.", () => {
        expect(isPasskeyResponse(makeAssertionBody({ response: { authenticatorData: "x", signature: "y" } }))).toBe(
            false,
        );
    });

    it("Returns false when authenticatorData is missing.", () => {
        expect(isPasskeyResponse(makeAssertionBody({ response: { clientDataJSON: "x", signature: "y" } }))).toBe(false);
    });

    it("Returns false when signature is missing.", () => {
        expect(
            isPasskeyResponse(makeAssertionBody({ response: { clientDataJSON: "x", authenticatorData: "y" } })),
        ).toBe(false);
    });
});

describe("isPasskeyRegistrationResponse", () => {
    function makeRegistrationBody(overrides: any = {}) {
        return {
            id: "cred-id-1",
            rawId: "cred-id-1",
            response: {
                clientDataJSON: "clientDataJSON-base64",
                attestationObject: "attestationObject-base64",
            },
            type: "public-key",
            clientExtensionResults: {},
            ...overrides,
        };
    }

    it("Returns true for a well-formed registration response.", () => {
        expect(isPasskeyRegistrationResponse(makeRegistrationBody())).toBe(true);
    });

    it("Returns false when the response is nullish.", () => {
        expect(isPasskeyRegistrationResponse(undefined)).toBe(false);
    });

    it("Returns false when id is not a string.", () => {
        expect(isPasskeyRegistrationResponse(makeRegistrationBody({ id: 123 }))).toBe(false);
    });

    it("Returns false when clientDataJSON is missing.", () => {
        expect(isPasskeyRegistrationResponse(makeRegistrationBody({ response: { attestationObject: "x" } }))).toBe(
            false,
        );
    });

    it("Returns false when attestationObject is missing.", () => {
        expect(isPasskeyRegistrationResponse(makeRegistrationBody({ response: { clientDataJSON: "x" } }))).toBe(false);
    });
});

describe("obfuscateContact", () => {
    it("Obfuscates an email address.", () => {
        expect(obfuscateContact("john.smith@gmail.com", OTPContactType.EMAIL)).toBe("j***th@gmail.com");
    });

    it("Obfuscates a phone number.", () => {
        expect(obfuscateContact("8188675309", OTPContactType.SMS)).toBe("******5309");
    });

    it("Obfuscates a WhatsApp number like an SMS one.", () => {
        expect(obfuscateContact("8188675309", OTPContactType.WHATSAPP)).toBe("******5309");
    });

    it("Returns the contact unchanged for an unrecognized type.", () => {
        expect(obfuscateContact("some-value", "bogus" as OTPContactType)).toBe("some-value");
    });
});

describe("isWhatsAppConfigured", () => {
    it("Is false when there is no messaging utils.", async () => {
        expect(await isWhatsAppConfigured(undefined)).toBe(false);
    });

    it("Uses the isWhatsAppConfigured() hook when present, awaiting an async result.", async () => {
        expect(await isWhatsAppConfigured({ isWhatsAppConfigured: () => true } as any)).toBe(true);
        expect(await isWhatsAppConfigured({ isWhatsAppConfigured: async () => true } as any)).toBe(true);
        expect(await isWhatsAppConfigured({ isWhatsAppConfigured: () => false } as any)).toBe(false);
        expect(await isWhatsAppConfigured({ isWhatsAppConfigured: async () => false } as any)).toBe(false);
    });

    it("Calls the hook on the messaging utils itself and re-checks it on every call (runtime changes are seen).", async () => {
        let configured = false;
        const messagingUtils: any = {
            isWhatsAppConfigured() {
                return this === messagingUtils && configured;
            },
        };

        expect(await isWhatsAppConfigured(messagingUtils)).toBe(false);
        configured = true;
        expect(await isWhatsAppConfigured(messagingUtils)).toBe(true);
    });

    it("Treats a hook's answer as authoritative over core's own whatsapp field.", async () => {
        const hookFalse: any = { isWhatsAppConfigured: () => false, whatsapp: { accessToken: "t" } };
        const hookTrue: any = { isWhatsAppConfigured: () => true };

        expect(await isWhatsAppConfigured(hookFalse)).toBe(false);
        expect(await isWhatsAppConfigured(hookTrue)).toBe(true);
    });

    it("Treats a hook that throws or rejects as not configured.", async () => {
        const throws: any = {
            isWhatsAppConfigured: () => {
                throw new Error("boom");
            },
        };
        const rejects: any = { isWhatsAppConfigured: () => Promise.reject(new Error("boom")) };

        expect(await isWhatsAppConfigured(throws)).toBe(false);
        expect(await isWhatsAppConfigured(rejects)).toBe(false);
    });

    it("Falls back to core's private whatsapp field when there is no hook.", async () => {
        expect(await isWhatsAppConfigured({ whatsapp: { accessToken: "t", phoneNumberId: "1" } } as any)).toBe(true);
        expect(await isWhatsAppConfigured({ whatsapp: undefined } as any)).toBe(false);
        expect(await isWhatsAppConfigured({} as any)).toBe(false);
    });
});

describe("WhatsApp method ids", () => {
    it("Derives a distinct id from the alias uid.", () => {
        expect(toWhatsAppMethodId("alias-1")).toBe("alias-1:whatsapp");
        expect(toWhatsAppMethodId("alias-1")).not.toBe("alias-1");
    });

    it("Round-trips through parseWhatsAppMethodId().", () => {
        expect(parseWhatsAppMethodId(toWhatsAppMethodId("alias-1"))).toBe("alias-1");
    });

    it("Returns undefined for an id that is not a WhatsApp method id, including the bare suffix.", () => {
        expect(parseWhatsAppMethodId("alias-1")).toBeUndefined();
        expect(parseWhatsAppMethodId(":whatsapp")).toBeUndefined();
        expect(parseWhatsAppMethodId("")).toBeUndefined();
    });
});

describe("OTP helpers", () => {
    const START = new Date("2026-11-05T12:00:00.000Z").getTime();

    /** The helpers under test, defaulting to the `login` purpose and no rate limiter. */
    const gen = (req: HttpRequest, data?: any, config?: OTPConfig, purpose: OTPPurpose = "login") =>
        generateOTP(req, data, config, purpose);
    const ver = (req: HttpRequest, payload?: any, config?: OTPConfig, purpose: OTPPurpose = "login", ctx?: OTPContext) =>
        verifyOTP(req, payload, config, purpose, ctx);

    /** Returns a code of the same length that differs from `code` in its first character. */
    const wrongCode = (code: string): string => (code[0] === "2" ? "3" : "2") + code.slice(1);

    beforeEach(() => {
        vi.useFakeTimers({ toFake: ["Date"] });
        vi.setSystemTime(START);
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe("generateOTP", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            // Regression: a deployment misconfiguration, not a client-caused auth failure - must surface
            // as a distinguishable 500, not get flattened into a generic 401.
            await expect(gen(req)).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/session support/),
            });
        });

        it("Derives requestData from the request itself when not provided.", async () => {
            const req = makeReq({ body: { id: "contact-1" } });
            await gen(req);
            expect((req.session as any).otp.id).toBe("contact-1");
        });

        it("Issues a 6 character upper-case code from the unambiguous alphabet.", async () => {
            const seen = new Set<string>();
            for (let i = 0; i < 3000; i++) {
                const code = await gen(makeReq(), { id: "contact-1" });
                expect(code).toMatch(/^[2-9A-HJKMNP-Z]{6}$/);
                for (const ch of code) {
                    seen.add(ch);
                }
            }
            // Never any of the look-alike characters, and every character of the alphabet does get used.
            for (const ch of "01ILO") {
                expect(seen.has(ch)).toBe(false);
            }
            expect(DEFAULT_OTP_ALPHABET).toHaveLength(31);
            expect([...seen].sort().join("")).toBe([...DEFAULT_OTP_ALPHABET].sort().join(""));
            expect(DEFAULT_OTP_LENGTH).toBe(6);
        });

        it("Honors a configured length and alphabet.", async () => {
            const code = await gen(makeReq(), { id: "c" }, { length: 10, alphabet: "abcd" });
            expect(code).toMatch(/^[ABCD]{10}$/);
        });

        it("Rejects an invalid configuration.", async () => {
            await expect(gen(makeReq(), { id: "c" }, { alphabet: "a" })).rejects.toThrow(/alphabet/);
            await expect(gen(makeReq(), { id: "c" }, { alphabet: "aAaA" })).rejects.toThrow(/alphabet/);
            await expect(gen(makeReq(), { id: "c" }, { alphabet: "ab-c" })).rejects.toThrow(/alphabet/);
            await expect(gen(makeReq(), { id: "c" }, { length: 3 })).rejects.toThrow(/length/);
            await expect(gen(makeReq(), { id: "c" }, { length: 4.5 })).rejects.toThrow(/length/);
            await expect(gen(makeReq(), { id: "c" }, { maxAttempts: 0 })).rejects.toThrow(/maxAttempts/);
        });

        it("Requires a valid purpose.", async () => {
            await expect(generateOTP(makeReq(), { id: "c" }, undefined, undefined as any)).rejects.toThrow(/purpose/);
            await expect(generateOTP(makeReq(), { id: "c" }, undefined, "admin" as any)).rejects.toThrow(/purpose/);
        });

        it("Records the purpose in the challenge.", async () => {
            for (const purpose of ["login", "mfa", "elevate", "register", "contact"] as OTPPurpose[]) {
                const req = makeReq();
                await gen(req, { id: "c" }, undefined, purpose);
                expect((req.session as any).otp.purpose).toBe(purpose);
            }
        });

        it("Stores only a salted hash, the issue time and an attempt counter - never the code.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "contact-1" });
            const session = req.session as any;

            expect(Object.keys(session)).toEqual(["otp"]);
            expect(Object.keys(session.otp).sort()).toEqual(["attempts", "hash", "id", "issuedAt", "purpose", "salt"]);
            expect(session.otp).toMatchObject({ id: "contact-1", purpose: "login", attempts: 0, issuedAt: START });
            expect(JSON.stringify(session)).not.toContain(code);
            expect(session.token).toBeUndefined();
            expect(session.secret).toBeUndefined();
        });

        it("Records the user the code was issued for, when one is given.", async () => {
            const req = makeReq();
            await generateOTP(req, { id: "contact-1" }, undefined, "login", "user-1");
            expect((req.session as any).otp.userUid).toBe("user-1");
            await generateOTP(req, { id: "contact-1" }, undefined, "login");
            expect("userUid" in (req.session as any).otp).toBe(false);
        });

        it("Rejects an id that is missing, not a string, empty or over 256 characters.", async () => {
            for (const id of [undefined, 5, {}, "", "x".repeat(257)]) {
                await expect(gen(makeReq(), { id })).rejects.toThrow(/Invalid authentication request/);
            }
            await expect(gen(makeReq(), { id: "x".repeat(256) })).resolves.toEqual(expect.any(String));
        });

        it("Refuses to verify an id that is not a bounded string, whatever challenge is pending.", async () => {
            const req = makeReq();
            await gen(req, { id: "c" });
            for (const id of ["x".repeat(257), { a: 1 }, 5]) {
                await expect(ver(req, { id, token: "ABC234" })).rejects.toThrow(/Invalid authentication request/);
            }
            expect(isOTPChallengePending(req)).toBe(true);
        });

        it("Uses a different salt (and hash) for every challenge, and replaces a pending one.", async () => {
            const req = makeReq();
            await gen(req, { id: "contact-1" });
            const first = { ...(req.session as any).otp };
            await gen(req, { id: "contact-1" });
            expect((req.session as any).otp.salt).not.toBe(first.salt);
            expect((req.session as any).otp.hash).not.toBe(first.hash);
        });
    });

    describe("verifyOTP", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            await expect(ver(req, { id: "c", token: "ABC234" })).rejects.toThrow(/session support/);
        });

        it("Derives payload from the request itself when not provided.", async () => {
            const req = makeReq({ body: { id: "c" } });
            const code = await gen(req);
            req.body.token = code;
            expect(await ver(req)).toBe(true);
        });

        it("Throws when the payload is not a valid OTP response shape.", async () => {
            const req = makeReq();
            await gen(req, { id: "c" });
            await expect(ver(req, { id: "c" })).rejects.toThrow(/Invalid authentication request/);
        });

        it("Throws when no challenge is pending, or the stored challenge is malformed.", async () => {
            await expect(ver(makeReq(), { id: "c", token: "ABC234" })).rejects.toThrow(
                /Invalid authentication request/,
            );
            await expect(
                ver(makeReq({ session: { otp: { id: "c", hash: 1, salt: "00" } } }), { id: "c", token: "ABC234" }),
            ).rejects.toThrow(/Invalid authentication request/);
            await expect(
                ver(makeReq({ session: { otp: { id: "c", hash: "00", salt: 1 } } }), { id: "c", token: "ABC234" }),
            ).rejects.toThrow(/Invalid authentication request/);
        });

        it("Throws and consumes the challenge when the id does not match.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            await expect(ver(req, { id: "other", token: code })).rejects.toThrow(
                /Invalid authentication request/,
            );
            expect(isOTPChallengePending(req)).toBe(false);
            // The right id and code no longer work either.
            await expect(ver(req, { id: "c", token: code })).rejects.toThrow(/Invalid authentication request/);
        });

        it("Accepts the code regardless of case, surrounding whitespace, and internal spaces or hyphens.", async () => {
            const variants = [
                (c: string) => c,
                (c: string) => c.toLowerCase(),
                (c: string) => `  ${c.toLowerCase()}\n`,
                (c: string) => `${c.slice(0, 3)}-${c.slice(3)}`,
                (c: string) => `${c.slice(0, 3).toLowerCase()} ${c.slice(3)}`,
            ];
            for (const variant of variants) {
                const req = makeReq();
                const code = await gen(req, { id: "c" });
                expect(await ver(req, { id: "c", token: variant(code) })).toBe(true);
            }
        });

        it("Returns false for a wrong code, and for a token that is not a string.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            expect(await ver(req, { id: "c", token: wrongCode(code) })).toBe(false);
            expect(await ver(req, { id: "c", token: 234567 })).toBe(false);
            expect(await ver(req, { id: "c", token: "  - " })).toBe(false);
            expect((req.session as any).otp.attempts).toBe(3);
        });

        it.each([
            ["31 seconds", 31_000],
            ["5 minutes", 5 * 60_000],
            ["just under the TTL", 600_000 - 1],
            ["exactly the TTL", 600_000],
        ])("Still accepts the code after %s.", async (_name, elapsed) => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            vi.setSystemTime(START + elapsed);
            expect(await ver(req, { id: "c", token: code })).toBe(true);
        });

        it("Rejects the code once the TTL has passed, and consumes it.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            vi.setSystemTime(START + 600_001);
            expect(await ver(req, { id: "c", token: code })).toBe(false);
            expect(isOTPChallengePending(req)).toBe(false);
        });

        it("Honors a configured TTL, given as seconds or as a duration string.", async () => {
            for (const ttl of [60, "1m"]) {
                const req = makeReq();
                const code = await gen(req, { id: "c" }, { ttl });
                vi.setSystemTime(START + 59_000);
                expect(await ver(req, { id: "c", token: code }, { ttl })).toBe(true);

                vi.setSystemTime(START);
                const late = makeReq();
                const lateCode = await gen(late, { id: "c" }, { ttl });
                vi.setSystemTime(START + 61_000);
                expect(await ver(late, { id: "c", token: lateCode }, { ttl })).toBe(false);
                vi.setSystemTime(START);
            }
        });

        it("Rejects a TTL that can't be parsed, is not positive or exceeds an hour.", async () => {
            for (const ttl of ["soon", 0, "0s", -5, 3601, "2h"]) {
                expect(() => resolveOTPConfig({ ttl })).toThrow(/ttl/);
            }
            expect(resolveOTPConfig({ ttl: 3600 }).ttl).toBe(3600);
            expect(resolveOTPConfig({ ttl: "1h" }).ttl).toBe(3600);
        });

        it("Tolerates the default number of wrong codes, then still accepts the right one.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            for (let i = 0; i < DEFAULT_OTP_MAX_ATTEMPTS - 1; i++) {
                expect(await ver(req, { id: "c", token: wrongCode(code) })).toBe(false);
            }
            expect(isOTPChallengePending(req)).toBe(true);
            expect(await ver(req, { id: "c", token: code })).toBe(true);
        });

        it("Invalidates the challenge after the maximum wrong codes, so even the right code is rejected.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            for (let i = 0; i < DEFAULT_OTP_MAX_ATTEMPTS; i++) {
                expect(await ver(req, { id: "c", token: wrongCode(code) })).toBe(false);
            }
            expect(isOTPChallengePending(req)).toBe(false);
            await expect(ver(req, { id: "c", token: code })).rejects.toThrow(/Invalid authentication request/);
        });

        it("Honors a configured maximum number of attempts.", async () => {
            const req = makeReq();
            const config = { maxAttempts: 2 };
            const code = await gen(req, { id: "c" }, config);
            expect(await ver(req, { id: "c", token: wrongCode(code) }, config)).toBe(false);
            expect(await ver(req, { id: "c", token: wrongCode(code) }, config)).toBe(false);
            await expect(ver(req, { id: "c", token: code }, config)).rejects.toThrow(
                /Invalid authentication request/,
            );
        });

        it("Rejects a challenge that is already out of attempts under a stricter configuration.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            (req.session as any).otp.attempts = 3;
            expect(await ver(req, { id: "c", token: code }, { maxAttempts: 3 })).toBe(false);
            expect(isOTPChallengePending(req)).toBe(false);
        });

        it("Is single-use: the code cannot be verified a second time after it succeeds.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            expect(await ver(req, { id: "c", token: code })).toBe(true);
            expect(isOTPChallengePending(req)).toBe(false);
            await expect(ver(req, { id: "c", token: code })).rejects.toThrow(/Invalid authentication request/);
        });

        it("Leaves no code, hash or challenge behind once consumed.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            await ver(req, { id: "c", token: code });
            expect(JSON.stringify(req.session)).not.toContain(code);
            expect((req.session as any).otp).toBeUndefined();
            expect((req.session as any).token).toBeUndefined();
            expect((req.session as any).secret).toBeUndefined();
        });

        it("Rejects a stored challenge with a bad issue time or a hash of the wrong length.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            (req.session as any).otp.issuedAt = "yesterday";
            expect(await ver(req, { id: "c", token: code })).toBe(false);

            const other = makeReq();
            const otherCode = await gen(other, { id: "c" });
            (other.session as any).otp.hash = "abcd";
            (other.session as any).otp.attempts = "x";
            expect(await ver(other, { id: "c", token: otherCode })).toBe(false);
            expect((other.session as any).otp.attempts).toBe(1);
        });
    });

    describe("purpose binding", () => {
        const purposes: OTPPurpose[] = ["login", "mfa", "elevate", "register", "contact"];

        it("Accepts a code only for the purpose it was issued for.", async () => {
            for (const issued of purposes) {
                for (const presented of purposes) {
                    const req = makeReq();
                    const code = await gen(req, { id: "c" }, undefined, issued);
                    if (issued === presented) {
                        expect(await ver(req, { id: "c", token: code }, undefined, presented)).toBe(true);
                    } else {
                        await expect(ver(req, { id: "c", token: code }, undefined, presented)).rejects.toThrow(
                            /Invalid authentication request/,
                        );
                        // The challenge was consumed by the mismatch: the right purpose no longer works either.
                        expect(isOTPChallengePending(req)).toBe(false);
                        await expect(ver(req, { id: "c", token: code }, undefined, issued)).rejects.toThrow(
                            /Invalid authentication request/,
                        );
                    }
                }
            }
        });

        it("Rejects a stored challenge that carries no purpose, such as one written by an older version.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            delete (req.session as any).otp.purpose;
            await expect(ver(req, { id: "c", token: code })).rejects.toThrow(/Invalid authentication request/);
        });
    });

    describe("submission length cap", () => {
        it("Counts a token longer than four times the code length as a wrong guess, even if it normalizes to the code.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            const padded = code + "-".repeat(4 * code.length - code.length + 1);
            expect(padded.length).toBe(4 * code.length + 1);
            expect(await ver(req, { id: "c", token: padded })).toBe(false);
            expect((req.session as any).otp.attempts).toBe(1);
            // The real code still works afterwards.
            expect(await ver(req, { id: "c", token: code })).toBe(true);
        });

        it("Accepts a token of exactly four times the code length.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            const padded = code + " ".repeat(3 * code.length);
            expect(padded.length).toBe(4 * code.length);
            expect(await ver(req, { id: "c", token: padded })).toBe(true);
        });

        it("Scales the cap with a configured length.", async () => {
            const config = { length: 8 };
            const req = makeReq();
            const code = await gen(req, { id: "c" }, config);
            expect(await ver(req, { id: "c", token: code + " ".repeat(25) }, config)).toBe(false);
            expect(await ver(req, { id: "c", token: code + " ".repeat(24) }, config)).toBe(true);
        });
    });

    describe("configuration validation", () => {
        it("Returns the defaults, memoized, when nothing is configured.", () => {
            const resolved = resolveOTPConfig();
            expect(resolved.length).toBe(DEFAULT_OTP_LENGTH);
            expect(resolved.maxAttempts).toBe(DEFAULT_OTP_MAX_ATTEMPTS);
            expect(resolved.ttl).toBe(600);
            expect(resolved.alphabet).toHaveLength(31);
            expect(resolved.issue).toEqual({ maxAttempts: 5, windowSeconds: 900 });
            expect(resolved.issueTotal).toEqual({ maxAttempts: 20, windowSeconds: 900 });
            expect(resolved.verify).toEqual({ maxAttempts: 20, windowSeconds: 3600 });
            expect(DEFAULT_OTP_ISSUE_TOTAL_LIMIT).toEqual(resolved.issueTotal);
            expect(resolved.user).toEqual({ maxAttempts: 50, windowSeconds: 3600 });
            expect(DEFAULT_OTP_ISSUE_LIMIT).toEqual(resolved.issue);
            expect(DEFAULT_OTP_VERIFY_LIMIT).toEqual(resolved.verify);
            expect(DEFAULT_OTP_USER_LIMIT).toEqual(resolved.user);
            expect(resolveOTPConfig()).toBe(resolved);

            const config: OTPConfig = { length: 8 };
            expect(resolveOTPConfig(config)).toBe(resolveOTPConfig(config));
        });

        it("Rejects an alphabet that is not printable ASCII.", () => {
            for (const alphabet of ["ABC DEF", "ABCDÉF", "ABCDEF\n", "ABCD\u{1F600}EF", "ABCD\u0000EF", "ABCDEFé", ""]) {
                expect(() => resolveOTPConfig({ alphabet })).toThrow(/alphabet/);
            }
            expect(() => resolveOTPConfig({ alphabet: 5 as any })).toThrow(/alphabet/);
        });

        it("Rejects an alphabet containing a hyphen, since hyphens are stripped from submitted codes.", () => {
            expect(() => resolveOTPConfig({ alphabet: "ABCDEF-" })).toThrow(/alphabet/);
        });

        it("Accepts any other printable ASCII symbol, and upper-cases and de-duplicates the alphabet.", () => {
            expect(resolveOTPConfig({ alphabet: "!~abAB#", length: 10 }).alphabet).toEqual(["!", "~", "A", "B", "#"]);
        });

        it("Rejects a length outside 4 to 64.", () => {
            for (const length of [0, 3, 65, 6.5, "six" as any, "6.5" as any, "", {} as any, NaN]) {
                expect(() => resolveOTPConfig({ length })).toThrow(/length/);
            }
        });

        it("Rejects fewer than 20 bits of entropy.", () => {
            // 4 * log2(31) = 19.8 bits
            expect(() => resolveOTPConfig({ length: 4 })).toThrow(/entropy/);
            // 19 * 1 bit is not enough either, nor is a 2-symbol alphabet at 19 characters.
            expect(() => resolveOTPConfig({ length: 19, alphabet: "01" })).toThrow(/entropy/);
            // 20 * 1 bit is exactly enough.
            expect(resolveOTPConfig({ length: 20, alphabet: "01" }).length).toBe(20);
            // 5 * log2(31) = 24.8 bits
            expect(resolveOTPConfig({ length: 5 }).length).toBe(5);
        });

        it("Rejects a TTL of zero, a negative TTL and one over an hour.", () => {
            expect(() => resolveOTPConfig({ ttl: 0 })).toThrow(/ttl/);
            expect(() => resolveOTPConfig({ ttl: -1 })).toThrow(/ttl/);
            expect(() => resolveOTPConfig({ ttl: 3601 })).toThrow(/ttl/);
            expect(() => resolveOTPConfig({ ttl: "61m" })).toThrow(/ttl/);
        });

        it("Rejects maxAttempts outside 1 to 10.", () => {
            for (const maxAttempts of [0, -1, 11, 2.5, NaN, "five" as any, "5.5" as any, "11" as any, [] as any]) {
                expect(() => resolveOTPConfig({ maxAttempts })).toThrow(/maxAttempts/);
            }
            expect(resolveOTPConfig({ maxAttempts: 1 }).maxAttempts).toBe(1);
            expect(resolveOTPConfig({ maxAttempts: 10 }).maxAttempts).toBe(10);
        });

        it("Rejects an invalid limit and honors a valid one.", () => {
            for (const name of ["issue", "issueTotal", "verify", "user"]) {
                for (const bad of [
                    { maxAttempts: 0 },
                    { maxAttempts: 1.5 },
                    { maxAttempts: "many" },
                    { windowSeconds: 0 },
                    { windowSeconds: 0.5 },
                    { windowSeconds: "soon" },
                ]) {
                    expect(() => resolveOTPConfig({ limits: { [name]: bad } })).toThrow(new RegExp(`limits:${name}`));
                }
            }
            const resolved = resolveOTPConfig({ limits: { issue: { maxAttempts: 2 }, user: { windowSeconds: 60 } } });
            expect(resolved.issue).toEqual({ maxAttempts: 2, windowSeconds: 900 });
            expect(resolved.user).toEqual({ maxAttempts: 50, windowSeconds: 60 });
            expect(resolved.verify).toEqual({ maxAttempts: 20, windowSeconds: 3600 });
        });

        it("Accepts numbers given as strings, as environment variables are, and still rejects garbage.", () => {
            const resolved = resolveOTPConfig({
                length: "8" as any,
                maxAttempts: " 3 " as any,
                ttl: "300",
                limits: {
                    issue: { maxAttempts: "2" as any, windowSeconds: "60" as any },
                    user: { maxAttempts: "7" as any },
                },
            });
            expect(resolved.length).toBe(8);
            expect(resolved.maxAttempts).toBe(3);
            expect(resolved.ttl).toBe(300);
            expect(resolved.issue).toEqual({ maxAttempts: 2, windowSeconds: 60 });
            expect(resolved.user).toEqual({ maxAttempts: 7, windowSeconds: 3600 });
            expect(() => resolveOTPConfig({ length: "8abc" as any })).toThrow(/length/);
            expect(() => resolveOTPConfig({ maxAttempts: "3x" as any })).toThrow(/maxAttempts/);
        });

        it("Is not re-validated on every call: the result for a config object is reused.", () => {
            const config: OTPConfig = { length: 6 };
            const first = resolveOTPConfig(config);
            // Mutating the object afterwards does not matter, validation happened once.
            config.length = 1;
            expect(resolveOTPConfig(config)).toBe(first);
        });
    });

    describe("counters integration", () => {
        /** A Redis connection (the fake, with only Redis 7 commands) for a counters instance. */
        const connect = (counters: OTPCounters, redis: FakeRedisClient): OTPCounters => {
            (counters as any).connMgr = { connections: new Map([["cache", redis]]) };
            return counters;
        };

        let counters: OTPCounters;
        beforeEach(() => {
            counters = new OTPCounters();
        });
        const ctx = (extra: Partial<OTPContext> = {}): OTPContext => ({ counters, ...extra });

        it("Counts verification against the contact and the user the code was issued for, with the configured limits.", async () => {
            const throttle = vi.spyOn(counters, "throttle");
            const req = makeReq();
            const code = await generateOTP(req, { id: "Contact" }, undefined, "login", "u1");
            await ver(req, { id: "Contact", token: code }, undefined, "login", ctx());
            const contact = counterKeyPart("contact");
            const address = counterKeyPart("unknown");
            const owner = counterKeyPart("u1");
            expect(throttle).toHaveBeenCalledWith(`verify:login:${contact}:${address}`, DEFAULT_OTP_VERIFY_LIMIT);
            expect(throttle).toHaveBeenCalledWith(`verify-total:login:${contact}`, DEFAULT_OTP_VERIFY_TOTAL_LIMIT);
            expect(throttle).toHaveBeenCalledWith(`user:login:${owner}:${address}`, DEFAULT_OTP_USER_LIMIT);
            expect(throttle).toHaveBeenCalledWith(`user-total:login:${owner}`, DEFAULT_OTP_USER_TOTAL_LIMIT);
            expect(DEFAULT_OTP_VERIFY_LIMIT).toEqual({ maxAttempts: 20, windowSeconds: 3600 });
            expect(DEFAULT_OTP_VERIFY_TOTAL_LIMIT).toEqual({ maxAttempts: 60, windowSeconds: 3600 });
            expect(DEFAULT_OTP_USER_LIMIT).toEqual({ maxAttempts: 50, windowSeconds: 3600 });
            expect(DEFAULT_OTP_USER_TOTAL_LIMIT).toEqual({ maxAttempts: 150, windowSeconds: 3600 });
        });

        it("Counts verification per address, so one address cannot drain the allowance of everyone else.", async () => {
            const config = { limits: { verify: { maxAttempts: 3, windowSeconds: 60 } } };
            const at = (address: string) => makeReq({ socket: { remoteAddress: address } });
            // The attacker's address spends its own 3 attempts across fresh codes, then is refused.
            for (let i = 0; i < 3; i++) {
                const req = at("10.0.0.1");
                const code = await gen(req, { id: "c" }, config);
                expect(await ver(req, { id: "c", token: wrongCode(code) }, config, "login", ctx())).toBe(false);
            }
            const attacker = at("10.0.0.1");
            const attackerCode = await gen(attacker, { id: "c" }, config);
            await expect(
                ver(attacker, { id: "c", token: attackerCode }, config, "login", ctx()),
            ).rejects.toMatchObject({ status: 429 });

            // The contact's owner, from another address, is not locked out.
            const owner = at("10.0.0.2");
            const ownerCode = await gen(owner, { id: "c" }, config);
            expect(await ver(owner, { id: "c", token: ownerCode }, config, "login", ctx())).toBe(true);
        });

        it("Caps verification against one contact across all addresses with verifyTotal.", async () => {
            const config = {
                limits: { verify: { maxAttempts: 2, windowSeconds: 60 }, verifyTotal: { maxAttempts: 3, windowSeconds: 60 } },
            };
            for (const address of ["10.0.0.1", "10.0.0.1", "10.0.0.2"]) {
                const req = makeReq({ socket: { remoteAddress: address } });
                const code = await gen(req, { id: "c" }, config);
                expect(await ver(req, { id: "c", token: wrongCode(code) }, config, "login", ctx())).toBe(false);
            }
            const req = makeReq({ socket: { remoteAddress: "10.0.0.3" } });
            const code = await gen(req, { id: "c" }, config);
            await expect(ver(req, { id: "c", token: code }, config, "login", ctx())).rejects.toMatchObject({
                status: 429,
            });
        });

        it("Counts the per-user budget per address too, and caps it across addresses with userTotal.", async () => {
            const config = {
                limits: { user: { maxAttempts: 1, windowSeconds: 60 }, userTotal: { maxAttempts: 2, windowSeconds: 60 } },
            };
            const attempt = async (address: string, id: string) => {
                const req = makeReq({ socket: { remoteAddress: address } });
                const code = await generateOTP(req, { id }, config, "login", "u1");
                return ver(req, { id, token: wrongCode(code) }, config, "login", ctx());
            };
            expect(await attempt("10.0.0.1", "a@example.com")).toBe(false);
            // The same address has used its own allowance, while another address still has its own ...
            await expect(attempt("10.0.0.1", "b@example.com")).rejects.toMatchObject({ status: 429 });
            expect(await attempt("10.0.0.2", "b@example.com")).toBe(false);
            // ... until the user-wide total is spent as well.
            await expect(attempt("10.0.0.3", "c@example.com")).rejects.toMatchObject({ status: 429 });
        });

        it("Skips the per-user counter when the challenge does not name a user.", async () => {
            const throttle = vi.spyOn(counters, "throttle");
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            await ver(req, { id: "c", token: code }, undefined, "login", ctx());
            expect(throttle.mock.calls.some((c) => c[0].startsWith("user:"))).toBe(false);
        });

        it("Does not spend the verification budget unless the session holds a code for that contact and purpose.", async () => {
            const throttle = vi.spyOn(counters, "throttle");

            // Nothing pending at all.
            await expect(ver(makeReq(), { id: "c", token: "ABC234" }, undefined, "login", ctx())).rejects.toThrow(
                /Invalid authentication request/,
            );
            // A code pending for another contact.
            const other = makeReq();
            await gen(other, { id: "someone-else" });
            await expect(ver(other, { id: "c", token: "ABC234" }, undefined, "login", ctx())).rejects.toThrow(
                /Invalid authentication request/,
            );
            // A code pending for another purpose.
            const purpose = makeReq();
            await gen(purpose, { id: "c" }, undefined, "register");
            await expect(ver(purpose, { id: "c", token: "ABC234" }, undefined, "login", ctx())).rejects.toThrow(
                /Invalid authentication request/,
            );

            expect(throttle).not.toHaveBeenCalled();
        });

        it("Refuses further verification against a contact once the per-contact limit is exceeded, across codes.", async () => {
            const config = { limits: { verify: { maxAttempts: 3, windowSeconds: 60 } } };
            // Each iteration is a fresh code (as a resend would be), so only the aggregate counter can stop it.
            for (let i = 0; i < 3; i++) {
                const req = makeReq();
                const code = await gen(req, { id: "c" }, config);
                expect(await ver(req, { id: "c", token: wrongCode(code) }, config, "login", ctx())).toBe(false);
            }
            const req = makeReq();
            const code = await gen(req, { id: "c" }, config);
            await expect(ver(req, { id: "c", token: code }, config, "login", ctx())).rejects.toMatchObject({
                status: 429,
            });
        });

        it("Keeps the budgets of different purposes apart, even for the same id.", async () => {
            const config = { limits: { verify: { maxAttempts: 1, windowSeconds: 60 } } };
            const login = makeReq();
            const loginCode = await gen(login, { id: "same" }, config, "login");
            expect(await ver(login, { id: "same", token: wrongCode(loginCode) }, config, "login", ctx())).toBe(false);
            const again = makeReq();
            await gen(again, { id: "same" }, config, "login");
            await expect(ver(again, { id: "same", token: "ABC234" }, config, "login", ctx())).rejects.toMatchObject({
                status: 429,
            });

            // The exhausted login budget does not touch the MFA budget for the same id.
            const mfa = makeReq();
            const mfaCode = await gen(mfa, { id: "same" }, config, "mfa");
            expect(await ver(mfa, { id: "same", token: mfaCode }, config, "mfa", ctx())).toBe(true);
        });

        it("Refuses further verification for a user once the per-user limit is exceeded, across every contact.", async () => {
            const config = { limits: { user: { maxAttempts: 3, windowSeconds: 60 } } };
            // Three different aliases of the same account.
            for (const id of ["a@example.com", "b@example.com", "+15551234567"]) {
                const req = makeReq();
                const code = await generateOTP(req, { id }, config, "login", "u1");
                expect(await ver(req, { id, token: wrongCode(code) }, config, "login", ctx())).toBe(false);
            }
            const req = makeReq();
            const code = await generateOTP(req, { id: "d@example.com" }, config, "login", "u1");
            await expect(ver(req, { id: "d@example.com", token: code }, config, "login", ctx())).rejects.toMatchObject({
                status: 429,
            });
            // Another user is unaffected.
            const other = makeReq();
            const otherCode = await generateOTP(other, { id: "e@example.com" }, config, "login", "u2");
            expect(await ver(other, { id: "e@example.com", token: otherCode }, config, "login", ctx())).toBe(true);
        });

        it("Stops a guesser racing stale copies of one challenge at maxAttempts, wherever the session says the count is.", async () => {
            // A Redis-backed session store hands every parallel request its own copy with attempts: 0.
            const origin = makeReq();
            const code = await gen(origin, { id: "c" });
            const challenge = (origin.session as any).otp;

            const results: boolean[] = [];
            for (let i = 0; i < 8; i++) {
                const copy = makeReq({ session: { otp: { ...challenge } } as any });
                results.push(await ver(copy, { id: "c", token: wrongCode(code) }, undefined, "login", ctx()));
            }
            expect(results.every((r) => r === false)).toBe(true);

            // The 6th and later guesses were refused by the atomic counter, so even the right code fails now, on a
            // pristine copy that still says attempts: 0.
            const late = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(late, { id: "c", token: code }, undefined, "login", ctx())).toBe(false);
            expect(isOTPChallengePending(late)).toBe(false);
            expect(await counters.increment(`attempts:${challenge.salt}`, 600)).toBe(10);
        });

        it("Lets exactly maxAttempts parallel copies guess, and still accepts the right code among them.", async () => {
            const origin = makeReq();
            const code = await gen(origin, { id: "c" });
            const challenge = (origin.session as any).otp;

            for (let i = 0; i < 4; i++) {
                const copy = makeReq({ session: { otp: { ...challenge } } as any });
                expect(await ver(copy, { id: "c", token: wrongCode(code) }, undefined, "login", ctx())).toBe(false);
            }
            const last = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(last, { id: "c", token: code }, undefined, "login", ctx())).toBe(true);
        });

        it("Redeems a code once even when a stale write-back resurrects the consumed challenge.", async () => {
            const origin = makeReq();
            const code = await gen(origin, { id: "c" });
            const challenge = (origin.session as any).otp;

            const first = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(first, { id: "c", token: code }, undefined, "login", ctx())).toBe(true);

            // The session store "restores" the pre-consumption challenge, as a late wrong-guess write would.
            const replay = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(replay, { id: "c", token: code }, undefined, "login", ctx())).toBe(false);
            expect(isOTPChallengePending(replay)).toBe(false);
        });

        it("Lets only one of many parallel redemptions of the right code succeed.", async () => {
            const origin = makeReq();
            const code = await gen(origin, { id: "c" });
            const challenge = (origin.session as any).otp;

            const results = await Promise.all(
                Array.from({ length: 5 }, () =>
                    ver(makeReq({ session: { otp: { ...challenge } } as any }), { id: "c", token: code }, undefined, "login", ctx()),
                ),
            );
            expect(results.filter(Boolean)).toHaveLength(1);
        });

        it("Keeps the claim and the guess counter even when rate limiting is disabled (rateLimit:enabled).", async () => {
            (counters as any).rateLimitConfig = { enabled: false };
            const increment = vi.spyOn(counters, "increment");

            // The throttles are off: any number of verifications against one contact is allowed ...
            const config = { limits: { verify: { maxAttempts: 1, windowSeconds: 60 } } };
            for (let i = 0; i < 3; i++) {
                const req = makeReq();
                const code = await gen(req, { id: "c" }, config);
                expect(await ver(req, { id: "c", token: wrongCode(code) }, config, "login", ctx())).toBe(false);
            }
            // ... but the guess counter was still applied to each code, and a success is still claimed once.
            expect(increment.mock.calls.filter((c) => c[0].startsWith("attempts:"))).toHaveLength(3);
            const origin = makeReq();
            const code = await gen(origin, { id: "c" }, config);
            const challenge = (origin.session as any).otp;
            const first = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(first, { id: "c", token: code }, config, "login", ctx())).toBe(true);
            const replay = makeReq({ session: { otp: { ...challenge } } as any });
            expect(await ver(replay, { id: "c", token: code }, config, "login", ctx())).toBe(false);
        });

        it("Propagates a counter failure, rather than failing open.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            const challenge = (req.session as any).otp;

            vi.spyOn(counters, "increment").mockRejectedValueOnce(new Error("redis down"));
            await expect(ver(req, { id: "c", token: code }, undefined, "login", ctx())).rejects.toThrow(/redis down/);

            vi.spyOn(counters, "claim").mockRejectedValueOnce(new Error("redis down"));
            const again = makeReq({ session: { otp: { ...challenge } } as any });
            await expect(ver(again, { id: "c", token: code }, undefined, "login", ctx())).rejects.toThrow(/redis down/);
        });

        it("Keeps working from the session alone when there are no counters.", async () => {
            const req = makeReq();
            const code = await gen(req, { id: "c" });
            expect(await ver(req, { id: "c", token: wrongCode(code) }, undefined, "login", {})).toBe(false);
            expect(await ver(req, { id: "c", token: code }, undefined, "login", {})).toBe(true);
        });

        describe("two server instances sharing one Redis", () => {
            let redis: FakeRedisClient;
            let a: OTPCounters;
            let b: OTPCounters;
            beforeEach(() => {
                redis = new FakeRedisClient(1);
                a = connect(new OTPCounters(), redis);
                b = connect(new OTPCounters(), redis);
            });

            it("Redeems a code once across both instances, however the requests are spread.", async () => {
                const origin = makeReq();
                const code = await gen(origin, { id: "c" });
                const challenge = (origin.session as any).otp;

                const results = await Promise.all(
                    Array.from({ length: 8 }, (_, i) =>
                        ver(makeReq({ session: { otp: { ...challenge } } as any }), { id: "c", token: code }, undefined, "login", {
                            counters: i % 2 ? a : b,
                        }),
                    ),
                );
                expect(results.filter(Boolean)).toHaveLength(1);
            });

            it("Counts guesses against one code across both instances.", async () => {
                const origin = makeReq();
                const code = await gen(origin, { id: "c" });
                const challenge = (origin.session as any).otp;

                const results = await Promise.all(
                    Array.from({ length: 12 }, (_, i) =>
                        ver(makeReq({ session: { otp: { ...challenge } } as any }), { id: "c", token: wrongCode(code) }, undefined, "login", {
                            counters: i % 2 ? a : b,
                        }),
                    ),
                );
                expect(results.every((r) => r === false)).toBe(true);
                // 12 guesses were made against a code that tolerates 5, and the counter saw every one of them.
                expect(redis.values.get(`auth:otp:attempts:${challenge.salt}`)).toBe("12");
                const late = makeReq({ session: { otp: { ...challenge } } as any });
                expect(await ver(late, { id: "c", token: code }, undefined, "login", { counters: a })).toBe(false);
            });

            it("Shares the dedicated limits between the instances.", async () => {
                const config = { limits: { verify: { maxAttempts: 4, windowSeconds: 60 } } };
                let refused = 0;
                for (let i = 0; i < 6; i++) {
                    const req = makeReq();
                    const code = await gen(req, { id: "c" }, config);
                    try {
                        await ver(req, { id: "c", token: wrongCode(code) }, config, "login", { counters: i % 2 ? a : b });
                    } catch (err: any) {
                        expect(err.status).toBe(429);
                        refused++;
                    }
                }
                expect(refused).toBe(2);
            });

            it("Uses only commands available since Redis 7, never INCREX.", async () => {
                const req = makeReq();
                const code = await gen(req, { id: "c" });
                await ver(req, { id: "c", token: code }, undefined, "login", { counters: a });
                expect(new Set(redis.commands)).toEqual(new Set(["EXEC", "SET"]));
            });
        });
    });

    describe("enforceOTPIssueLimit", () => {
        let counters: OTPCounters;
        beforeEach(() => {
            counters = new OTPCounters();
        });
        const from = (address: string) => makeReq({ socket: { remoteAddress: address } });
        const enforce = (req: HttpRequest, id: string, config?: OTPConfig, purpose: OTPPurpose = "login") =>
            enforceOTPIssueLimit(req, id, config, purpose, { counters });

        it("Is a no-op without counters.", async () => {
            await expect(enforceOTPIssueLimit(makeReq(), "c", undefined, "login")).resolves.toBeUndefined();
            await expect(enforceOTPIssueLimit(makeReq(), "c", undefined, "login", {})).resolves.toBeUndefined();
        });

        it("Allows 5 codes per contact and address and refuses the 6th by default, but not for another address.", async () => {
            for (let i = 0; i < 5; i++) {
                await enforce(from("10.0.0.1"), "c@example.com");
            }
            await expect(enforce(from("10.0.0.1"), "c@example.com")).rejects.toMatchObject({ status: 429 });
            // A different address, or a different contact, has its own budget.
            await expect(enforce(from("10.0.0.2"), "c@example.com")).resolves.toBeUndefined();
            await expect(enforce(from("10.0.0.1"), "d@example.com")).resolves.toBeUndefined();
        });

        it("Caps the codes sent to one contact from all addresses together, at a higher number.", async () => {
            // 20 codes from 4 addresses (5 each) are fine; the 21st from a fresh address is not.
            for (let i = 0; i < 20; i++) {
                await enforce(from(`10.0.0.${i % 4}`), "c@example.com");
            }
            await expect(enforce(from("10.0.0.99"), "c@example.com")).rejects.toMatchObject({ status: 429 });
        });

        it("Does not charge the contact-wide allowance for a request its own address already exhausted.", async () => {
            const throttle = vi.spyOn(counters, "throttle");
            for (let i = 0; i < 5; i++) {
                await enforce(from("10.0.0.1"), "c");
            }
            throttle.mockClear();
            await expect(enforce(from("10.0.0.1"), "c")).rejects.toMatchObject({ status: 429 });
            expect(throttle).toHaveBeenCalledTimes(1);
        });

        it("Keeps a separate allowance for every purpose, and ignores the case of the contact.", async () => {
            for (let i = 0; i < 5; i++) {
                await enforce(from("10.0.0.1"), "C@Example.com", undefined, "login");
            }
            await expect(enforce(from("10.0.0.1"), "c@example.com", undefined, "login")).rejects.toMatchObject({
                status: 429,
            });
            await expect(enforce(from("10.0.0.1"), "c@example.com", undefined, "mfa")).resolves.toBeUndefined();
            await expect(enforce(from("10.0.0.1"), "c@example.com", undefined, "elevate")).resolves.toBeUndefined();
        });

        it("Honors configured limits.", async () => {
            const config = { limits: { issue: { maxAttempts: 2, windowSeconds: 30 }, issueTotal: { maxAttempts: 3 } } };
            await enforce(from("10.0.0.1"), "c", config);
            await enforce(from("10.0.0.1"), "c", config);
            await expect(enforce(from("10.0.0.1"), "c", config)).rejects.toMatchObject({ status: 429 });
            await enforce(from("10.0.0.2"), "c", config);
            await expect(enforce(from("10.0.0.3"), "c", config)).rejects.toMatchObject({ status: 429 });
        });

        it("Rejects an id that is not a bounded, non-empty string, and an unknown purpose.", async () => {
            for (const id of ["", undefined, 5, {}, "x".repeat(257)]) {
                await expect(enforce(makeReq(), id as any)).rejects.toThrow(/Invalid authentication request/);
            }
            await expect(enforce(makeReq(), "x".repeat(256))).resolves.toBeUndefined();
            await expect(enforce(makeReq(), "c", undefined, "nope" as any)).rejects.toThrow(/purpose/);
        });
    });

    describe("clientRateLimitKey", () => {
        it("Puts a client supplied identifier in a namespace of its own.", () => {
            expect(clientRateLimitKey("alice")).toBe("id:alice");
            expect(clientRateLimitKey("elevate:some-uid")).toBe("id:elevate:some-uid");
            expect(clientRateLimitKey("otp:user:some-uid")).toBe("id:otp:user:some-uid");
            // No client value can ever start with an internal prefix.
            for (const value of ["ip:1.2.3.4", "oauth_token:x", "elevate:u", "", "id:"]) {
                expect(clientRateLimitKey(value).startsWith("id:")).toBe(true);
            }
        });

        it("Bounds long values by hashing them, and stringifies values that are not strings.", () => {
            const long = clientRateLimitKey("x".repeat(5000));
            expect(long).toMatch(/^idh:sha256:[0-9a-f]{64}$/);
            expect(clientRateLimitKey("x".repeat(5000))).toBe(long);
            expect(clientRateLimitKey("x".repeat(5001))).not.toBe(long);
            expect(clientRateLimitKey("x".repeat(256))).toBe("id:" + "x".repeat(256));
            expect(clientRateLimitKey({ a: 1 })).toBe("id:[object Object]");
            expect(clientRateLimitKey(undefined)).toBe("id:undefined");
        });
    });

    describe("counter key hygiene", () => {
        it("Gives hashed identifiers a prefix that no literal identifier can spell.", () => {
            // A client typing the exact text of a hashed key lands in the literal namespace, not on the hash.
            const hashed = clientRateLimitKey("y".repeat(300));
            const digest = hashed.slice("idh:sha256:".length);
            expect(hashed.startsWith("id:")).toBe(false);
            expect(clientRateLimitKey(`sha256:${digest}`)).toBe(`id:sha256:${digest}`);
            expect(clientRateLimitKey(`sha256:${digest}`)).not.toBe(hashed);
            expect(clientRateLimitKey(`idh:sha256:${digest}`)).toBe(`id:idh:sha256:${digest}`);
        });

        it("Hashes the subject and the address separately, so IPv6 addresses cannot collide with other pairs.", async () => {
            const counters = new OTPCounters();
            const keys: string[] = [];
            vi.spyOn(counters, "throttle").mockImplementation(async (key: string) => {
                keys.push(key);
            });
            const at = (address: string) => makeReq({ socket: { remoteAddress: address } });
            // Joined with ":", both pairs would read "login:a:b:c:d".
            await enforceOTPIssueLimit(at("b:c:d"), "a", undefined, "login", { counters });
            await enforceOTPIssueLimit(at("c:d"), "a:b", undefined, "login", { counters });
            await enforceOTPIssueLimit(at("2001:db8::1"), "a", undefined, "login", { counters });

            const perAddress = keys.filter((key) => key.startsWith("issue:"));
            expect(new Set(perAddress).size).toBe(3);
            for (const key of perAddress) {
                expect(key).toMatch(/^issue:login:[0-9a-f]{64}:[0-9a-f]{64}$/);
            }
            expect(keys.filter((key) => key.startsWith("issue-total:"))[0]).toMatch(
                /^issue-total:login:[0-9a-f]{64}$/,
            );
        });

        it("Hashes the verification keys the same way.", async () => {
            const counters = new OTPCounters();
            const keys: string[] = [];
            vi.spyOn(counters, "throttle").mockImplementation(async (key: string) => {
                keys.push(key);
            });
            const req = makeReq({ socket: { remoteAddress: "2001:db8::1" } });
            const code = await generateOTP(req, { id: "a:b" }, undefined, "login", "u:1");
            await ver(req, { id: "a:b", token: code }, undefined, "login", { counters });
            expect(keys).toHaveLength(4);
            expect(keys[0]).toMatch(/^verify:login:[0-9a-f]{64}:[0-9a-f]{64}$/);
            expect(keys[1]).toMatch(/^verify-total:login:[0-9a-f]{64}$/);
            expect(keys[2]).toMatch(/^user:login:[0-9a-f]{64}:[0-9a-f]{64}$/);
            expect(keys[3]).toMatch(/^user-total:login:[0-9a-f]{64}$/);
        });
    });

    describe("isOTPChallengePending", () => {
        it("Is false without a session or a challenge, and true while one is pending.", async () => {
            expect(isOTPChallengePending(makeReq({ session: undefined }))).toBe(false);
            const req = makeReq();
            expect(isOTPChallengePending(req)).toBe(false);
            await gen(req, { id: "c" });
            expect(isOTPChallengePending(req)).toBe(true);
        });
    });
});

describe("toUint8Array", () => {
    const bytes = [165, 1, 2, 3, 4, 5, 6, 7, 8, 9, 250];

    it("Returns a Uint8Array (and a Buffer) as is.", () => {
        const arr = new Uint8Array(bytes);
        expect(toUint8Array(arr)).toBe(arr);
        const buf = Buffer.from(bytes);
        expect(toUint8Array(buf)).toBe(buf);
    });

    it("Restores a BSON Binary read back from MongoDB.", () => {
        // A Uint8Array stored by the MongoDB driver comes back as a `Binary` whose backing buffer isn't
        // necessarily exactly the length of the data. Regression test: this used to decode to 3 bytes of garbage.
        const stored = deserialize(serialize({ data: { publicKey: new Uint8Array(bytes) } })) as any;
        expect(stored.data.publicKey).not.toBeInstanceOf(Uint8Array);
        expect(Array.from(toUint8Array(stored.data.publicKey))).toEqual(bytes);
    });

    it("Restores a base64 string (a Binary serialized by a JSON cache).", () => {
        const stored = JSON.parse(JSON.stringify({ k: new Binary(new Uint8Array(bytes)) }));
        expect(typeof stored.k).toBe("string");
        expect(Array.from(toUint8Array(stored.k))).toEqual(bytes);
    });

    it("Restores a JSON-serialized Buffer.", () => {
        const stored = JSON.parse(JSON.stringify(Buffer.from(bytes)));
        expect(Array.from(toUint8Array(stored))).toEqual(bytes);
    });

    it("Restores an index-keyed object (TypeORM simple-json).", () => {
        const stored = JSON.parse(JSON.stringify({ k: new Uint8Array(bytes) })).k;
        expect(Array.from(toUint8Array(stored))).toEqual(bytes);
    });

    it("Restores a plain array of numbers.", () => {
        expect(Array.from(toUint8Array(bytes))).toEqual(bytes);
    });

    it("Throws for a value that can't hold a key.", () => {
        expect(() => toUint8Array(undefined)).toThrow(/invalid public key/);
        expect(() => toUint8Array(42)).toThrow(/invalid public key/);
    });
});

describe("Passkey helpers", () => {
    describe("generatePasskeyChallenge", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            await expect(generatePasskeyChallenge(makePasskeyConfig(), req)).rejects.toThrow(/session support/);
        });

        it("Stores the returned challenge in the session.", async () => {
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });
            const req = makeReq();
            const result = await generatePasskeyChallenge(makePasskeyConfig(), req);
            expect(result).toEqual({ challenge: "chal-123" });
            expect((req.session as any).challenge).toBe("chal-123");
        });
    });

    describe("verifyPasskeyChallenge", () => {
        const credential: StoredPasskeyCredential = {
            id: "cred-1",
            uid: "user-1",
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 5,
            transports: ["usb"],
        };

        it("Throws when the stored counter is not finite.", async () => {
            await expect(
                verifyPasskeyChallenge({ ...credential, counter: NaN }, makePasskeyConfig(), "chal", {}),
            ).rejects.toThrow(/invalid counter/);
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Delegates to verifyAuthenticationResponse with the expected shape.", async () => {
            mockVerifyAuthenticationResponse.mockResolvedValue({ verified: true });
            const payload = { id: "cred-1" };
            const result = await verifyPasskeyChallenge(credential, makePasskeyConfig(), "chal", payload);
            expect(result).toEqual({ verified: true });
            expect(mockVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response: payload,
                expectedChallenge: "chal",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: { id: "cred-1", counter: 5, publicKey: credential.publicKey, transports: ["usb"] },
                requireUserVerification: true,
            });
        });
    });

    describe("generatePasskeyRegistrationOptions", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            await expect(
                generatePasskeyRegistrationOptions(makePasskeyConfig(), req, { id: "user-1", name: "test" }),
            ).rejects.toThrow(/session support/);
        });

        it("Stores the returned challenge in the session.", async () => {
            mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "reg-chal-1" });
            const req = makeReq();
            const result = await generatePasskeyRegistrationOptions(makePasskeyConfig(), req, {
                id: "user-1",
                name: "test",
            });
            expect(result).toEqual({ challenge: "reg-chal-1" });
            expect((req.session as any).challenge).toBe("reg-chal-1");
        });
    });

    describe("verifyPasskeyRegistrationResponse", () => {
        it("Delegates to verifyRegistrationResponse with the expected shape.", async () => {
            mockVerifyRegistrationResponse.mockResolvedValue({ verified: true });
            const payload = { id: "cred-1" };
            const result = await verifyPasskeyRegistrationResponse(makePasskeyConfig(), "reg-chal-1", payload);
            expect(result).toEqual({ verified: true });
            expect(mockVerifyRegistrationResponse).toHaveBeenCalledWith({
                response: payload,
                expectedChallenge: "reg-chal-1",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                requireUserVerification: true,
            });
        });
    });
});

describe("TOTP helpers", () => {
    describe("generateTOTP", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            await expect(generateTOTP(req)).rejects.toThrow(/session support/);
        });

        it("Derives requestData from the request itself when not provided.", async () => {
            const req = makeReq({ body: { id: "user-1" } });
            const token = await generateTOTP(req);
            expect(token).toBeDefined();
            expect((req.session as any).id).toBe("user-1");
        });

        it("Stores the generated secret/token/id in the session.", async () => {
            const req = makeReq();
            const token = await generateTOTP(req, { id: "user-1" });
            expect(token).toBeDefined();
            expect((req.session as any).id).toBe("user-1");
            expect((req.session as any).secret).toBeDefined();
            expect((req.session as any).token).toBe(token);
        });
    });

    describe("verifyTOTP", () => {
        it("Returns the verification result for a single valid secret.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret() };
            const token = await otplib.generate(secret);
            const result = await verifyTOTP(token, secret);
            expect(result?.valid).toBe(true);
        });

        it("Checks each secret in an array until one is valid.", async () => {
            const badSecret: TOTPSecret = { secret: otplib.generateSecret() };
            const goodSecret: TOTPSecret = { secret: otplib.generateSecret() };
            const token = await otplib.generate(goodSecret);
            const result = await verifyTOTP(token, [badSecret, goodSecret]);
            expect(result?.valid).toBe(true);
        });

        it("Returns undefined when no secret validates the token.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret() };
            const result = await verifyTOTP("000000", secret);
            expect(result).toBeUndefined();
        });

        it("Returns the matched secret's uid alongside the verification result.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret(), uid: "secret-uid-1" };
            const token = await otplib.generate(secret);
            const result = await verifyTOTP(token, secret);
            expect(result?.uid).toBe("secret-uid-1");
        });

        it("Rejects a token whose time step is at or before the secret's lastTimeStep (replay protection).", async () => {
            const base: TOTPSecret = { secret: otplib.generateSecret() };
            const token = await otplib.generate(base);
            const first = await verifyTOTP(token, base);
            expect(first?.valid).toBe(true);

            // Replaying the exact same token against a secret that already recorded this time step
            // as used must fail, even though the code itself is still within its validity window.
            const replayed = await verifyTOTP(token, { ...base, lastTimeStep: first.timeStep });
            expect(replayed).toBeUndefined();
        });

        it("Still accepts a token generated at a time step after lastTimeStep.", async () => {
            const base: TOTPSecret = { secret: otplib.generateSecret() };
            const token = await otplib.generate(base);
            const first = await verifyTOTP(token, base);

            const result = await verifyTOTP(token, { ...base, lastTimeStep: first.timeStep - 1 });
            expect(result?.valid).toBe(true);
        });

        it("Fails cleanly (rather than throwing) for a malformed token, e.g. wrong length or non-numeric.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret() };

            await expect(verifyTOTP("", secret)).resolves.toBeUndefined();
            await expect(verifyTOTP("12345", secret)).resolves.toBeUndefined();
            await expect(verifyTOTP("abcdef", secret)).resolves.toBeUndefined();
        });

        it("Validates token length against the secret's own digits override, not the otplib default.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret(), digits: 8 };
            const token = await otplib.generate(secret);

            expect(token).toHaveLength(8);
            // A well-formed 6-digit token must not even reach otplib for an 8-digit secret.
            await expect(verifyTOTP("123456", secret)).resolves.toBeUndefined();
            await expect(verifyTOTP(token, secret)).resolves.toMatchObject({ valid: true });
        });

        it("Decrypts an encrypted secret before verifying, given the matching encryption key.", async () => {
            const key = "a".repeat(64);
            const rawSecret = otplib.generateSecret();
            const encrypted: TOTPSecret = { secret: encryptTOTPSecret(rawSecret, key) };
            const token = await otplib.generate({ secret: rawSecret });

            const result = await verifyTOTP(token, encrypted, key);

            expect(result?.valid).toBe(true);
        });

        it("Still verifies a plaintext secret unchanged even when an encryption key is configured.", async () => {
            const key = "a".repeat(64);
            const secret: TOTPSecret = { secret: otplib.generateSecret() };
            const token = await otplib.generate(secret);

            const result = await verifyTOTP(token, secret, key);

            expect(result?.valid).toBe(true);
        });

        // Regression: a candidate that can't be decrypted under the current key used to let the throw
        // escape verifyTOTP() entirely, aborting the check instead of just skipping that one candidate -
        // see the two tests below for why that matters once a caller can have more than one TOTP secret.
        it("Does not throw (treats as a non-match) when a single candidate is encrypted but no encryption key is provided.", async () => {
            const key = "a".repeat(64);
            const encrypted: TOTPSecret = { secret: encryptTOTPSecret(otplib.generateSecret(), key) };

            await expect(verifyTOTP("123456", encrypted)).resolves.toBeUndefined();
        });

        it("Falls through to a later candidate when an earlier one can't be decrypted under the current key.", async () => {
            const key = "a".repeat(64);
            const undecryptable: TOTPSecret = { secret: encryptTOTPSecret(otplib.generateSecret(), key) };
            const goodSecret = otplib.generateSecret();
            const good: TOTPSecret = { secret: goodSecret, uid: "good-secret-uid" };
            const token = await otplib.generate({ secret: goodSecret });

            // No `encryptionKey` passed, so `undecryptable` can't be decrypted (wrong/missing key) while
            // `good` verifies fine as plaintext - the bad candidate must not block reaching the good one.
            const result = await verifyTOTP(token, [undecryptable, good]);

            expect(result?.valid).toBe(true);
            expect(result?.uid).toBe("good-secret-uid");
        });

        it("Falls through to a later candidate when an earlier one was encrypted under a different key.", async () => {
            const key = "a".repeat(64);
            const staleKey = "b".repeat(64);
            const undecryptable: TOTPSecret = { secret: encryptTOTPSecret(otplib.generateSecret(), staleKey) };
            const goodSecret = otplib.generateSecret();
            const good: TOTPSecret = { secret: encryptTOTPSecret(goodSecret, key), uid: "good-secret-uid" };
            const token = await otplib.generate({ secret: goodSecret });

            // `undecryptable` was encrypted under `staleKey` (e.g. a key rotation that didn't re-encrypt
            // every record), so its auth-tag check fails under the currently-configured `key`, while
            // `good` (encrypted under `key`) verifies correctly.
            const result = await verifyTOTP(token, [undecryptable, good], key);

            expect(result?.valid).toBe(true);
            expect(result?.uid).toBe("good-secret-uid");
        });
    });

    describe("isValidTOTPSecret", () => {
        it("Returns false for a non-string value.", async () => {
            expect(await isValidTOTPSecret(12345)).toBe(false);
        });

        it("Returns false for an empty string.", async () => {
            expect(await isValidTOTPSecret("")).toBe(false);
        });

        it("Returns false for a string that isn't valid Base32.", async () => {
            expect(await isValidTOTPSecret("not-valid-base32!!!")).toBe(false);
        });

        it("Returns false for a Base32 string decoding to fewer than 128 bits.", async () => {
            expect(await isValidTOTPSecret("AAAAAAAA")).toBe(false);
        });

        it("Returns true for a Base32 string decoding to at least 128 bits.", async () => {
            expect(await isValidTOTPSecret(otplib.generateSecret())).toBe(true);
        });
    });

    describe("generateTOTPURI", () => {
        const config: TOTPConfig = { issuer: "rapidrest", digits: 6, period: 30, algorithm: "sha1" };

        it("Uses the issuer config defaults when the secret has no per-secret overrides.", async () => {
            const secret: TOTPSecret = { secret: otplib.generateSecret() };
            const uri = await generateTOTPURI(config, "user1", secret);
            expect(uri).toContain("otpauth://totp/");
            expect(uri).toContain("issuer=rapidrest");
        });

        it("Prefers the secret's own algorithm/digits/period over the issuer config's.", async () => {
            const secret: TOTPSecret = {
                secret: otplib.generateSecret(),
                algorithm: "sha256",
                digits: 8,
                period: 60,
            };
            const uri = await generateTOTPURI(config, "user1", secret);
            expect(uri).toContain("algorithm=SHA256");
            expect(uri).toContain("digits=8");
            expect(uri).toContain("period=60");
        });
    });
});

describe("verifyDummyPassword", () => {
    it("Resolves without throwing regardless of the input, since the hash is never a real credential.", async () => {
        await expect(verifyDummyPassword("anything")).resolves.toBeUndefined();
        await expect(verifyDummyPassword("")).resolves.toBeUndefined();
    });

    it("DUMMY_ARGON2_HASH is a real, valid Argon2id hash (not a placeholder string).", async () => {
        const argon2 = await import("argon2");

        expect(DUMMY_ARGON2_HASH).toMatch(/^\$argon2id\$/);
        await expect(argon2.verify(DUMMY_ARGON2_HASH, "definitely-the-wrong-password")).resolves.toBe(false);
    });

    // When userUid/config are supplied, the dummy path must take the same shape-dependent branch a real
    // verification would (see normalizePasswordSubmission()), so the extra hash step a plaintext
    // submission triggers doesn't itself become a timing side-channel.
    describe("with userUid/config (the real password call sites' usage)", () => {
        it("Resolves without throwing for a plaintext-shaped input.", async () => {
            await expect(
                verifyDummyPassword("plaintext-guess", "some-uid", new PasswordConfig()),
            ).resolves.toBeUndefined();
        });

        it("Resolves without throwing for an already client-hashed-shaped input at/above the floor.", async () => {
            const clientHash = await (
                await import("argon2")
            ).hash("whatever", { salt: deriveClientSalt("some-uid"), ...CLIENT_ARGON2_PARAMS });

            await expect(verifyDummyPassword(clientHash, "some-uid", new PasswordConfig())).resolves.toBeUndefined();
        });

        it("Resolves without throwing for a below-floor fake hash (the WeakClientHashError branch).", async () => {
            const weakHash = "$argon2id$v=19$m=8,p=1,t=1$c29tZXNhbHQ$aGFzaA";

            await expect(verifyDummyPassword(weakHash, "some-uid", new PasswordConfig())).resolves.toBeUndefined();
        });

        // Regression/coverage: a non-WeakClientHashError thrown while normalizing (e.g. deriveClientSalt()
        // choking on a malformed uid) must propagate, not be silently swallowed alongside the
        // WeakClientHashError case above.
        it("Propagates a non-WeakClientHashError thrown while normalizing, rather than swallowing it.", async () => {
            await expect(verifyDummyPassword("plaintext-guess", 123 as any, new PasswordConfig())).rejects.toThrow(
                /must be of type string/,
            );
        });
    });
});

describe("isClientHashedFormat", () => {
    it("Returns true for a real Argon2id hash string.", async () => {
        const argon2 = await import("argon2");
        const hash = await argon2.hash("some-password");

        expect(isClientHashedFormat(hash)).toBe(true);
    });

    it("Returns false for a plaintext password, even one that happens to contain '$'.", () => {
        expect(isClientHashedFormat("Str0ngP@ss")).toBe(false);
        expect(isClientHashedFormat("$cheap$fake$hash")).toBe(false);
    });

    it("Returns false for an empty string.", () => {
        expect(isClientHashedFormat("")).toBe(false);
    });

    it("Returns true regardless of the m/t/p parameter order.", () => {
        expect(isClientHashedFormat("$argon2id$v=19$m=19456,p=1,t=2$c29tZXNhbHQ$aGFzaA")).toBe(true);
        expect(isClientHashedFormat("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA")).toBe(true);
    });

    it("Returns false unless the parameters are exactly m, t and p, once each.", () => {
        // Unknown key.
        expect(isClientHashedFormat("$argon2id$v=19$m=19456,t=2,x=1$c29tZXNhbHQ$aGFzaA")).toBe(false);
        // Duplicate key.
        expect(isClientHashedFormat("$argon2id$v=19$m=19456,t=2,t=1$c29tZXNhbHQ$aGFzaA")).toBe(false);
        // Missing key.
        expect(isClientHashedFormat("$argon2id$v=19$m=19456,t=2$c29tZXNhbHQ$aGFzaA")).toBe(false);
    });
});

describe("deriveClientSalt", () => {
    it("Is deterministic for the same uid.", () => {
        expect(deriveClientSalt("user-uid-1")).toEqual(deriveClientSalt("user-uid-1"));
    });

    it("Differs for different uids.", () => {
        expect(deriveClientSalt("user-uid-1")).not.toEqual(deriveClientSalt("user-uid-2"));
    });

    it("Returns a 32-byte buffer, satisfying argon2's minimum salt length.", () => {
        expect(deriveClientSalt("user-uid-1").length).toBe(32);
    });
});

describe("normalizePasswordSubmission", () => {
    it("Is deterministic for the same plaintext password and uid — this is what lets a capable client " +
        "reproduce the same hash across sessions/devices.", async () => {
        const config = new PasswordConfig();

        const a = await normalizePasswordSubmission("Str0ngP@ss", "user-uid-1", config);
        const b = await normalizePasswordSubmission("Str0ngP@ss", "user-uid-1", config);

        expect(a).toBe(b);
    });

    it("Produces different canonical values for the same password under different uids.", async () => {
        const config = new PasswordConfig();

        const a = await normalizePasswordSubmission("Str0ngP@ss", "user-uid-1", config);
        const b = await normalizePasswordSubmission("Str0ngP@ss", "user-uid-2", config);

        expect(a).not.toBe(b);
    });

    // Known-answer vector: every stored password secret is an argon2 hash OF this canonical string, so its exact
    // bytes (including the m,p,t parameter order emitted by argon2 < 0.45.2) must never drift, whatever order
    // the installed argon2 emits. A change here means every existing account's password stops verifying.
    const CANONICAL_STR0NGPASS_USER_UID_1 =
        "$argon2id$v=19$m=19456,p=1,t=2$d1RvgFSLVY/gcFrFMQYf7TrjYOXoUU849cB1knLBEXU" +
        "$Ea0iGwuXEz/r9zJdpqb5bRd2EiT3JOjfBPsmjt3eMNA";

    it("Hashes plaintext using deriveClientSalt(userUid) and CLIENT_ARGON2_PARAMS, in canonical m,p,t order.", async () => {
        const config = new PasswordConfig();

        const canonical = await normalizePasswordSubmission("Str0ngP@ss", "user-uid-1", config);

        expect(canonical).toBe(CANONICAL_STR0NGPASS_USER_UID_1);
    });

    it("Returns an already client-hashed value in canonical form when it meets the configured cost floor.", async () => {
        const config = new PasswordConfig();
        const argon2 = await import("argon2");
        const clientHash = await argon2.hash("Str0ngP@ss", {
            salt: deriveClientSalt("user-uid-1"),
            ...CLIENT_ARGON2_PARAMS,
        });

        const canonical = await normalizePasswordSubmission(clientHash, "user-uid-1", config);

        expect(canonical).toBe(CANONICAL_STR0NGPASS_USER_UID_1);
    });

    // A capable client may use any argon2 implementation; the reference order is m,t,p but older node-argon2
    // emitted m,p,t. Both must normalize to the same canonical value, or the same password would only verify
    // from clients whose library happens to match the one used at registration.
    it("Normalizes a client hash to the same value regardless of its parameter order.", async () => {
        const config = new PasswordConfig();
        const [salt, hash] = CANONICAL_STR0NGPASS_USER_UID_1.split("$").slice(-2);
        const mtp = `$argon2id$v=19$m=19456,t=2,p=1$${salt}$${hash}`;
        const tpm = `$argon2id$v=19$t=2,p=1,m=19456$${salt}$${hash}`;

        expect(await normalizePasswordSubmission(mtp, "user-uid-1", config)).toBe(CANONICAL_STR0NGPASS_USER_UID_1);
        expect(await normalizePasswordSubmission(tpm, "user-uid-1", config)).toBe(CANONICAL_STR0NGPASS_USER_UID_1);
    });

    it("Throws WeakClientHashError for a below-floor client hash in m,t,p order too.", async () => {
        const weakHash = "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$aGFzaA";

        await expect(normalizePasswordSubmission(weakHash, "user-uid-1", new PasswordConfig())).rejects.toThrow(
            WeakClientHashError,
        );
    });

    it("Throws WeakClientHashError for a below-floor client-hashed value.", async () => {
        const config = new PasswordConfig();
        // Well-formed PHC shape, but m/t/p all below the default floor (19456/2/1).
        const weakHash = "$argon2id$v=19$m=8,p=1,t=1$c29tZXNhbHQ$aGFzaA";

        await expect(normalizePasswordSubmission(weakHash, "user-uid-1", config)).rejects.toThrow(
            WeakClientHashError,
        );
    });

    it("Accepts a client-hashed value using higher-than-floor cost parameters.", async () => {
        const config = new PasswordConfig();
        const argon2 = await import("argon2");
        const strongerHash = await argon2.hash("Str0ngP@ss", {
            salt: deriveClientSalt("user-uid-1"),
            memoryCost: 65536,
            timeCost: 4,
            parallelism: 2,
            hashLength: 32,
        });

        const canonical = await normalizePasswordSubmission(strongerHash, "user-uid-1", config);

        expect(canonical).toMatch(/^\$argon2id\$v=19\$m=65536,p=2,t=4\$/);
        expect(canonical.split("$").slice(-2)).toEqual(strongerHash.split("$").slice(-2));
    });

    it("Honors a deployment-configured (non-default) cost floor.", async () => {
        const config = new PasswordConfig();
        (config as any).client_hash_min_memory_cost = 999_999;
        const argon2 = await import("argon2");
        const clientHash = await argon2.hash("Str0ngP@ss", {
            salt: deriveClientSalt("user-uid-1"),
            ...CLIENT_ARGON2_PARAMS,
        });

        await expect(normalizePasswordSubmission(clientHash, "user-uid-1", config)).rejects.toThrow(
            WeakClientHashError,
        );
    });
});

describe("verifyDummyTOTP", () => {
    it("Resolves without throwing regardless of the input, since the secret is never a real credential.", async () => {
        await expect(verifyDummyTOTP("123456")).resolves.toBeUndefined();
        await expect(verifyDummyTOTP("")).resolves.toBeUndefined();
        await expect(verifyDummyTOTP("not-a-code")).resolves.toBeUndefined();
    });

    it("DUMMY_TOTP_SECRET is a real, valid Base32 TOTP secret (not a placeholder string).", async () => {
        expect(await isValidTOTPSecret(DUMMY_TOTP_SECRET.secret)).toBe(true);
    });
});

describe("encryptTOTPSecret / decryptTOTPSecret", () => {
    const KEY = "b".repeat(64);

    describe("encryptTOTPSecret", () => {
        it("Returns the secret unchanged (plaintext passthrough) when no key is given.", () => {
            const secret = otplib.generateSecret();
            expect(encryptTOTPSecret(secret)).toBe(secret);
        });

        it("Returns an `enc:v1:`-prefixed value distinct from the plaintext when a key is given.", () => {
            const secret = otplib.generateSecret();
            const encrypted = encryptTOTPSecret(secret, KEY);
            expect(encrypted).toMatch(/^enc:v1:/);
            expect(encrypted).not.toBe(secret);
        });

        it("Produces a different ciphertext each call (fresh random IV), even for the same secret/key.", () => {
            const secret = otplib.generateSecret();
            const a = encryptTOTPSecret(secret, KEY);
            const b = encryptTOTPSecret(secret, KEY);
            expect(a).not.toBe(b);
        });

        it("Throws an ApiError when the key is not a valid 64-character hex string.", () => {
            const secret = otplib.generateSecret();
            expect(() => encryptTOTPSecret(secret, "too-short")).toThrow(/64-character hex string/);
        });
    });

    describe("decryptTOTPSecret", () => {
        it("Returns the value unchanged when it lacks the `enc:v1:` prefix (legacy plaintext passthrough).", () => {
            const secret = otplib.generateSecret();
            expect(decryptTOTPSecret(secret, KEY)).toBe(secret);
            // Even with no key configured at all - a never-encrypted deployment must keep working.
            expect(decryptTOTPSecret(secret)).toBe(secret);
        });

        it("Round-trips: decrypting an encrypted secret with the same key recovers the original plaintext.", () => {
            const secret = otplib.generateSecret();
            const encrypted = encryptTOTPSecret(secret, KEY);
            expect(decryptTOTPSecret(encrypted, KEY)).toBe(secret);
        });

        it("Throws an ApiError when the value is encrypted but no key is provided.", () => {
            const secret = otplib.generateSecret();
            const encrypted = encryptTOTPSecret(secret, KEY);
            expect(() => decryptTOTPSecret(encrypted)).toThrow(/encryption_key/);
        });

        it("Throws an ApiError when the key is not a valid 64-character hex string.", () => {
            const secret = otplib.generateSecret();
            const encrypted = encryptTOTPSecret(secret, KEY);
            expect(() => decryptTOTPSecret(encrypted, "too-short")).toThrow(/64-character hex string/);
        });

        it("Throws when decrypting with the wrong key (auth tag mismatch, not silently wrong plaintext).", () => {
            const secret = otplib.generateSecret();
            const encrypted = encryptTOTPSecret(secret, KEY);
            const wrongKey = "c".repeat(64);
            expect(() => decryptTOTPSecret(encrypted, wrongKey)).toThrow();
        });
    });
});

function makePasswordConfig(overrides: Partial<PasswordConfig> = {}): PasswordConfig {
    return Object.assign(new PasswordConfig(), overrides);
}

describe("generatePassword", () => {
    it("Generates a password of length max(min_length, recommended_length) by default.", () => {
        const config = makePasswordConfig();
        const pw = generatePassword(config);
        expect(pw.length).toBe(Math.max(config.min_length, config.recommended_length));
    });

    it("Satisfies every default requirement (lowercase, uppercase, numeral, special).", () => {
        const config = makePasswordConfig();
        const pw = generatePassword(config);
        expect(pw).toMatch(/[a-z]/);
        expect(pw).toMatch(/[A-Z]/);
        expect(pw).toMatch(/[0-9]/);
        expect(pw).toMatch(new RegExp(`[${config.special_chars}]`));
    });

    it("Uses recommended_length when it is larger than min_length.", () => {
        const config = makePasswordConfig({ min_length: 8, recommended_length: 40 });
        expect(generatePassword(config).length).toBe(40);
    });

    it("Falls back to min_length when it is larger than recommended_length.", () => {
        const config = makePasswordConfig({ min_length: 20, recommended_length: 10 });
        expect(generatePassword(config).length).toBe(20);
    });

    it("Draws only from the numeral pool when it is the only required category.", () => {
        const config = makePasswordConfig({
            require_lowercase: false,
            require_uppercase: false,
            require_numeral: true,
            require_special: false,
            recommended_length: 16,
        });
        const pw = generatePassword(config);
        expect(pw).toMatch(/^[0-9]+$/);
        expect(pw.length).toBe(16);
    });

    it("Falls back to the lowercase pool when no character category is required.", () => {
        const config = makePasswordConfig({
            require_lowercase: false,
            require_uppercase: false,
            require_numeral: false,
            require_special: false,
            recommended_length: 12,
        });
        const pw = generatePassword(config);
        expect(pw).toMatch(/^[a-z]+$/);
        expect(pw.length).toBe(12);
    });

    it("Only draws from the configured special_chars set when it is the only required category.", () => {
        const config = makePasswordConfig({
            require_lowercase: false,
            require_uppercase: false,
            require_numeral: false,
            require_special: true,
            special_chars: "#$%",
            recommended_length: 20,
        });
        const pw = generatePassword(config);
        expect(pw).toMatch(/^[#$%]+$/);
    });

    it("Generates distinct passwords across calls.", () => {
        const config = makePasswordConfig();
        expect(generatePassword(config)).not.toBe(generatePassword(config));
    });
});

describe("touchSecretLastUsedAt", () => {
    it("Is a no-op when secretRepo is undefined.", async () => {
        await touchSecretLastUsedAt(undefined, "secret-1");
        // No assertion beyond "did not throw" - there's nothing else to observe with no repo at all.
    });

    it("Does nothing (does not call update) when no matching secret is found.", async () => {
        const findOne = vi.fn().mockResolvedValue(undefined);
        const update = vi.fn();
        const secretRepo: any = { findOne, update };

        await touchSecretLastUsedAt(secretRepo, "secret-1");

        expect(findOne).toHaveBeenCalledWith("secret-1", { ignoreACL: true });
        expect(update).not.toHaveBeenCalled();
    });

    it("Persists a fresh ISO-8601 lastUsedAt on the matched secret via a minimal partial update.", async () => {
        const secret = { uid: "secret-1", version: 3 };
        const findOne = vi.fn().mockResolvedValue(secret);
        const update = vi.fn().mockResolvedValue(undefined);
        const secretRepo: any = { findOne, update };

        const before = Date.now();
        await touchSecretLastUsedAt(secretRepo, "secret-1");
        const after = Date.now();

        expect(update).toHaveBeenCalledTimes(1);
        const [patch, existing, options] = update.mock.calls[0];
        expect(patch.uid).toBe("secret-1");
        expect(patch.version).toBe(3);
        expect(typeof patch.lastUsedAt).toBe("string");
        expect(Date.parse(patch.lastUsedAt)).toBeGreaterThanOrEqual(before);
        expect(Date.parse(patch.lastUsedAt)).toBeLessThanOrEqual(after);
        expect(existing).toBe(secret);
        expect(options).toEqual({ ignoreACL: true, recordEvent: false });
    });

    it("Swallows a findOne() failure without throwing, and logs it via the given logger.", async () => {
        const findOne = vi.fn().mockRejectedValue(new Error("datastore unavailable"));
        const update = vi.fn();
        const secretRepo: any = { findOne, update };
        const logger = { debug: vi.fn(), warn: vi.fn() };

        await expect(touchSecretLastUsedAt(secretRepo, "secret-1", logger)).resolves.toBeUndefined();

        expect(update).not.toHaveBeenCalled();
        expect(logger.debug).toHaveBeenCalledTimes(1);
        expect(logger.debug.mock.calls[0][0]).toMatch(/Failed to persist 'lastUsedAt'/);
    });

    it("Swallows an update() failure without throwing, even with no logger supplied.", async () => {
        const secret = { uid: "secret-1", version: 1 };
        const findOne = vi.fn().mockResolvedValue(secret);
        const update = vi.fn().mockRejectedValue(new Error("version conflict"));
        const secretRepo: any = { findOne, update };

        await expect(touchSecretLastUsedAt(secretRepo, "secret-1")).resolves.toBeUndefined();
    });
});

describe("Library imports", () => {
    it("importArgon2 throws a helpful error when argon2 cannot be imported.", async () => {
        vi.doMock("argon2", () => {
            throw new Error("Cannot find module 'argon2'");
        });
        vi.resetModules();
        const { importArgon2: freshImportArgon2 } = await import("../../src/auth/shared.js");

        await expect(freshImportArgon2()).rejects.toThrow(/optional peer dependency 'argon2'/);

        vi.doUnmock("argon2");
        vi.resetModules();
    });

    it("importOTPLib throws a helpful error when otplib cannot be imported.", async () => {
        vi.doMock("otplib", () => {
            throw new Error("Cannot find module 'otplib'");
        });
        vi.resetModules();
        const { importOTPLib: freshImportOTPLib } = await import("../../src/auth/shared.js");

        await expect(freshImportOTPLib()).rejects.toThrow(/optional peer dependency 'otplib'/);

        vi.doUnmock("otplib");
        vi.resetModules();
    });

    it("importSimpleWebAuthn throws a helpful error when @simplewebauthn/server cannot be imported.", async () => {
        vi.doMock("@simplewebauthn/server", () => {
            throw new Error("Cannot find module '@simplewebauthn/server'");
        });
        vi.resetModules();
        const { importSimpleWebAuthn: freshImportSimpleWebAuthn } = await import("../../src/auth/shared.js");

        await expect(freshImportSimpleWebAuthn()).rejects.toThrow(/optional peer dependency '@simplewebauthn\/server'/);

        vi.doUnmock("@simplewebauthn/server");
        vi.resetModules();
    });
});

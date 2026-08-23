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

import type { HttpRequest } from "@rapidrest/service-core";
import * as otplib from "otplib";
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from "@simplewebauthn/server";
import {
    DUMMY_ARGON2_HASH,
    DUMMY_TOTP_SECRET,
    decryptTOTPSecret,
    encryptTOTPSecret,
    generateOTP,
    generatePasskeyChallenge,
    generatePasskeyRegistrationOptions,
    generatePassword,
    generateTOTP,
    generateTOTPURI,
    getBasicData,
    getRequestData,
    isOTPResponse,
    isPasskeyRegistrationResponse,
    isPasskeyResponse,
    isValidTOTPSecret,
    obfuscateContact,
    verifyDummyPassword,
    verifyDummyTOTP,
    verifyOTP,
    verifyPasskeyChallenge,
    verifyPasskeyRegistrationResponse,
    verifyTOTP,
} from "../../src/auth/shared.js";
import {
    OTPContactType,
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

    it("Returns the contact unchanged for an unrecognized type.", () => {
        expect(obfuscateContact("some-value", "bogus" as OTPContactType)).toBe("some-value");
    });
});

describe("OTP helpers", () => {
    describe("generateOTP", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            // Regression: a deployment misconfiguration, not a client-caused auth failure - must surface
            // as a distinguishable 500, not get flattened into a generic 401.
            await expect(generateOTP(req)).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/session support/),
            });
        });

        it("Derives requestData from the request itself when not provided.", async () => {
            const req = makeReq({ body: { id: "contact-1" } });
            await generateOTP(req);
            expect((req.session as any).id).toBe("contact-1");
        });

        it("Stores the generated secret/token/id in the session.", async () => {
            const req = makeReq();
            const token = await generateOTP(req, { id: "contact-1" });
            expect(token).toBeDefined();
            expect((req.session as any).id).toBe("contact-1");
            expect((req.session as any).secret).toBeDefined();
            expect((req.session as any).token).toBe(token);
        });
    });

    describe("verifyOTP", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            await expect(verifyOTP(req, { id: "c", token: "123456" })).rejects.toThrow(/session support/);
        });

        it("Derives payload from the request itself when not provided.", async () => {
            const req = makeReq({
                session: { id: "c", secret: otplib.generateSecret() },
                body: { id: "c", token: "000000" },
            });
            const result = await verifyOTP(req);
            expect(result).toBe(false);
        });

        it("Throws when the payload is not a valid OTP response shape.", async () => {
            const req = makeReq({ session: {} });
            await expect(verifyOTP(req, { id: "c" })).rejects.toThrow(/Invalid authentication request/);
        });

        it("Throws when the session id does not match the payload id.", async () => {
            const req = makeReq({ session: { id: "other" } });
            await expect(verifyOTP(req, { id: "c", token: "123456" })).rejects.toThrow(
                /Invalid authentication request/,
            );
        });

        it("Returns true for a valid token.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({ session: { id: "c", secret } });
            const result = await verifyOTP(req, { id: "c", token });
            expect(result).toBe(true);
        });

        it("Returns false for an invalid token.", async () => {
            const req = makeReq({ session: { id: "c", secret: otplib.generateSecret() } });
            const result = await verifyOTP(req, { id: "c", token: "000000" });
            expect(result).toBe(false);
        });

        it("Clears the session id/secret/token after a successful verification.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({ session: { id: "c", secret, token } });

            await verifyOTP(req, { id: "c", token });

            expect((req.session as any).id).toBeUndefined();
            expect((req.session as any).secret).toBeUndefined();
            expect((req.session as any).token).toBeUndefined();
        });

        it("Clears the session id/secret/token even when verification fails.", async () => {
            const secret = otplib.generateSecret();
            const req = makeReq({ session: { id: "c", secret, token: "some-token" } });

            await verifyOTP(req, { id: "c", token: "000000" });

            expect((req.session as any).id).toBeUndefined();
            expect((req.session as any).secret).toBeUndefined();
            expect((req.session as any).token).toBeUndefined();
        });

        it("Rejects replaying the same valid token a second time (single-use).", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({ session: { id: "c", secret } });

            const first = await verifyOTP(req, { id: "c", token });
            expect(first).toBe(true);

            // The session was cleared by the first call, so the second (replayed) attempt no longer
            // has a matching session id and must be rejected rather than re-verified.
            await expect(verifyOTP(req, { id: "c", token })).rejects.toThrow(/Invalid authentication request/);
        });
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

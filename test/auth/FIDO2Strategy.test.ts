///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for FIDO2Strategy — no HTTP server, no database. SimpleWebAuthn's own
// ceremony functions are mocked here; these tests verify FIDO2Strategy's own orchestration
// (session/challenge handling, calling storage callbacks in the right order, error handling), not
// SimpleWebAuthn's cryptographic correctness, which is that library's own tested responsibility.
// FIDO2Strategy shares its WebAuthn ceremony logic with PasskeyStrategy (see
// test/auth/PasskeyStrategy.test.ts) — the tests here mirror that suite to confirm the FIDO2-specific
// wiring (strategy name, error messages) behaves identically.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
}));

import type { JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import {
    FIDO2Strategy,
    FIDO2StrategyOptions,
    type PasskeyConfig,
    type StoredPasskeyCredential,
} from "../../src/auth/FIDO2Strategy.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as any;
const mockVerifyAuthenticationResponse = verifyAuthenticationResponse as any;

function makeConfig(overrides: Partial<PasskeyConfig> = {}): PasskeyConfig {
    return {
        rpName: "Test RP",
        rpID: "example.com",
        origin: "https://example.com",
        ...overrides,
    };
}

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "POST",
        path: "/auth/fido2",
        url: "/auth/fido2",
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

function makeRes(): HttpResponse {
    return {
        statusCode: 200,
        headersSent: false,
        writableEnded: false,
        status: vi.fn().mockReturnThis(),
        setHeader: vi.fn().mockReturnThis(),
        getHeader: vi.fn(),
        json: vi.fn(),
        send: vi.fn(),
        end: vi.fn(),
        onFinish: vi.fn(),
    };
}

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

const storedCredential: StoredPasskeyCredential = {
    id: "cred-id-1",
    uid: "user-uid-1",
    publicKey: new Uint8Array([1, 2, 3]),
    counter: 5,
    transports: ["usb"],
};

describe("FIDO2Strategy Tests", () => {
    let options: FIDO2StrategyOptions;
    let strategy: FIDO2Strategy;

    beforeEach(() => {
        options = new FIDO2StrategyOptions(makeConfig());
        options.getCredentialById = vi.fn();
        options.getCredentials = vi.fn();
        options.updateCredentialCounter = vi.fn();
        options.getUser = vi.fn();
        strategy = new FIDO2Strategy(options);
    });

    describe("Begin (phase 1)", () => {
        it("Generates options with no allowCredentials when no uid hint is given.", async () => {
            const req = makeReq({ query: {} });
            const res = makeRes();
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123", rpId: "example.com" });

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(mockGenerateAuthenticationOptions).toHaveBeenCalledWith({
                rpID: "example.com",
                allowCredentials: undefined,
                userVerification: undefined,
                timeout: undefined,
            });
            expect((req.session as any).challenge).toBe("chal-123");
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ challenge: "chal-123", rpId: "example.com" });
            expect(options.getCredentials).not.toHaveBeenCalled();
        });

        it("Builds allowCredentials from getCredentials when a uid hint has registered credentials.", async () => {
            const req = makeReq({ query: { uid: "user-uid-1" } });
            const res = makeRes();
            (options.getCredentials as any).mockResolvedValue([storedCredential]);
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-456" });

            await strategy.authenticate(req, res);

            expect(options.getCredentials).toHaveBeenCalledWith("user-uid-1");
            expect(mockGenerateAuthenticationOptions).toHaveBeenCalledWith(
                expect.objectContaining({
                    allowCredentials: [{ id: "cred-id-1", transports: ["usb"] }],
                }),
            );
        });

        it("Leaves allowCredentials undefined (not an empty array) when a uid hint has zero credentials.", async () => {
            const req = makeReq({ query: { uid: "user-with-no-keys" } });
            const res = makeRes();
            (options.getCredentials as any).mockResolvedValue([]);
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-789" });

            await strategy.authenticate(req, res);

            expect(mockGenerateAuthenticationOptions).toHaveBeenCalledWith(
                expect.objectContaining({ allowCredentials: undefined }),
            );
        });

        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ session: undefined });
            const res = makeRes();
            await expect(strategy.authenticate(req, res)).rejects.toThrow(/session support/);
        });

        it("Throws if res is missing.", async () => {
            const req = makeReq({ query: {} });
            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/response object/);
        });

        it("Invokes checkRateLimit with the uid hint when one is given.", async () => {
            const req = makeReq({ query: { uid: "user-uid-1" } });
            const res = makeRes();
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            (options.getCredentials as any).mockResolvedValue([]);
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });

            await strategy.authenticate(req, res);

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        it("Does not invoke checkRateLimit for the discoverable/no-hint flow.", async () => {
            const req = makeReq({ query: {} });
            const res = makeRes();
            options.checkRateLimit = vi.fn();
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });

            await strategy.authenticate(req, res);

            expect(options.checkRateLimit).not.toHaveBeenCalled();
        });

        it("Aborts before getCredentials() when checkRateLimit throws.", async () => {
            const req = makeReq({ query: { uid: "user-uid-1" } });
            const res = makeRes();
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, res)).rejects.toThrow(/Too many attempts/);
            expect(options.getCredentials).not.toHaveBeenCalled();
        });
    });

    describe("Finish (phase 2)", () => {
        it("Verifies successfully, updates the counter, clears the session challenge, and returns the AuthResult.", async () => {
            const body = makeAssertionBody();
            const req = makeReq({ body, session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            const jwtUser: JWTUser = { uid: "user-uid-1", name: "test", roles: [] };
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, undefined as any);

            expect(options.getCredentialById).toHaveBeenCalledWith("cred-id-1");
            expect(mockVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response: body,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: {
                    id: "cred-id-1",
                    counter: 5,
                    publicKey: storedCredential.publicKey,
                    transports: ["usb"],
                },
                requireUserVerification: true,
            });
            expect(options.updateCredentialCounter).toHaveBeenCalledWith("cred-id-1", 6);
            expect((req.session as any).challenge).toBeUndefined();
            expect(result).toEqual({
                data: body,
                method: "fido2",
                payload: { newCounter: 6, credentialID: "cred-id-1" },
                user: jwtUser,
            });
        });

        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: undefined });
            // Regression: this is a deployment misconfiguration, not a client-caused auth failure - it
            // must surface as a distinguishable 500, not get flattened into a generic 401.
            await expect(strategy.authenticate(req, undefined as any)).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/session support/),
            });
            expect(options.getCredentialById).not.toHaveBeenCalled();
        });

        it("Throws if there is no challenge stored in the session.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: {} });
            // Regression: an out-of-sequence verify call is malformed client input, not an auth failure -
            // it must surface as a 400, not get flattened into a generic 401.
            await expect(strategy.authenticate(req, undefined as any)).rejects.toMatchObject({
                status: 400,
                message: expect.stringMatching(/No FIDO2 ceremony/),
            });
            expect(options.getCredentialById).not.toHaveBeenCalled();
        });

        it("Throws on a malformed response body without calling storage or SimpleWebAuthn.", async () => {
            const req = makeReq({
                body: { id: "cred-id-1", response: { clientDataJSON: "x" } }, // missing authenticatorData/signature
                session: { challenge: "stored-challenge" },
            });
            await expect(strategy.authenticate(req, undefined as any)).rejects.toMatchObject({
                status: 400,
                message: expect.stringMatching(/Malformed/),
            });
            expect(options.getCredentialById).not.toHaveBeenCalled();
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Throws a generic failure on an unknown credential ID without calling verifyAuthenticationResponse.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/authentication failed/i);
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Invokes checkRateLimit with the credential id after shape validation succeeds.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            (options.getUser as any).mockResolvedValue({ uid: "user-uid-1", name: "test", roles: [] });

            await strategy.authenticate(req, undefined as any);

            expect(options.checkRateLimit).toHaveBeenCalledWith("cred-id-1", req);
        });

        it("Aborts before getCredentialById() when checkRateLimit throws.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/Too many attempts/);
            expect(options.getCredentialById).not.toHaveBeenCalled();
        });

        it("Throws a generic failure when verification resolves verified: false, without updating the counter.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({ verified: false, authenticationInfo: undefined });

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/authentication failed/i);
            expect(options.updateCredentialCounter).not.toHaveBeenCalled();
        });

        it("Clears the session challenge before verification is attempted, even on failure.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow();
            expect((req.session as any).challenge).toBeUndefined();
        });

        it("Rejects a non-finite stored counter as an invalid credential.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue({ ...storedCredential, counter: NaN });

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/invalid counter/);
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Propagates a thrown/rejected verifyAuthenticationResponse error without updating the counter.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockRejectedValue(new Error("origin mismatch"));

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/origin mismatch/);
            expect(options.updateCredentialCounter).not.toHaveBeenCalled();
        });

        it("Rejects a non-zero counter that does not exceed the stored counter (cloned authenticator), without updating.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential); // counter: 5
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 5, credentialID: "cred-id-1" }, // did not increase
            });

            await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/authentication failed/i);
            expect(options.updateCredentialCounter).not.toHaveBeenCalled();
        });

        it("Accepts a newCounter of 0 despite not exceeding the stored counter.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential); // counter: 5
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 0, credentialID: "cred-id-1" },
            });
            const jwtUser: JWTUser = { uid: "user-uid-1", name: "test", roles: [] };
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, undefined as any);

            expect(options.updateCredentialCounter).toHaveBeenCalledWith("cred-id-1", 0);
            expect(result?.user).toEqual(jwtUser);
        });

        it("Returns undefined (does not throw) when verify() resolves undefined and auth is not required.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            (options.getUser as any).mockResolvedValue(undefined);

            const result = await strategy.authenticate(req, undefined as any, false);

            expect(options.updateCredentialCounter).toHaveBeenCalledWith("cred-id-1", 6);
            expect(result).toBeUndefined();
        });

        it("Throws when verify() resolves undefined and auth is required.", async () => {
            const req = makeReq({ body: makeAssertionBody(), session: { challenge: "stored-challenge" } });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            (options.getUser as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, undefined as any, true)).rejects.toThrow(/authentication failed/i);
        });
    });

    it("authenticateSync throws 'Not supported'.", () => {
        const req = makeReq();
        const res = makeRes();
        expect(() => strategy.authenticateSync(req, res)).toThrow(/Not supported/);
    });

    it("Dispatches to verify() when the body has a response but no id.", async () => {
        const req = makeReq({ body: { response: {} }, session: { challenge: "stored-challenge" } });

        await expect(strategy.authenticate(req, undefined as any)).rejects.toThrow(/Malformed/);
        expect(options.getCredentialById).not.toHaveBeenCalled();
    });

    describe("Default FIDO2StrategyOptions", () => {
        const defaultOptions = new FIDO2StrategyOptions(makeConfig());

        it("getCredentialById throws if the consumer forgot to override it.", async () => {
            await expect(defaultOptions.getCredentialById("cred-id-1")).rejects.toThrow(
                /Did you forget to override FIDO2StrategyOptions.getCredentialById/,
            );
        });

        it("getCredentials throws if the consumer forgot to override it.", async () => {
            await expect(defaultOptions.getCredentials("user-uid-1")).rejects.toThrow(
                /Did you forget to override FIDO2StrategyOptions.getCredentials/,
            );
        });

        it("updateCredentialCounter throws if the consumer forgot to override it.", async () => {
            await expect(defaultOptions.updateCredentialCounter("cred-id-1", 1)).rejects.toThrow(
                /Did you forget to override FIDO2StrategyOptions.updateCredentialCounter/,
            );
        });

        it("getUser throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getUser("user-uid-1")).toThrow(
                /Did you forget to override FIDO2StrategyOptions.getUser/,
            );
        });
    });
});

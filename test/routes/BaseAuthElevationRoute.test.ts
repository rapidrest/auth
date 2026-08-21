///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthElevationRoute — no HTTP server, no database. Only the external
// WebAuthn ceremony library is mocked (matching test/auth/MFAStrategy.test.ts); OTP/TOTP verification
// runs through the real shared.ts helpers.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
}));

import type { JWTUser } from "@rapidrest/core";
import { RepoUtils, type HttpRequest, type HttpResponse } from "@rapidrest/service-core";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import * as otplib from "otplib";
import { MFAMethod, MFAMethodType } from "../../src/auth/MFAStrategy.js";
import { BaseAuthElevationRoute } from "../../src/routes/BaseAuthElevationRoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { AliasType, SecretType } from "../../src/models/types.js";
import { OTPContactType, PasskeyConfig, StoredPasskeyCredential } from "../../src/auth/types.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as any;
const mockVerifyAuthenticationResponse = verifyAuthenticationResponse as any;

class FakeSecretClass {
    static readonly name = "FakeSecret";
}
class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeAliasClass {
    static readonly name = "FakeAlias";
}

class TestAuthElevationRoute extends BaseAuthElevationRoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(aliasRepo: any, secretRepo: any, userRepo: any, userUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeSecretClass.name) return secretRepo;
            if (opts.name === FakeUserClass.name) return userRepo;
            return undefined;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        return undefined;
    });
    return { newInstance };
}

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "POST",
        path: "/auth/elevate",
        url: "/auth/elevate",
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
        appendHeader: vi.fn().mockReturnThis(),
        getHeader: vi.fn(),
        json: vi.fn(),
        send: vi.fn(),
        end: vi.fn(),
        onFinish: vi.fn(),
    };
}

function makeFidoConfig(overrides: Partial<PasskeyConfig> = {}): PasskeyConfig {
    return {
        rpName: "Test RP",
        rpID: "example.com",
        origin: "https://example.com",
        ...overrides,
    };
}

const jwtUser: JWTUser = { uid: "user-uid-1", roles: [] };

const storedCredential: StoredPasskeyCredential = {
    id: "cred-id-1",
    uid: "user-uid-1",
    publicKey: new Uint8Array([1, 2, 3]),
    counter: 5,
    transports: ["usb"],
};

function makeAssertionBody(overrides: any = {}): any {
    return {
        id: "cred-id-1",
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

describe("BaseAuthElevationRoute Tests", () => {
    beforeEach(() => {
        mockGenerateAuthenticationOptions.mockReset();
        mockVerifyAuthenticationResponse.mockReset();
    });

    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestAuthElevationRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Does not recreate repos/utils if initialize() runs again.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).objectFactory = makeMockObjectFactory({}, {}, {}, {});
            const existingAliasRepo = { find: vi.fn() };
            const existingSecretRepo = { find: vi.fn() };
            const existingUserRepo = { find: vi.fn() };
            const existingUserUtils = { lookup: vi.fn() };
            (route as any).aliasRepo = existingAliasRepo;
            (route as any).secretRepo = existingSecretRepo;
            (route as any).userRepo = existingUserRepo;
            (route as any).userUtils = existingUserUtils;

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(existingAliasRepo);
            expect((route as any).secretRepo).toBe(existingSecretRepo);
            expect((route as any).userRepo).toBe(existingUserRepo);
            expect((route as any).userUtils).toBe(existingUserUtils);
        });
    });

    describe("listMethods", () => {
        it("Delegates to getMethods() scoped to the authenticated caller's own uid.", async () => {
            const route = new TestAuthElevationRoute();
            const getMethodsSpy = vi.spyOn(route as any, "getMethods").mockResolvedValue([]);

            const result = await route.listMethods(jwtUser);

            expect(getMethodsSpy).toHaveBeenCalledWith("user-uid-1");
            expect(result).toEqual([]);
        });
    });

    describe("elevate (dispatch)", () => {
        it("Throws INTERNAL_ERROR when tokenUtils is not set.", async () => {
            const route = new TestAuthElevationRoute();
            const req = makeReq();

            await expect(route.elevate({}, jwtUser, req, makeRes())).rejects.toThrow(/internal error/i);
        });

        it("Throws when req.session is missing (session support required).", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn() };
            const req = makeReq({ session: undefined });

            await expect(route.elevate({}, jwtUser, req, makeRes())).rejects.toThrow(/session support/);
        });

        it("Rate limits keyed on the authenticated caller's own uid, never anything client-supplied.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn() };
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            const req = makeReq({ body: { id: "attacker-controlled-id", password: "x" } });
            vi.spyOn(route as any, "verifyPasswordOnly").mockResolvedValue(undefined);

            await expect(route.elevate({ id: "attacker-controlled-id", password: "x" }, jwtUser, req, makeRes())).rejects.toThrow();

            expect(checkAndIncrement).toHaveBeenCalledWith("elevate:user-uid-1");
        });

        it("Ignores a client-supplied `id` in the body, forcing the authenticated caller's own uid.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn() };
            const beginChallengeSpy = vi.spyOn(route as any, "beginChallenge").mockResolvedValue({});
            const req = makeReq({ body: { id: "attacker-controlled-id", methodId: "method-1" } });

            await route.elevate({ id: "attacker-controlled-id", methodId: "method-1" }, jwtUser, req, makeRes());

            expect(beginChallengeSpy).toHaveBeenCalledWith("method-1", jwtUser, req);
        });

        it("Routes a `methodId` payload to beginChallenge() and returns its result directly, without minting a token.", async () => {
            const route = new TestAuthElevationRoute();
            const createAuthResult = vi.fn();
            (route as any).tokenUtils = { createAuthResult };
            vi.spyOn(route as any, "beginChallenge").mockResolvedValue({ challenge: "chal-123" });
            const req = makeReq({ body: { methodId: "method-1" } });

            const result = await route.elevate({ methodId: "method-1" }, jwtUser, req, makeRes());

            expect(result).toEqual({ challenge: "chal-123" });
            expect(createAuthResult).not.toHaveBeenCalled();
        });

        it("Routes an OTP-shaped payload (token, no session mfaMethodId) to verifyOTPChallenge.", async () => {
            const route = new TestAuthElevationRoute();
            const createAuthResult = vi.fn().mockResolvedValue({ token: "tok" });
            (route as any).tokenUtils = { createAuthResult };
            const verifyOTPChallengeSpy = vi.spyOn(route as any, "verifyOTPChallenge").mockResolvedValue(jwtUser);
            const req = makeReq({ body: { token: "123456" }, session: {} });
            const res = makeRes();

            const result = await route.elevate({ token: "123456" }, jwtUser, req, res);

            expect(verifyOTPChallengeSpy).toHaveBeenCalledWith({ id: "user-uid-1", token: "123456" }, req);
            expect(createAuthResult).toHaveBeenCalledWith(jwtUser, [], req, res, true);
            expect(result).toEqual({ token: "tok" });
        });

        it("Routes an OTP-shaped payload to verifyTOTPChallenge instead when session.mfaMethodId is set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn().mockResolvedValue({}) };
            const verifyTOTPChallengeSpy = vi.spyOn(route as any, "verifyTOTPChallenge").mockResolvedValue(jwtUser);
            const verifyOTPChallengeSpy = vi.spyOn(route as any, "verifyOTPChallenge");
            const req = makeReq({ body: { token: "123456" }, session: { mfaMethodId: "secret-1" } });

            await route.elevate({ token: "123456" }, jwtUser, req, makeRes());

            expect(verifyTOTPChallengeSpy).toHaveBeenCalled();
            expect(verifyOTPChallengeSpy).not.toHaveBeenCalled();
        });

        it("Routes a passkey-shaped payload to verifyFIDOChallenge.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn().mockResolvedValue({}) };
            const verifyFIDOChallengeSpy = vi.spyOn(route as any, "verifyFIDOChallenge").mockResolvedValue(jwtUser);
            const req = makeReq({ body: makeAssertionBody() });

            await route.elevate(makeAssertionBody(), jwtUser, req, makeRes());

            expect(verifyFIDOChallengeSpy).toHaveBeenCalled();
        });

        it("Routes a `password` payload to verifyPasswordOnly.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn().mockResolvedValue({}) };
            const verifyPasswordOnlySpy = vi.spyOn(route as any, "verifyPasswordOnly").mockResolvedValue(jwtUser);
            const req = makeReq({ body: { password: "hunter2" } });

            await route.elevate({ password: "hunter2" }, jwtUser, req, makeRes());

            expect(verifyPasswordOnlySpy).toHaveBeenCalledWith(jwtUser, "hunter2");
        });

        it("Throws INVALID_REQUEST when the payload matches no known shape.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn() };
            const req = makeReq({ body: {} });

            await expect(route.elevate({}, jwtUser, req, makeRes())).rejects.toThrow(/Invalid elevation request/);
        });

        it("Throws AUTH_FAILED when verification resolves undefined (wrong password/code/assertion).", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn() };
            vi.spyOn(route as any, "verifyPasswordOnly").mockResolvedValue(undefined);
            const req = makeReq({ body: { password: "wrong" } });

            await expect(route.elevate({ password: "wrong" }, jwtUser, req, makeRes())).rejects.toThrow(
                /Invalid or missing authentication token|auth/i,
            );
        });

        it("Mints an elevated AuthResult (elevated: true) on successful verification.", async () => {
            const route = new TestAuthElevationRoute();
            const createAuthResult = vi.fn().mockResolvedValue({ token: "tok", refresh: "ref", user: jwtUser });
            (route as any).tokenUtils = { createAuthResult };
            (route as any).defaultScopes = ["profile"];
            vi.spyOn(route as any, "verifyPasswordOnly").mockResolvedValue(jwtUser);
            const req = makeReq({ body: { password: "correct" } });
            const res = makeRes();

            const result = await route.elevate({ password: "correct" }, jwtUser, req, res);

            expect(createAuthResult).toHaveBeenCalledWith(jwtUser, ["profile"], req, res, true);
            expect(result).toEqual({ token: "tok", refresh: "ref", user: jwtUser });
        });
    });

    describe("beginChallenge", () => {
        it("Throws INVALID_REQUEST when the method does not resolve (not found, or belongs to another user).", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue(undefined);
            const req = makeReq({ session: {} });

            await expect((route as any).beginChallenge("bogus", jwtUser, req)).rejects.toThrow(
                /Invalid secondary authentication method/,
            );
        });

        it("Generates a FIDO2 challenge scoped to the selected credential and records session state.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({
                id: "method-1",
                type: MFAMethodType.FIDO2,
                data: { id: "cred-id-1", transports: ["usb"] },
            });
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });
            const req = makeReq({ session: {} });

            const result = await (route as any).beginChallenge("method-1", jwtUser, req);

            expect(mockGenerateAuthenticationOptions).toHaveBeenCalledWith(
                expect.objectContaining({ allowCredentials: [{ id: "cred-id-1", transports: ["usb"] }] }),
            );
            expect(result).toEqual({ challenge: "chal-123" });
            // Recorded under a route-local `elevateUid` field, deliberately distinct from the shared
            // `session.userUid` that TokenUtils/BaseAuthRefreshRoute use to track the caller's actual
            // logged-in identity (see the "does not touch session.userUid" regression tests below).
            expect((req.session as any).elevateUid).toBe("user-uid-1");
            expect((req.session as any).userUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBe("method-1");
        });

        it("Sends an OTP notification and records session state, without a challenge in the response.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({
                id: "method-1",
                type: MFAMethodType.OTP,
                data: { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true },
            });
            const notifyContactSpy = vi.spyOn(route as any, "notifyContact").mockResolvedValue(undefined);
            const req = makeReq({ session: { mfaMethodId: "stale-totp-id" } });

            const result = await (route as any).beginChallenge("method-1", jwtUser, req);

            expect(result).toEqual({});
            expect(notifyContactSpy).toHaveBeenCalled();
            expect((req.session as any).elevateUid).toBe("user-uid-1");
            // Clears any stale mfaMethodId left over from a previous TOTP/FIDO2 selection.
            expect((req.session as any).mfaMethodId).toBeUndefined();
        });

        it("Acknowledges a TOTP method selection without sending a notification, and records the method id.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({ id: "method-1", type: MFAMethodType.TOTP, data: {} });
            const notifyContactSpy = vi.spyOn(route as any, "notifyContact");
            const req = makeReq({ session: {} });

            const result = await (route as any).beginChallenge("method-1", jwtUser, req);

            expect(result).toEqual({});
            expect(notifyContactSpy).not.toHaveBeenCalled();
            expect((req.session as any).elevateUid).toBe("user-uid-1");
            expect((req.session as any).mfaMethodId).toBe("method-1");
        });

        it("Throws INVALID_REQUEST for an unsupported method type.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({ id: "method-1", type: "unknown", data: {} });
            const req = makeReq({ session: {} });

            await expect((route as any).beginChallenge("method-1", jwtUser, req)).rejects.toThrow(
                /Unsupported elevation method/,
            );
        });

        // Regression: beginChallenge() used to write the caller's uid into the shared `session.userUid`
        // field — the same field TokenUtils/BaseAuthRefreshRoute rely on to identify the caller's actual
        // logged-in session for refresh-token validation. Starting (or failing) an elevation challenge
        // must never disturb that field.
        it("Never writes to the shared session.userUid field used by the login/refresh flow.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({ id: "method-1", type: MFAMethodType.TOTP, data: {} });
            const req = makeReq({ session: { userUid: "user-uid-1", refreshUid: "refresh-uid-1" } });

            await (route as any).beginChallenge("method-1", jwtUser, req);

            expect((req.session as any).userUid).toBe("user-uid-1");
            expect((req.session as any).refreshUid).toBe("refresh-uid-1");
        });
    });

    describe("verifyOTPChallenge", () => {
        it("Resolves the user via the session-bound identity, and clears it after, on a valid token.", async () => {
            const route = new TestAuthElevationRoute();
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const getUserSpy = vi.spyOn(route as any, "getUser").mockResolvedValue(jwtUser);
            const req = makeReq({ session: { id: "user-uid-1", secret, elevateUid: "user-uid-1" } });

            const result = await (route as any).verifyOTPChallenge({ id: "user-uid-1", token }, req);

            expect(getUserSpy).toHaveBeenCalledWith("user-uid-1");
            expect(result).toEqual(jwtUser);
            expect((req.session as any).elevateUid).toBeUndefined();
        });

        it("Returns undefined and clears session state when the token is invalid.", async () => {
            const route = new TestAuthElevationRoute();
            const getUserSpy = vi.spyOn(route as any, "getUser");
            const req = makeReq({
                session: { id: "user-uid-1", secret: otplib.generateSecret(), elevateUid: "user-uid-1" },
            });

            const result = await (route as any).verifyOTPChallenge({ id: "user-uid-1", token: "000000" }, req);

            expect(result).toBeUndefined();
            expect(getUserSpy).not.toHaveBeenCalled();
            expect((req.session as any).elevateUid).toBeUndefined();
        });

        // Regression: this used to clear the shared `session.userUid` field regardless of outcome. Since
        // BaseAuthElevationRoute runs on an already-authenticated session with a live refresh token bound
        // to that same field (see BaseAuthRefreshRoute.authenticate()), a failed elevation attempt used to
        // silently strand the caller's refresh token — the very next refresh would 401 even though nothing
        // was wrong with their login. The fix moved this route's own challenge-binding state to a
        // dedicated `elevateUid` field, so `session.userUid` must never be touched here, on success or
        // failure.
        it("Does not touch the shared session.userUid field, even on a failed verification.", async () => {
            const route = new TestAuthElevationRoute();
            const req = makeReq({
                session: {
                    id: "user-uid-1",
                    secret: otplib.generateSecret(),
                    elevateUid: "user-uid-1",
                    userUid: "user-uid-1",
                    refreshUid: "refresh-uid-1",
                },
            });

            await (route as any).verifyOTPChallenge({ id: "user-uid-1", token: "000000" }, req);

            expect((req.session as any).userUid).toBe("user-uid-1");
            expect((req.session as any).refreshUid).toBe("refresh-uid-1");
        });
    });

    describe("verifyTOTPChallenge", () => {
        it("Verifies against the selected TOTP secret, persists the time step, and resolves the user.", async () => {
            const route = new TestAuthElevationRoute();
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            vi.spyOn(route as any, "getMethod").mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.TOTP,
                data: { secret },
            });
            const getUserSpy = vi.spyOn(route as any, "getUser").mockResolvedValue(jwtUser);
            const updateSecretTimeStepSpy = vi.spyOn(route as any, "updateSecretTimeStep").mockResolvedValue(undefined);
            const req = makeReq({ session: { elevateUid: "user-uid-1", mfaMethodId: "secret-1" } });

            const result = await (route as any).verifyTOTPChallenge({ id: "user-uid-1", token }, req);

            expect(getUserSpy).toHaveBeenCalledWith("user-uid-1");
            expect(updateSecretTimeStepSpy).toHaveBeenCalledWith("secret-1", expect.any(Number));
            expect(result).toEqual(jwtUser);
            expect((req.session as any).elevateUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
        });

        it("Returns undefined when there is no session-bound challenge state (cold request).", async () => {
            const route = new TestAuthElevationRoute();
            const req = makeReq({ session: {} });

            const result = await (route as any).verifyTOTPChallenge({ id: "user-uid-1", token: "123456" }, req);

            expect(result).toBeUndefined();
        });

        it("Returns undefined when the selected method is no longer a TOTP method.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({ id: "secret-1", type: MFAMethodType.OTP, data: {} });
            const req = makeReq({ session: { elevateUid: "user-uid-1", mfaMethodId: "secret-1" } });

            const result = await (route as any).verifyTOTPChallenge({ id: "user-uid-1", token: "123456" }, req);

            expect(result).toBeUndefined();
        });

        it("Returns undefined when the token does not verify.", async () => {
            const route = new TestAuthElevationRoute();
            const secret = otplib.generateSecret();
            vi.spyOn(route as any, "getMethod").mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: { secret } });
            const req = makeReq({ session: { elevateUid: "user-uid-1", mfaMethodId: "secret-1" } });

            const result = await (route as any).verifyTOTPChallenge({ id: "user-uid-1", token: "000000" }, req);

            expect(result).toBeUndefined();
        });

        it("Does not touch the shared session.userUid field, even on a failed verification.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethod").mockResolvedValue(undefined);
            const req = makeReq({
                session: {
                    elevateUid: "user-uid-1",
                    mfaMethodId: "secret-1",
                    userUid: "user-uid-1",
                    refreshUid: "refresh-uid-1",
                },
            });

            await (route as any).verifyTOTPChallenge({ id: "user-uid-1", token: "000000" }, req);

            expect((req.session as any).userUid).toBe("user-uid-1");
            expect((req.session as any).refreshUid).toBe("refresh-uid-1");
        });
    });

    describe("verifyFIDOChallenge", () => {
        function makeFidoSessionReq(overrides: any = {}): HttpRequest {
            return makeReq({
                session: {
                    elevateUid: "user-uid-1",
                    mfaMethodId: "cred-id-1",
                    challenge: "stored-challenge",
                    ...overrides,
                },
            });
        }

        it("Verifies successfully, updates the counter, clears session state, and resolves the user.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getCredentialById").mockResolvedValue(storedCredential);
            const updateCredentialCounterSpy = vi.spyOn(route as any, "updateCredentialCounter").mockResolvedValue(undefined);
            const getUserSpy = vi.spyOn(route as any, "getUser").mockResolvedValue(jwtUser);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            const req = makeFidoSessionReq();

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(updateCredentialCounterSpy).toHaveBeenCalledWith("cred-id-1", 6);
            expect(getUserSpy).toHaveBeenCalledWith("user-uid-1");
            expect(result).toEqual(jwtUser);
            expect((req.session as any).elevateUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).challenge).toBeUndefined();
        });

        it("Does not touch the shared session.userUid field, even on a failed verification.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getCredentialById").mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({ verified: false });
            const req = makeFidoSessionReq({ userUid: "user-uid-1", refreshUid: "refresh-uid-1" });

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(result).toBeUndefined();
            expect((req.session as any).userUid).toBe("user-uid-1");
            expect((req.session as any).refreshUid).toBe("refresh-uid-1");
        });

        it("Returns undefined when there is no session-bound challenge state (cold request).", async () => {
            const route = new TestAuthElevationRoute();
            const req = makeReq({ session: {} });

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(result).toBeUndefined();
        });

        it("Returns undefined when the resolved credential does not match the one selected during the challenge.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getCredentialById").mockResolvedValue(storedCredential);
            const req = makeFidoSessionReq({ mfaMethodId: "some-other-cred" });

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(result).toBeUndefined();
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Returns undefined when the resolved credential belongs to a different user (regression guard: never trust a client-supplied credential owner).", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getCredentialById").mockResolvedValue({ ...storedCredential, uid: "someone-else" });
            const req = makeFidoSessionReq();

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(result).toBeUndefined();
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Returns undefined on a regressed (cloned authenticator) counter.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).fido2Config = makeFidoConfig();
            vi.spyOn(route as any, "getCredentialById").mockResolvedValue(storedCredential);
            const updateCredentialCounterSpy = vi.spyOn(route as any, "updateCredentialCounter");
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 5, credentialID: "cred-id-1" },
            });
            const req = makeFidoSessionReq();

            const result = await (route as any).verifyFIDOChallenge(makeAssertionBody(), req);

            expect(result).toBeUndefined();
            expect(updateCredentialCounterSpy).not.toHaveBeenCalled();
        });
    });

    describe("verifyPasswordOnly", () => {
        it("Throws INVALID_REQUEST when the caller has a secondary method enrolled — password alone is not accepted.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethods").mockResolvedValue([
                { id: "method-1", type: MFAMethodType.TOTP, data: {} },
            ]);
            const verifySpy = vi.spyOn(route as any, "verify");

            await expect((route as any).verifyPasswordOnly(jwtUser, "correct")).rejects.toThrow(
                /must be used instead of a password/,
            );
            expect(verifySpy).not.toHaveBeenCalled();
        });

        it("Delegates to verify() scoped to the caller's own uid when no secondary method is enrolled.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethods").mockResolvedValue([]);
            const verifySpy = vi.spyOn(route as any, "verify").mockResolvedValue(jwtUser);

            const result = await (route as any).verifyPasswordOnly(jwtUser, "correct");

            expect(verifySpy).toHaveBeenCalledWith("user-uid-1", "correct");
            expect(result).toEqual(jwtUser);
        });

        it("Returns undefined (rather than propagating) when verify() throws on a wrong password.", async () => {
            const route = new TestAuthElevationRoute();
            vi.spyOn(route as any, "getMethods").mockResolvedValue([]);
            vi.spyOn(route as any, "verify").mockRejectedValue(new Error("Invalid authorization request."));

            const result = await (route as any).verifyPasswordOnly(jwtUser, "wrong");

            expect(result).toBeUndefined();
        });
    });

    describe("convertAliasToMethod", () => {
        it("Converts an EMAIL alias into an OTP method.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "user@example.com",
                type: AliasType.EMAIL,
                verified: true,
            });

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "user@example.com", type: OTPContactType.EMAIL, verified: true },
                type: MFAMethodType.OTP,
            });
        });

        it("Returns undefined for an alias type that has no OTP equivalent.", () => {
            const route = new TestAuthElevationRoute();
            // `verified: true` so this exercises the switch's fallthrough (no case for NAME), not the
            // unverified early-return guarded by the tests below.
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "John Doe",
                type: AliasType.NAME,
                verified: true,
            });

            expect(result).toBeUndefined();
        });

        it("Converts a PHONE alias into an OTP method.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "+15551234567",
                type: AliasType.PHONE,
                verified: true,
            });

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "+15551234567", type: OTPContactType.SMS, verified: true },
                type: MFAMethodType.OTP,
            });
        });

        it("Obfuscates the contact for a PHONE alias when obfuscate is true.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertAliasToMethod(
                {
                    uid: "alias-1",
                    alias: "+15551234567",
                    type: AliasType.PHONE,
                    verified: true,
                },
                true,
            );

            expect(result?.data.contact).toBe((route as any).obfuscateAlias("+15551234567", AliasType.PHONE));
            expect(result?.data.contact).not.toBe("+15551234567");
        });

        // Regression: an elevation method must be a *proven* point of contact. Without this check, a
        // caller holding only a non-elevated (possibly stolen) access token could add a brand-new,
        // self-controlled, unverified email/phone alias via BaseAliasRoute.create() (which requires no
        // elevation), then use it as an elevation method to receive and submit a real OTP code —
        // obtaining a fully elevated token without ever proving anything beyond holding that token.
        it("Returns undefined for an unverified EMAIL alias, even though it would otherwise convert.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "attacker@evil.com",
                type: AliasType.EMAIL,
                verified: false,
            });

            expect(result).toBeUndefined();
        });

        it("Returns undefined for an unverified PHONE alias, even though it would otherwise convert.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "+15551234567",
                type: AliasType.PHONE,
                verified: false,
            });

            expect(result).toBeUndefined();
        });
    });

    describe("convertSecretToMethod", () => {
        it("Converts a FIDO2 secret into a FIDO2 method.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.FIDO2,
                data: { id: "cred-1" },
            });

            expect(result).toEqual({ id: "secret-1", data: { id: "cred-1" }, type: MFAMethodType.FIDO2 });
        });

        it("Converts a TOTP secret into a TOTP method.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.TOTP,
                data: { secret: "AAAA" },
            });

            expect(result).toEqual({ id: "secret-1", data: { secret: "AAAA" }, type: MFAMethodType.TOTP });
        });

        it("Returns undefined for a secret type that has no elevation equivalent.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.PASSWORD,
                data: "hash",
            });

            expect(result).toBeUndefined();
        });
    });

    describe("getCredentialById", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();

            await expect((route as any).getCredentialById("cred-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns undefined when the matching secret is not of type FIDO2.", async () => {
            const route = new TestAuthElevationRoute();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.TOTP, data: { secret: "AAAA" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(result).toBeUndefined();
        });

        it("Returns the .data of a matching secret of type FIDO2.", async () => {
            const route = new TestAuthElevationRoute();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.FIDO2, data: { id: "cred-1" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(result).toEqual({ id: "cred-1" });
        });

        it("Returns undefined without querying the repo when credentialId is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthElevationRoute();
            const findOne = vi.fn();
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById({ $ne: null });

            expect(result).toBeUndefined();
            expect(findOne).not.toHaveBeenCalled();
        });
    });

    describe("getMethod", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { findOne: vi.fn() };

            await expect((route as any).getMethod("id-1", "user-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).aliasRepo = { findOne: vi.fn() };

            await expect((route as any).getMethod("id-1", "user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns undefined without querying either repo when id or userUid is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthElevationRoute();
            const secretFindOne = vi.fn();
            const aliasFindOne = vi.fn();
            (route as any).secretRepo = { findOne: secretFindOne };
            (route as any).aliasRepo = { findOne: aliasFindOne };

            const result = await (route as any).getMethod({ $ne: null }, "user-1");

            expect(result).toBeUndefined();
            expect(secretFindOne).not.toHaveBeenCalled();
            expect(aliasFindOne).not.toHaveBeenCalled();
        });

        it("Returns undefined when neither a matching secret nor a matching alias exists.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = { findOne: vi.fn().mockResolvedValue(undefined) };

            const result = await (route as any).getMethod("bogus-id", "user-1");

            expect(result).toBeUndefined();
        });

        it("Returns undefined when the matching secret belongs to a different user.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = {
                findOne: vi.fn().mockResolvedValue({ uid: "secret-1", userUid: "attacker-1", type: SecretType.TOTP, data: {} }),
            };
            (route as any).aliasRepo = { findOne: vi.fn() };

            const result = await (route as any).getMethod("secret-1", "victim-1");

            expect(result).toBeUndefined();
        });

        it("Returns the method for a matching secret owned by the given uid.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = {
                findOne: vi
                    .fn()
                    .mockResolvedValue({ uid: "secret-1", userUid: "user-1", type: SecretType.TOTP, data: {} }),
            };
            (route as any).aliasRepo = { findOne: vi.fn() };

            const result = await (route as any).getMethod("secret-1", "user-1");

            expect(result).toEqual({ id: "secret-1", data: {}, type: MFAMethodType.TOTP });
        });

        it("Returns the method for a matching, verified alias owned by the given uid.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    userUid: "user-1",
                    alias: "user@example.com",
                    type: AliasType.EMAIL,
                    verified: true,
                }),
            };

            const result = await (route as any).getMethod("alias-1", "user-1");

            expect(result?.type).toBe(MFAMethodType.OTP);
        });

        // Regression guard for the same fix as convertAliasToMethod's — getMethod() is the path
        // beginChallenge() actually calls, so this is what a direct exploit attempt would hit.
        it("Returns undefined for a matching but unverified alias, even when owned by the given uid.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    userUid: "user-1",
                    alias: "attacker@evil.com",
                    type: AliasType.EMAIL,
                    verified: false,
                }),
            };

            const result = await (route as any).getMethod("alias-1", "user-1");

            expect(result).toBeUndefined();
        });
    });

    describe("getMethods", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userRepo = {};

            await expect((route as any).getMethods("user-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).aliasRepo = { find: vi.fn() };
            (route as any).userRepo = {};

            await expect((route as any).getMethods("user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Throws if userRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).aliasRepo = { find: vi.fn() };
            (route as any).secretRepo = { find: vi.fn() };

            await expect((route as any).getMethods("user-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Combines eligible secrets and aliases into a list of methods.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "secret-1", type: SecretType.TOTP, data: {} },
                    { uid: "secret-2", type: SecretType.PASSWORD, data: "hash" },
                ]),
            };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "user@example.com", type: AliasType.EMAIL, verified: true },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(2);
            expect(result[0]).toEqual({ id: "secret-1", data: {}, type: MFAMethodType.TOTP });
            expect(result[1].type).toBe(MFAMethodType.OTP);
        });

        // Regression: an unverified alias must never be offered as an elevation method — see
        // convertAliasToMethod's regression test for the full exploit this closes.
        it("Excludes unverified aliases from the list of methods.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "verified@example.com", type: AliasType.EMAIL, verified: true },
                    { uid: "alias-2", alias: "attacker@evil.com", type: AliasType.EMAIL, verified: false },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(1);
            expect(result[0].id).toBe("alias-1");
        });

        // Regression: this list is returned directly to the client by listMethods() (see the class doc
        // comment above getMethods()), so a real contact value here would leak a compromised account's
        // email/phone to whoever holds the (possibly stolen) access token.
        it("Obfuscates alias contact info in the returned methods.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "user@example.com", type: AliasType.EMAIL, verified: true },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(1);
            expect(result[0].data.contact).not.toBe("user@example.com");
            expect(result[0].data.contact).toBe((route as any).obfuscateAlias("user@example.com", AliasType.EMAIL));
        });
    });

    describe("getUser", () => {
        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthElevationRoute();

            await expect((route as any).getUser("user-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Delegates to userUtils.lookup().", async () => {
            const route = new TestAuthElevationRoute();
            const lookup = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).userUtils = { lookup };

            const result = await (route as any).getUser("user-1");

            expect(lookup).toHaveBeenCalledWith("user-1");
            expect(result).toEqual({ uid: "user-1" });
        });
    });

    describe("notifyContact", () => {
        it("Sends an email when the contact type is EMAIL.", async () => {
            const route = new TestAuthElevationRoute();
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };

            await (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456");

            expect(sendEmail).toHaveBeenCalledWith("login-otp", { totp: "123456" }, { to: "user@example.com" });
        });

        it("Sends an SMS when the contact type is SMS.", async () => {
            const route = new TestAuthElevationRoute();
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };

            await (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456");

            expect(sendSMS).toHaveBeenCalledWith("login-otp", { totp: "123456" }, { to: "+15551234567" });
        });

        // Regression: a rejected sendEmail/sendSMS promise used to have no .catch(), so under Node's
        // default `--unhandled-rejections=throw` a single transient messaging-provider failure during an
        // elevation challenge send would crash the entire process for every user, not just this request.
        it("Does not throw (and logs instead) when sendEmail rejects.", async () => {
            const route = new TestAuthElevationRoute();
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockRejectedValue(new Error("provider unavailable")),
                sendSMS: vi.fn(),
            };

            await expect(
                (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).resolves.toBeUndefined();
            // Flush the rejected .catch() microtask registered inside notifyContact.
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification e-mail"));
        });

        it("Does not throw (and logs instead) when sendSMS rejects.", async () => {
            const route = new TestAuthElevationRoute();
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn(),
                sendSMS: vi.fn().mockRejectedValue(new Error("provider unavailable")),
            };

            await expect(
                (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456"),
            ).resolves.toBeUndefined();
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification SMS"));
        });
    });

    describe("obfuscateAlias", () => {
        it("Obfuscates an EMAIL alias.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).obfuscateAlias("user@example.com", AliasType.EMAIL);
            expect(result).not.toBe("user@example.com");
        });

        it("Obfuscates a NAME alias.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).obfuscateAlias("John Doe", AliasType.NAME);
            expect(result).not.toBe("John Doe");
        });

        it("Obfuscates a PHONE alias.", () => {
            const route = new TestAuthElevationRoute();
            const result = (route as any).obfuscateAlias("+15551234567", AliasType.PHONE);
            expect(result).not.toBe("+15551234567");
        });
    });

    describe("updateCredentialCounter", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();

            await expect((route as any).updateCredentialCounter("cred-1", 5)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthElevationRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's counter when a matching secret is found.", async () => {
            const route = new TestAuthElevationRoute();
            const secret = { uid: "secret-1", version: 1, data: { id: "cred-1", counter: 1 } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(secret.data.counter).toBe(5);
            expect(update).toHaveBeenCalledWith(
                { uid: "secret-1", version: 1, data: secret.data },
                secret,
                { ignoreACL: true, recordEvent: false },
            );
        });
    });

    describe("updateSecretTimeStep", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();

            await expect((route as any).updateSecretTimeStep("secret-1", 42)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthElevationRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's lastTimeStep when a matching secret is found.", async () => {
            const route = new TestAuthElevationRoute();
            const secret = { uid: "secret-1", version: 1, data: { secret: "abc" } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(secret.data.lastTimeStep).toBe(42);
        });
    });

    describe("verify", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).userUtils = { lookup: vi.fn() };

            await expect((route as any).verify("user1", "pass1")).rejects.toThrow(/Secret repository not set/);
        });

        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn() };

            await expect((route as any).verify("user1", "pass1")).rejects.toThrow(/User repository not set/);
        });

        it("Throws when the user cannot be found.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };

            await expect((route as any).verify("unknown-user", "pass1")).rejects.toThrow(
                /Invalid authorization request/,
            );
        });

        it("Performs a dummy Argon2 verification when the user cannot be found, to equalize response timing.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect((route as any).verify("unknown-user", "pass1")).rejects.toThrow(
                /Invalid authorization request/,
            );

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1");
        });

        it("Resolves the user when at least one stored password matches — this is what lets a password-only " +
            "(no second factor enrolled) admin account still elevate.", async () => {
            const route = new TestAuthElevationRoute();
            const argon2 = await import("argon2");
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([{ data: await argon2.hash("correct-password") }]),
            };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };

            const user = await (route as any).verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
        });

        it("Throws when none of the user's stored passwords match.", async () => {
            const route = new TestAuthElevationRoute();
            const argon2 = await import("argon2");
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([{ data: await argon2.hash("correct-password") }]),
            };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };

            await expect((route as any).verify("user1", "wrong-password")).rejects.toThrow(
                /Invalid authorization request/,
            );
        });

        it("Performs a dummy Argon2 verification (and throws) when the user has no stored password secret.", async () => {
            const route = new TestAuthElevationRoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect((route as any).verify("user1", "any-password")).rejects.toThrow(
                /Invalid authorization request/,
            );

            expect(verifyDummySpy).toHaveBeenCalledWith("any-password");
        });
    });
});

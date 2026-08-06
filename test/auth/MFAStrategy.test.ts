///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for MFAStrategy — no HTTP server, no database. Only the external WebAuthn
// ceremony library is mocked (matching test/auth/PasskeyStrategy.test.ts); OTP/Basic-header parsing
// runs through the real shared.ts helpers, exactly as in the HTTP-level AuthMFARoute suites.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
}));

import type { JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import * as otplib from "otplib";
import { MFAMethod, MFAMethodType, MFAStrategy, MFAStrategyOptions } from "../../src/auth/MFAStrategy.js";
import { OTPContactType, PasskeyConfig } from "../../src/auth/types.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as any;

function makeFidoConfig(overrides: Partial<PasskeyConfig> = {}): PasskeyConfig {
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
        path: "/auth/mfa",
        url: "/auth/mfa",
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

function basicHeader(id: string, password: string): string {
    return `basic ${Buffer.from(`${id}:${password}`).toString("base64")}`;
}

const jwtUser: JWTUser = { uid: "user-uid-1", name: "test", roles: [] };

describe("MFAStrategy Tests", () => {
    let options: MFAStrategyOptions;
    let strategy: MFAStrategy;

    beforeEach(() => {
        options = new MFAStrategyOptions();
        options.getMethod = vi.fn();
        options.getMethods = vi.fn();
        options.getUser = vi.fn();
        options.notifyContact = vi.fn();
        options.verify = vi.fn();
        strategy = new MFAStrategy(options);
        mockGenerateAuthenticationOptions.mockReset();
    });

    it("authenticateSync throws 'Not supported'.", () => {
        const req = makeReq();
        expect(() => strategy.authenticateSync(req, makeRes())).toThrow(/Not supported/);
    });

    describe("Dispatch", () => {
        it("Routes an OTP-shaped payload (id+token) to verifyOTP and authenticates on success.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({
                body: { id: "user-uid-1", token },
                session: { id: "user-uid-1", secret, userUid: "user-uid-1" },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect(result).toEqual({
                data: { id: "user-uid-1", token },
                method: "mfa",
                payload: { id: "user-uid-1", token },
                user: jwtUser,
            });
        });

        it("Falls through to the required check when the OTP token is invalid.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", token: "000000" },
                session: { id: "user-uid-1", secret: otplib.generateSecret() },
            });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });

        it("Routes a passkey-shaped payload to verifyFIDO, which is not yet implemented.", async () => {
            const req = makeReq({
                body: {
                    id: "cred-id-1",
                    response: {
                        clientDataJSON: "x",
                        authenticatorData: "y",
                        signature: "z",
                    },
                },
            });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Not implemented/);
        });

        it("Authenticates on a passkey-shaped payload once verifyFIDO resolves a user.", async () => {
            // verifyFIDO() is an unimplemented stub on the base class (see the test above) — this
            // subclass exercises the surrounding dispatch/response-building logic on its own,
            // independent of whether FIDO2 verification itself has been implemented.
            class TestMFAStrategy extends MFAStrategy {
                protected async verifyFIDO(): Promise<JWTUser | undefined> {
                    return jwtUser;
                }
            }
            const fidoStrategy = new TestMFAStrategy(options);
            const req = makeReq({
                body: {
                    id: "cred-id-1",
                    response: {
                        clientDataJSON: "x",
                        authenticatorData: "y",
                        signature: "z",
                    },
                },
            });

            const result = await fidoStrategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
        });

        it("Falls through to the required check on a passkey-shaped payload once verifyFIDO resolves undefined.", async () => {
            class TestMFAStrategy extends MFAStrategy {
                protected async verifyFIDO(): Promise<JWTUser | undefined> {
                    return undefined;
                }
            }
            const fidoStrategy = new TestMFAStrategy(options);
            const req = makeReq({
                body: {
                    id: "cred-id-1",
                    response: {
                        clientDataJSON: "x",
                        authenticatorData: "y",
                        signature: "z",
                    },
                },
            });

            const result = await fidoStrategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
        });

        it("Routes an id+password payload to verifyBasic and authenticates when there are no 2FA methods and require2FA is false.", async () => {
            options.require2FA = false;
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
        });

        it("Routes an id+methodId payload to challenge() and returns undefined.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { userUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({
                id: "method-1",
                type: MFAMethodType.OTP,
                data: { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true },
            });

            const result = await strategy.authenticate(req, makeRes());

            expect(result).toBeUndefined();
            expect(options.getMethod).toHaveBeenCalledWith("method-1", "user-uid-1");
            expect(options.notifyContact).toHaveBeenCalled();
        });

        it("Throws when no dispatch condition matches and auth is required.", async () => {
            const req = makeReq({ body: {} });

            await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(/Invalid authentication request/);
        });

        it("Returns undefined when no dispatch condition matches and auth is not required.", async () => {
            const req = makeReq({ body: {} });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
        });
    });

    describe("challenge (phase 2)", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", methodId: "method-1" }, session: undefined });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/session support/);
        });

        it("Throws when there is no session-bound phase-1-verified identity (cold request).", async () => {
            const req = makeReq({ body: { id: "user-uid-1", methodId: "method-1" }, session: {} });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect(options.getMethod).not.toHaveBeenCalled();
        });

        it("Throws when the session-bound identity does not match the claimed payload id.", async () => {
            const req = makeReq({
                body: { id: "victim-uid", methodId: "method-1" },
                session: { userUid: "attacker-uid" },
            });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect(options.getMethod).not.toHaveBeenCalled();
        });

        it("Throws when the selected method id does not resolve.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "bogus" },
                session: { userUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /Invalid secondary authentication method/,
            );
        });

        it("Throws for a FIDO2 method when no fidoConfig is configured.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { userUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: MFAMethodType.FIDO2, data: {} });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /No configuration exists for MFA method: FIDO2/,
            );
        });

        it("Generates a FIDO2 challenge and writes it to the response when fidoConfig is configured.", async () => {
            options.fidoConfig = makeFidoConfig();
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { userUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: MFAMethodType.FIDO2, data: {} });
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ challenge: "chal-123" });
        });

        it("Throws for an unsupported method type.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { userUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: MFAMethodType.TOTP, data: {} });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Unsupported MFA method: totp/);
        });
    });

    describe("verifyBasic (phase 1)", () => {
        it("Throws when no Basic auth header is present, even if the dispatch payload has id/password.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "password" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid user id or password/);
            expect(options.verify).not.toHaveBeenCalled();
        });

        it("Throws when verify() resolves undefined.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "bogus") },
                body: { id: "user-uid-1", password: "bogus" },
            });
            (options.verify as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid user id or password/);
        });

        it("Returns the list of 2FA methods and does not authenticate when methods are available.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            (options.verify as any).mockResolvedValue(jwtUser);
            const methods: MFAMethod[] = [{ id: "method-1", type: MFAMethodType.OTP, data: {} }];
            (options.getMethods as any).mockResolvedValue(methods);
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith(methods);
        });

        it("Does not throw when req.session is missing on successful password verification.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
                session: undefined,
            });
            options.require2FA = false;
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
        });

        it("Binds the session to the verified identity on successful password verification.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([{ id: "method-1", type: MFAMethodType.OTP, data: {} }]);

            await strategy.authenticate(req, makeRes());

            expect((req.session as any).userUid).toBe("user-uid-1");
        });

        it("Throws when there are no 2FA methods and require2FA is true (the default).", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /No secondary authentication methods available/,
            );
        });

        it("Invokes checkRateLimit with the claimed identifier before verify().", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);
            options.require2FA = false;

            await strategy.authenticate(req, makeRes());

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        it("Aborts before verify() when checkRateLimit throws.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.verify).not.toHaveBeenCalled();
        });
    });

    describe("verifyOTP (phase 3)", () => {
        it("Resolves the user via the session-bound identity, not the client-supplied payload id, and clears it after.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            // The attacker claims `payload.id` is the victim, but only controls a challenge that was
            // actually bound (via session.userUid, set in verifyBasic) to their own identity.
            const req = makeReq({
                body: { id: "victim-uid", token },
                session: { id: "victim-uid", secret, userUid: "attacker-uid" },
            });
            (options.getUser as any).mockResolvedValue({ uid: "attacker-uid", name: "attacker", roles: [] });

            await strategy.authenticate(req, makeRes());

            expect(options.getUser).toHaveBeenCalledWith("attacker-uid");
            expect(options.getUser).not.toHaveBeenCalledWith("victim-uid");
            expect((req.session as any).userUid).toBeUndefined();
        });

        it("Clears the session-bound identity even when the OTP token is invalid.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", token: "000000" },
                session: { id: "user-uid-1", secret: otplib.generateSecret(), userUid: "user-uid-1" },
            });

            await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect((req.session as any).userUid).toBeUndefined();
        });

        it("Aborts before verifying the OTP token when checkRateLimit throws.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({
                body: { id: "user-uid-1", token },
                session: { id: "user-uid-1", secret, userUid: "user-uid-1" },
            });
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.getUser).not.toHaveBeenCalled();
        });
    });

    it("verifyTOTP is not yet implemented.", async () => {
        const req = makeReq();
        await expect((strategy as any).verifyTOTP({}, req, makeRes())).rejects.toThrow(/Not implemented/);
    });

    describe("Default MFAStrategyOptions", () => {
        const defaultOptions = new MFAStrategyOptions();

        it("getMethod throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getMethod("method-1", "user-uid-1")).toThrow(
                /Did you forget to override MFAStrategyOptions.getContact/,
            );
        });

        it("getMethods throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getMethods("user-uid-1")).toThrow(
                /Did you forget to override MFAStrategyOptions.getContacts/,
            );
        });

        it("getUser throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getUser("user-uid-1")).toThrow(
                /Did you forget to override MFAStrategyOptions.getUsers/,
            );
        });

        it("notifyContact throws if the consumer forgot to override it.", () => {
            expect(() =>
                defaultOptions.notifyContact({ contact: "test@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).toThrow(/Did you forget to override MFAStrategyOptions.notify/);
        });

        it("verify throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.verify("user-uid-1", "password")).toThrow(
                /Did you forget to override MFAStrategyOptions.verify/,
            );
        });
    });
});

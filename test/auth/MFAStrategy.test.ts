///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for MFAStrategy — no HTTP server, no database. Only the external WebAuthn
// ceremony library is mocked (matching test/auth/PasskeyStrategy.test.ts); OTP/Basic-header parsing
// runs through the real shared.ts helpers, exactly as in the HTTP-level AuthMFARoute suites.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
}));

import { ApiError, type JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import * as otplib from "otplib";
import { MFAMethod, MFAMethodType, MFAStrategy, MFAStrategyOptions } from "../../src/auth/MFAStrategy.js";
import { OTPCounters } from "../../src/auth/OTPCounters.js";
import { counterKeyPart as h, generateOTP } from "../../src/auth/shared.js";
import { OTPContactType, PasskeyConfig, StoredPasskeyCredential } from "../../src/auth/types.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as any;
const mockVerifyAuthenticationResponse = verifyAuthenticationResponse as any;

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

const storedCredential: StoredPasskeyCredential = {
    id: "cred-id-1",
    uid: "user-uid-1",
    publicKey: new Uint8Array([1, 2, 3]),
    counter: 5,
    transports: ["usb"],
};

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
        options.getCredentialById = vi.fn();
        options.getMethod = vi.fn();
        options.getMethods = vi.fn();
        options.getUser = vi.fn();
        options.notifyContact = vi.fn();
        options.updateCredentialCounter = vi.fn();
        options.verify = vi.fn();
        strategy = new MFAStrategy(options);
        mockGenerateAuthenticationOptions.mockReset();
        mockVerifyAuthenticationResponse.mockReset();
    });

    it("authenticateSync throws 'Not supported'.", () => {
        const req = makeReq();
        expect(() => strategy.authenticateSync(req, makeRes())).toThrow(/Not supported/);
    });

    describe("Dispatch", () => {
        it("Routes an OTP-shaped payload (id+token) to verifyOTP and authenticates on success.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            const token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");
            req.body.token = token;
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
            const req = makeReq({ body: { id: "user-uid-1", token: "000000" } });
            await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });

        it("Returns undefined for a passkey-shaped payload when there is no phase-2 session state (cold request).", async () => {
            const req = makeReq({ body: makeAssertionBody() });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getCredentialById).not.toHaveBeenCalled();
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
                session: { mfaPendingUid: "user-uid-1" },
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
                session: { mfaPendingUid: "attacker-uid" },
            });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect(options.getMethod).not.toHaveBeenCalled();
        });

        it("Throws when the selected method id does not resolve.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "bogus" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /Invalid secondary authentication method/,
            );
        });

        it("Throws for a FIDO2 method when no fidoConfig is configured.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: MFAMethodType.FIDO2, data: {} });

            // Regression: offering FIDO2 as a method but never wiring fidoConfig is a deployment
            // misconfiguration, not a client-caused auth failure - it must surface as a 500.
            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/No configuration exists for MFA method: FIDO2/),
            });
        });

        it("Generates a FIDO2 challenge scoped to the selected credential, writes it to the response, and records the method id.", async () => {
            options.fidoConfig = makeFidoConfig();
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({
                id: "method-1",
                type: MFAMethodType.FIDO2,
                data: { id: "cred-id-1", transports: ["usb"] },
            });
            mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "chal-123" });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(mockGenerateAuthenticationOptions).toHaveBeenCalledWith(
                expect.objectContaining({ allowCredentials: [{ id: "cred-id-1", transports: ["usb"] }] }),
            );
            expect((req.session as any).mfaMethodId).toBe("method-1");
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ challenge: "chal-123" });
        });

        it("Acknowledges a TOTP method selection without sending a notification, and records the method id.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: MFAMethodType.TOTP, data: {} });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(options.notifyContact).not.toHaveBeenCalled();
            expect((req.session as any).mfaMethodId).toBe("method-1");
            expect((req.session as any).mfaMethodType).toBe(MFAMethodType.TOTP);
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Acknowledges a RECOVERY_CODE method selection without sending a notification, and records the method id/type.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({
                id: "method-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { remaining: 7 },
            });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(options.notifyContact).not.toHaveBeenCalled();
            expect((req.session as any).mfaMethodId).toBe("method-1");
            expect((req.session as any).mfaMethodType).toBe(MFAMethodType.RECOVERY_CODE);
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Throws for an unsupported method type.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "method-1" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue({ id: "method-1", type: "unknown", data: {} });

            // Regression: the method type comes from the server's own prior recorded selection (not a
            // client guess), so this is a server-side wiring gap, not an auth failure - it must surface
            // as a 500.
            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/Unsupported MFA method: unknown/),
            });
        });

        // Regression: the OTP case used to leave a previously-recorded `mfaMethodId` (set by an earlier
        // TOTP/FIDO2 selection in the same session) in place. Since authenticate()'s phase-3 dispatch routes
        // purely on whether `mfaMethodId` is truthy, a stale value would misroute the subsequent (correct)
        // OTP submission into verifyTOTP(), which always fails against an OTP-shaped token.
        it("Clears a stale mfaMethodId left over from a previous TOTP/FIDO2 selection when OTP is selected.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "otp-method" },
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "stale-totp-secret-id" },
            });
            (options.getMethod as any).mockResolvedValue({
                id: "otp-method",
                type: MFAMethodType.OTP,
                data: { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true },
            });

            await strategy.authenticate(req, makeRes());

            expect((req.session as any).mfaMethodId).toBeUndefined();
        });

        // End-to-end regression for the same bug: selecting TOTP, then switching to OTP, must still let
        // the correct OTP code authenticate — before the fix, this always failed because the leftover
        // `mfaMethodId` from the TOTP selection misrouted the OTP submission into verifyTOTP().
        it("Regression: switching from a TOTP selection to OTP still authenticates on the correct OTP code.", async () => {
            const session: any = { mfaPendingUid: "user-uid-1" };

            // Phase 2a: select TOTP first, recording its method id in the session.
            (options.getMethod as any).mockResolvedValue({ id: "totp-method", type: MFAMethodType.TOTP, data: {} });
            await strategy.authenticate(
                makeReq({ body: { id: "user-uid-1", methodId: "totp-method" }, session }),
                makeRes(),
            );
            expect(session.mfaMethodId).toBe("totp-method");

            // Phase 2b: the user switches to OTP instead.
            (options.getMethod as any).mockResolvedValue({
                id: "otp-method",
                type: MFAMethodType.OTP,
                data: { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true },
            });
            await strategy.authenticate(
                makeReq({ body: { id: "user-uid-1", methodId: "otp-method" }, session }),
                makeRes(),
            );
            const otpToken: string = (options.notifyContact as any).mock.calls[0][1];

            // Phase 3: submitting the real OTP code must authenticate, not be misrouted to verifyTOTP().
            // verifyOTP() never calls getMethod() at all (unlike verifyTOTP(), which re-fetches the
            // selected secret) — its call count staying at 2 (the two challenge() calls above) confirms
            // phase 3 took the verifyOTP() path, not verifyTOTP().
            (options.getUser as any).mockResolvedValue(jwtUser);
            const result = await strategy.authenticate(
                makeReq({ body: { id: "user-uid-1", token: otpToken }, session }),
                makeRes(),
            );

            expect(result?.user).toEqual(jwtUser);
            expect(options.getMethod).toHaveBeenCalledTimes(2);
        });
    });

    describe("verifyBasic (phase 1)", () => {
        it("Authenticates using body-supplied credentials when no Basic auth header is present.", async () => {
            // The frontend's real sign-in call posts `{id, password}` as a JSON body with no Authorization
            // header at all — verifyBasic must accept the same body-aware payload that authenticate()'s
            // dispatch condition (`payload.id && payload.password`) already matched against, not silently
            // require a header the dispatcher never checked for.
            const req = makeReq({ body: { id: "user-uid-1", password: "password" } });
            options.require2FA = false;
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
            expect(options.verify).toHaveBeenCalledWith("user-uid-1", "password");
        });

        // authenticate()'s dispatch condition (`payload.id && payload.password`) already guarantees both
        // are present before verifyBasic() is ever reached through the public API — this guard only
        // protects verifyBasic() itself as a directly-callable protected method (e.g. for a subclass that
        // invokes it with a payload it hasn't already validated).
        it("Throws when called directly with a payload missing id or password.", async () => {
            const req = makeReq({});

            await expect((strategy as any).verifyBasic({ id: "user-uid-1" }, req, makeRes())).rejects.toThrow(
                /Invalid user id or password/,
            );
        });

        it("Throws when verify() resolves undefined.", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "bogus") },
                body: { id: "user-uid-1", password: "bogus" },
            });
            (options.verify as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid user id or password/);
        });

        it("Returns the user's uid alongside the list of 2FA methods, and does not authenticate, when methods are available.", async () => {
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
            // `uid` lets a client that logged in with a non-uid identifier (email, alias, etc.) know
            // what `id` to submit for phase 2/3 — the only point at which it's ever disclosed.
            expect(res.json).toHaveBeenCalledWith({ uid: jwtUser.uid, methods });
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

            expect((req.session as any).mfaPendingUid).toBe("user-uid-1");
        });

        it("Throws when there are no 2FA methods and require2FA is true (the default).", async () => {
            const req = makeReq({
                headers: { authorization: basicHeader("user-uid-1", "password") },
                body: { id: "user-uid-1", password: "password" },
            });
            (options.verify as any).mockResolvedValue(jwtUser);
            (options.getMethods as any).mockResolvedValue([]);

            // Regression: only reachable after the password already verified correctly, so it can't help
            // an anonymous attacker enumerate accounts - a legitimate client should see this distinctly
            // (401) rather than it being flattened into the same generic auth-failure code as everything
            // else on this path.
            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 401,
                message: expect.stringMatching(/No secondary authentication methods available/),
            });
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
        // Regression (security): verifyOTP used to skip the `payload.id === session.mfaPendingUid` check that TOTP and
        // recovery codes perform, and to return `getUser(session.mfaPendingUid)` for ANY valid one-time code in the
        // session - including one the attacker had issued to themselves through another flow.
        it("Refuses a payload id that is not the phase-1-verified identity, even with a valid code for that id.", async () => {
            const req = makeReq({ body: { id: "attacker@example.com" }, session: { mfaPendingUid: "victim-uid" } });
            req.body.token = await generateOTP(req, { id: "attacker@example.com" }, undefined, "mfa");
            (options.getUser as any).mockResolvedValue({ uid: "victim-uid", name: "victim", roles: [] });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
            expect((req.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Refuses a code issued by another flow to the attacker's own contact (registration or sign-in).", async () => {
            for (const purpose of ["register", "login", "contact", "elevate"] as const) {
                const req = makeReq({ body: { id: "attacker@example.com" }, session: { mfaPendingUid: "victim-uid" } });
                req.body.token = await generateOTP(req, { id: "attacker@example.com" }, undefined, purpose);
                (options.getUser as any).mockResolvedValue({ uid: "victim-uid", name: "victim", roles: [] });

                expect(await strategy.authenticate(req, makeRes(), false)).toBeUndefined();
                expect(options.getUser).not.toHaveBeenCalled();
            }
        });

        it("Refuses a code issued by another flow even when its id is the verified user's uid.", async () => {
            for (const purpose of ["register", "login", "contact", "elevate"] as const) {
                const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
                req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, purpose);
                (options.getUser as any).mockResolvedValue(jwtUser);

                await expect(strategy.authenticate(req, makeRes(), false)).rejects.toThrow(
                    /Invalid authentication request/,
                );
                expect(options.getUser).not.toHaveBeenCalled();
                // The mismatched challenge was consumed, and the identity cleared with it.
                expect((req.session as any).otp).toBeUndefined();
                expect((req.session as any).mfaPendingUid).toBeUndefined();
            }
        });

        it("Resolves the user via the session-bound identity and clears it after.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");
            (options.getUser as any).mockResolvedValue(jwtUser);

            await strategy.authenticate(req, makeRes());

            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect((req.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Clears the session-bound identity when verification throws, instead of leaving it for later requests.", async () => {
            // No challenge at all.
            const none = makeReq({ body: { id: "user-uid-1", token: "AAAAAA" }, session: { mfaPendingUid: "user-uid-1" } });
            await expect(strategy.authenticate(none, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect((none.session as any).mfaPendingUid).toBeUndefined();

            // A challenge for a different id.
            const other = makeReq({ body: { id: "user-uid-1", token: "AAAAAA" }, session: { mfaPendingUid: "user-uid-1" } });
            await generateOTP(other, { id: "someone-else" }, undefined, "mfa");
            await expect(strategy.authenticate(other, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect((other.session as any).mfaPendingUid).toBeUndefined();

            // A challenge for a different purpose.
            const purpose = makeReq({ body: { id: "user-uid-1", token: "AAAAAA" }, session: { mfaPendingUid: "user-uid-1" } });
            await generateOTP(purpose, { id: "user-uid-1" }, undefined, "register");
            await expect(strategy.authenticate(purpose, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect((purpose.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Clears the session-bound identity when the dedicated limit refuses, even though the challenge is pending.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa", "user-uid-1");
            const counters = new OTPCounters();
            vi.spyOn(counters, "throttle").mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow down"));
            options.counters = counters;

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ status: 429 });
            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
        });

        it("Clears the session-bound identity when the generic rate limit refuses, before anything is verified.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");
            options.checkRateLimit = vi.fn().mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow down"));

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ status: 429 });
            expect((req.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Clears the pending identity and method when the generic rate limit refuses a TOTP or recovery code.", async () => {
            for (const type of [MFAMethodType.TOTP, MFAMethodType.RECOVERY_CODE]) {
                const req = makeReq({
                    body: { id: "user-uid-1", token: "123456" },
                    session: { mfaPendingUid: "user-uid-1", mfaMethodId: "secret-1", mfaMethodType: type },
                });
                options.checkRateLimit = vi.fn().mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow"));

                await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ status: 429 });
                expect((req.session as any).mfaPendingUid).toBeUndefined();
                expect((req.session as any).mfaMethodId).toBeUndefined();
            }
        });

        it("Counts verification against the user's uid with the dedicated counters, per flow.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa", "user-uid-1");
            const counters = new OTPCounters();
            const throttle = vi.spyOn(counters, "throttle");
            options.counters = counters;
            (options.getUser as any).mockResolvedValue(jwtUser);

            await strategy.authenticate(req, makeRes());

            const keys = throttle.mock.calls.map((c) => c[0]);
            expect(keys).toContain(`verify:mfa:${h("user-uid-1")}:${h("unknown")}`);
            expect(keys).toContain(`user:mfa:${h("user-uid-1")}:${h("unknown")}`);
            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
        });

        it("Keeps the session-bound identity after a wrong OTP token while the challenge is still live, so a typo can be retried.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            const token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");
            req.body.token = token === "AAAAAA" ? "BBBBBB" : "AAAAAA";

            await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect((req.session as any).mfaPendingUid).toBe("user-uid-1");

            // The retry with the right code then succeeds.
            req.body.token = token;
            (options.getUser as any).mockResolvedValue(jwtUser);
            await strategy.authenticate(req, makeRes());
            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect((req.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Clears the session-bound identity when the OTP challenge is out of attempts.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", token: "AAAAAA" }, session: { mfaPendingUid: "user-uid-1" } });
            options.otpConfig = { maxAttempts: 1 };
            const token = await generateOTP(req, { id: "user-uid-1" }, options.otpConfig, "mfa");
            if (token === "AAAAAA") {
                req.body.token = "BBBBBB";
            }

            await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect((req.session as any).mfaPendingUid).toBeUndefined();
        });

        it("Aborts before verifying the OTP token when checkRateLimit throws.", async () => {
            const req = makeReq({ body: { id: "user-uid-1" }, session: { mfaPendingUid: "user-uid-1" } });
            req.body.token = await generateOTP(req, { id: "user-uid-1" }, undefined, "mfa");
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.getUser).not.toHaveBeenCalled();
        });
    });

    describe("one-time code challenge (phase 2)", () => {
        const otpMethod = {
            id: "otp-method",
            type: MFAMethodType.OTP,
            data: { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true },
        };

        it("Issues the code for the mfa purpose, bound to the verified user.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "otp-method" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue(otpMethod);

            await strategy.authenticate(req, makeRes());

            expect((req.session as any).otp).toMatchObject({ id: "user-uid-1", purpose: "mfa", userUid: "user-uid-1" });
        });

        it("Enforces the dedicated issue limit before sending anything.", async () => {
            const req = makeReq({
                body: { id: "user-uid-1", methodId: "otp-method" },
                session: { mfaPendingUid: "user-uid-1" },
            });
            (options.getMethod as any).mockResolvedValue(otpMethod);
            const counters = new OTPCounters();
            vi.spyOn(counters, "throttle").mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow down"));
            options.counters = counters;

            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ status: 429 });
            expect(options.notifyContact).not.toHaveBeenCalled();
            expect((req.session as any).otp).toBeUndefined();
        });

        it("Fails fast, at construction, on an unsafe one-time code configuration.", () => {
            const bad = new MFAStrategyOptions();
            bad.otpConfig = { maxAttempts: 50 };
            expect(() => new MFAStrategy(bad)).toThrow(/maxAttempts/);
        });
    });

    describe("verifyFIDO (phase 3)", () => {
        function makeFidoSessionReq(overrides: any = {}): HttpRequest {
            return makeReq({
                body: makeAssertionBody(),
                session: {
                    mfaPendingUid: "user-uid-1",
                    mfaMethodId: "cred-id-1",
                    challenge: "stored-challenge",
                },
                ...overrides,
            });
        }

        beforeEach(() => {
            options.fidoConfig = makeFidoConfig();
        });

        it("Verifies successfully, updates the counter, clears session state, and authenticates.", async () => {
            const req = makeFidoSessionReq();
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.getCredentialById).toHaveBeenCalledWith("cred-id-1");
            expect(options.updateCredentialCounter).toHaveBeenCalledWith("cred-id-1", 6);
            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect(result?.user).toEqual(jwtUser);
            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).challenge).toBeUndefined();
        });

        it("Throws if req.session is missing.", async () => {
            const req = makeFidoSessionReq({ session: undefined });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/session support/);
        });

        it("Throws for a FIDO2 response when no fidoConfig is configured, once session state is otherwise valid.", async () => {
            options.fidoConfig = undefined;
            const req = makeFidoSessionReq();

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(
                /No configuration exists for MFA method: FIDO2/,
            );
        });

        it("Returns undefined when the credential id does not match the one selected during phase 2.", async () => {
            const req = makeFidoSessionReq({
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "some-other-cred", challenge: "stored-challenge" },
            });
            (options.getCredentialById as any).mockResolvedValue(storedCredential);

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Returns undefined when the resolved credential belongs to a different user.", async () => {
            const req = makeFidoSessionReq();
            (options.getCredentialById as any).mockResolvedValue({ ...storedCredential, uid: "someone-else" });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
        });

        it("Returns undefined when the assertion fails verification.", async () => {
            const req = makeFidoSessionReq();
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({ verified: false });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.updateCredentialCounter).not.toHaveBeenCalled();
        });

        it("Returns undefined on a regressed (cloned authenticator) counter.", async () => {
            const req = makeFidoSessionReq();
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 5, credentialID: "cred-id-1" }, // did not increase
            });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.updateCredentialCounter).not.toHaveBeenCalled();
        });

        it("Rate limits by the phase-1-verified identity before verifying.", async () => {
            const req = makeFidoSessionReq();
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            (options.getCredentialById as any).mockResolvedValue(storedCredential);
            mockVerifyAuthenticationResponse.mockResolvedValue({
                verified: true,
                authenticationInfo: { newCounter: 6, credentialID: "cred-id-1" },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);

            await strategy.authenticate(req, makeRes());

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });
    });

    describe("verifyTOTP (phase 3)", () => {
        function makeTotpSessionReq(body: any): HttpRequest {
            return makeReq({
                body,
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "secret-1", mfaMethodType: MFAMethodType.TOTP },
            });
        }

        it("Routes an OTP-shaped payload to verifyTOTP instead of verifyOTP when a TOTP method was selected.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeTotpSessionReq({ id: "user-uid-1", token });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: { secret } });
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.getMethod).toHaveBeenCalledWith("secret-1", "user-uid-1");
            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect(result?.user).toEqual(jwtUser);
            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).mfaMethodType).toBeUndefined();
        });

        it("Invokes checkRateLimit with the claimed payload id.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeTotpSessionReq({ id: "user-uid-1", token });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: { secret } });
            (options.getUser as any).mockResolvedValue(jwtUser);
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes());

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        it("Persists the matched time step for replay protection on success.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeTotpSessionReq({ id: "user-uid-1", token });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: { secret } });
            (options.getUser as any).mockResolvedValue(jwtUser);
            options.updateSecretTimeStep = vi.fn().mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes());

            expect(options.updateSecretTimeStep).toHaveBeenCalledWith("secret-1", expect.any(Number));
        });

        it("Returns undefined when the token is invalid.", async () => {
            const secret = otplib.generateSecret();
            const req = makeTotpSessionReq({ id: "user-uid-1", token: "000000" });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: { secret } });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
        });

        it("Returns undefined when the claimed payload id does not match the session-bound identity.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeTotpSessionReq({ id: "someone-else", token });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getMethod).not.toHaveBeenCalled();
        });

        it("Returns undefined when the selected method is no longer a TOTP method.", async () => {
            const req = makeTotpSessionReq({ id: "user-uid-1", token: "123456" });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.OTP, data: {} });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
        });

        it("Clears the session-bound identity and method even when verification fails.", async () => {
            const req = makeTotpSessionReq({ id: "user-uid-1", token: "000000" });
            (options.getMethod as any).mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes(), false);

            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).mfaMethodType).toBeUndefined();
        });
    });

    describe("verifyRecoveryCode (phase 3)", () => {
        async function hashCode(code: string): Promise<string> {
            const argon = await import("argon2");
            return argon.hash(code);
        }

        function makeRecoverySessionReq(body: any): HttpRequest {
            return makeReq({
                body,
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "secret-1", mfaMethodType: MFAMethodType.RECOVERY_CODE },
            });
        }

        it("Routes an OTP-shaped payload to verifyRecoveryCode instead of verifyOTP/verifyTOTP when a RECOVERY_CODE method was selected.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "ABCDE-12345" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { codes: [{ hash: await hashCode("ABCDE-12345") }] },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.getMethod).toHaveBeenCalledWith("secret-1", "user-uid-1");
            expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
            expect(result?.user).toEqual(jwtUser);
            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).mfaMethodType).toBeUndefined();
        });

        it("Invokes checkRateLimit with the claimed payload id.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "ABCDE-12345" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { codes: [{ hash: await hashCode("ABCDE-12345") }] },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes());

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        it("Consumes the matched code by its index on success.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "SECOND-CODE" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: {
                    codes: [{ hash: await hashCode("FIRST-CODE") }, { hash: await hashCode("SECOND-CODE") }],
                },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);
            options.consumeRecoveryCode = vi.fn().mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes());

            expect(options.consumeRecoveryCode).toHaveBeenCalledWith("secret-1", 1, req);
        });

        it("Skips already-used codes when matching, and does not resurrect a used one.", async () => {
            const usedHash = await hashCode("USED-CODE");
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "USED-CODE" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { codes: [{ hash: usedHash, usedAt: "2026-01-01T00:00:00.000Z" }] },
            });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
        });

        it("Returns undefined without consuming any code when the submitted code matches nothing.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "WRONG-CODE1" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { codes: [{ hash: await hashCode("ABCDE-12345") }] },
            });
            options.consumeRecoveryCode = vi.fn();

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
            expect(options.consumeRecoveryCode).not.toHaveBeenCalled();
        });

        it("Returns undefined when the claimed payload id does not match the session-bound identity.", async () => {
            const req = makeRecoverySessionReq({ id: "someone-else", token: "ABCDE-12345" });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
            expect(options.getMethod).not.toHaveBeenCalled();
        });

        it("Returns undefined when the selected method is no longer a RECOVERY_CODE method.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "ABCDE-12345" });
            (options.getMethod as any).mockResolvedValue({ id: "secret-1", type: MFAMethodType.TOTP, data: {} });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
        });

        it("Clears the session-bound identity and method even when verification fails.", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "WRONG-CODE1" });
            (options.getMethod as any).mockResolvedValue(undefined);

            await strategy.authenticate(req, makeRes(), false);

            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect((req.session as any).mfaMethodId).toBeUndefined();
            expect((req.session as any).mfaMethodType).toBeUndefined();
        });

        it("Does not throw when consumeRecoveryCode is not provided (optional hook).", async () => {
            const req = makeRecoverySessionReq({ id: "user-uid-1", token: "ABCDE-12345" });
            (options.getMethod as any).mockResolvedValue({
                id: "secret-1",
                type: MFAMethodType.RECOVERY_CODE,
                data: { codes: [{ hash: await hashCode("ABCDE-12345") }] },
            });
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
        });
    });

    describe("Default MFAStrategyOptions", () => {
        const defaultOptions = new MFAStrategyOptions();

        it("getCredentialById throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getCredentialById("cred-id-1")).toThrow(
                /Did you forget to override MFAStrategyOptions.getCredentialById/,
            );
        });

        it("updateCredentialCounter throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.updateCredentialCounter("cred-id-1", 1)).toThrow(
                /Did you forget to override MFAStrategyOptions.updateCredentialCounter/,
            );
        });

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

describe("MFAStrategy session identity (MFA bypass of OAuth authorize)", () => {
    let options: MFAStrategyOptions;
    let strategy: MFAStrategy;

    beforeEach(() => {
        options = new MFAStrategyOptions();
        options.getCredentialById = vi.fn();
        options.getMethod = vi.fn();
        options.getMethods = vi.fn();
        options.getUser = vi.fn();
        options.notifyContact = vi.fn();
        options.updateCredentialCounter = vi.fn();
        options.verify = vi.fn();
        strategy = new MFAStrategy(options);
    });

    it("Never writes session.userUid after the password step, only the pending identity.", async () => {
        const req = makeReq({ body: { id: "user-uid-1", password: "password" } });
        (options.verify as any).mockResolvedValue(jwtUser);
        (options.getMethods as any).mockResolvedValue([{ id: "m", type: MFAMethodType.TOTP, data: {} }]);

        await strategy.authenticate(req, makeRes());

        expect((req.session as any).userUid).toBeUndefined();
        expect((req.session as any).mfaPendingUid).toBe("user-uid-1");
    });

    it("Does not leave a pending identity when no second factor applies (the caller signs in for real).", async () => {
        const req = makeReq({ body: { id: "user-uid-1", password: "password" } });
        options.require2FA = false;
        (options.verify as any).mockResolvedValue(jwtUser);
        (options.getMethods as any).mockResolvedValue([]);

        const result = await strategy.authenticate(req, makeRes());

        expect(result?.user).toEqual(jwtUser);
        expect((req.session as any).userUid).toBeUndefined();
        expect((req.session as any).mfaPendingUid).toBeUndefined();
    });

    it("Drops an earlier pending identity when a new password attempt fails.", async () => {
        const req = makeReq({ body: { id: "user-uid-1", password: "wrong" }, session: { mfaPendingUid: "user-uid-1" } });
        (options.verify as any).mockResolvedValue(undefined);

        await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid user id or password/);

        expect((req.session as any).mfaPendingUid).toBeUndefined();
    });

    it("Ignores a signed-in session's userUid as proof of the password step.", async () => {
        const req = makeReq({
            body: { id: "user-uid-1", methodId: "otp-method" },
            session: { userUid: "user-uid-1" },
        });

        await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid authentication request/);
        expect(options.getMethod).not.toHaveBeenCalled();
    });

    it.each([
        ["a one-time code", { id: "user-uid-1", token: "AAAAAA" }, {}],
        ["a TOTP code", { id: "user-uid-1", token: "123456" }, { mfaMethodId: "s", mfaMethodType: MFAMethodType.TOTP }],
        [
            "a recovery code",
            { id: "user-uid-1", token: "AAAAA-AAAAA" },
            { mfaMethodId: "s", mfaMethodType: MFAMethodType.RECOVERY_CODE },
        ],
        ["a passkey", makeAssertionBody(), { mfaMethodId: "cred-id-1", challenge: "c" }],
    ])("A failed second factor (%s) never signs out an existing real session.", async (_name, body, extra) => {
        (options.getMethod as any).mockResolvedValue(undefined);
        (options.getCredentialById as any).mockResolvedValue(undefined);
        const req = makeReq({
            body,
            session: { userUid: "user-uid-1", refreshUid: "refresh-1", mfaPendingUid: "user-uid-1", ...extra },
        });

        await strategy.authenticate(req, makeRes(), false).catch(() => undefined);

        expect((req.session as any).userUid).toBe("user-uid-1");
        expect((req.session as any).refreshUid).toBe("refresh-1");
        expect((req.session as any).mfaPendingUid).toBeUndefined();
    });

    describe("rate limiting of phases 2 and 3 is matched to the phase-1-verified identity first", () => {
        // Each phase with the session state that makes it reach its rate limit, and a body naming the pending user.
        const phases: Array<[string, any, any]> = [
            ["challenge", { id: "user-uid-1", methodId: "m" }, {}],
            ["a one-time code", { id: "user-uid-1", token: "AAAAAA" }, {}],
            ["a TOTP code", { id: "user-uid-1", token: "123456" }, { mfaMethodId: "s", mfaMethodType: MFAMethodType.TOTP }],
            [
                "a recovery code",
                { id: "user-uid-1", token: "AAAAA-AAAAA" },
                { mfaMethodId: "s", mfaMethodType: MFAMethodType.RECOVERY_CODE },
            ],
            ["a passkey", makeAssertionBody(), { mfaMethodId: "cred-id-1", challenge: "c" }],
        ];

        beforeEach(() => {
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            options.checkPendingRateLimit = vi.fn().mockResolvedValue(undefined);
            (options.getMethod as any).mockResolvedValue(undefined);
            (options.getCredentialById as any).mockResolvedValue(undefined);
        });

        it.each(phases)(
            "Counts %s on the session's pending uid through checkPendingRateLimit, and not on the client's id.",
            async (_name, body, extra) => {
                const req = makeReq({ body, session: { mfaPendingUid: "user-uid-1", ...extra } });

                await strategy.authenticate(req, makeRes(), false).catch(() => undefined);

                expect(options.checkPendingRateLimit).toHaveBeenCalledTimes(1);
                expect(options.checkPendingRateLimit).toHaveBeenCalledWith("user-uid-1", req);
                expect(options.checkRateLimit).not.toHaveBeenCalled();
            },
        );

        it.each(phases)(
            "Counts nothing for %s when there is no pending identity, whatever id the request names.",
            async (_name, body, extra) => {
                const req = makeReq({ body: { ...body, ...(body.id === "user-uid-1" ? { id: "victim-uid" } : {}) }, session: extra });

                await strategy.authenticate(req, makeRes(), false).catch(() => undefined);

                expect(options.checkPendingRateLimit).not.toHaveBeenCalled();
                expect(options.checkRateLimit).not.toHaveBeenCalled();
            },
        );

        it.each(phases.filter(([name]) => name !== "a passkey"))(
            "Counts nothing for %s when the request names someone other than the pending user, and drops the pending state.",
            async (_name, body, extra) => {
                const req = makeReq({
                    body: { ...body, id: "victim-uid" },
                    session: { mfaPendingUid: "user-uid-1", ...extra },
                });

                await strategy.authenticate(req, makeRes(), false).catch(() => undefined);

                expect(options.checkPendingRateLimit).not.toHaveBeenCalled();
                expect(options.checkRateLimit).not.toHaveBeenCalled();
                expect((req.session as any).mfaPendingUid).toBeUndefined();
            },
        );

        // A refused challenge keeps the pending identity (the user retries once the window passes); every phase-3 outcome clears it.
        it.each(phases.filter(([name]) => name !== "challenge"))("Clears the pending state and fails when the limit for %s refuses.", async (_name, body, extra) => {
            options.checkPendingRateLimit = vi.fn().mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow"));
            const req = makeReq({ body, session: { mfaPendingUid: "user-uid-1", ...extra } });

            await expect(strategy.authenticate(req, makeRes(), false)).rejects.toMatchObject({ status: 429 });

            expect((req.session as any).mfaPendingUid).toBeUndefined();
            expect(options.getUser).not.toHaveBeenCalled();
        });

        it("Falls back to checkRateLimit with the pending uid when no pending limit is supplied.", async () => {
            options.checkPendingRateLimit = undefined;
            const req = makeReq({
                body: { id: "user-uid-1", token: "123456" },
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "s", mfaMethodType: MFAMethodType.TOTP },
            });

            await strategy.authenticate(req, makeRes(), false).catch(() => undefined);

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        it("Does not need any limit hook at all.", async () => {
            options.checkPendingRateLimit = undefined;
            options.checkRateLimit = undefined;
            const req = makeReq({
                body: { id: "user-uid-1", token: "123456" },
                session: { mfaPendingUid: "user-uid-1", mfaMethodId: "s", mfaMethodType: MFAMethodType.TOTP },
            });

            await expect(strategy.authenticate(req, makeRes(), false)).resolves.toBeUndefined();
        });
    });

    it.each([
        ["a TOTP code", MFAMethodType.TOTP, "123456"],
        ["a recovery code", MFAMethodType.RECOVERY_CODE, "AAAAA-AAAAA"],
    ])("Fails %s when the pending identity matches but no method was selected.", async (_name, type, token) => {
        const req = makeReq({
            body: { id: "user-uid-1", token },
            session: { mfaPendingUid: "user-uid-1", mfaMethodType: type },
        });

        await expect(strategy.authenticate(req, makeRes(), false)).resolves.toBeUndefined();

        expect(options.getMethod).not.toHaveBeenCalled();
        expect((req.session as any).mfaPendingUid).toBeUndefined();
    });

    it("Starting a new password attempt clears the method and challenge an earlier attempt selected.", async () => {
        const req = makeReq({
            body: { id: "user-uid-1", password: "password" },
            session: {
                mfaPendingUid: "other-uid",
                mfaMethodId: "stale-method",
                mfaMethodType: MFAMethodType.TOTP,
                challenge: "stale-challenge",
            },
        });
        (options.verify as any).mockResolvedValue(jwtUser);
        (options.getMethods as any).mockResolvedValue([{ id: "m", type: MFAMethodType.OTP, data: {} }]);

        await strategy.authenticate(req, makeRes(), false);

        expect((req.session as any).mfaPendingUid).toBe("user-uid-1");
        expect((req.session as any).mfaMethodId).toBeUndefined();
        expect((req.session as any).mfaMethodType).toBeUndefined();
        expect((req.session as any).challenge).toBeUndefined();
    });

    it("Starting a new password attempt that then fails leaves no stale method either.", async () => {
        const req = makeReq({
            body: { id: "user-uid-1", password: "wrong" },
            session: { mfaPendingUid: "user-uid-1", mfaMethodId: "stale", mfaMethodType: MFAMethodType.RECOVERY_CODE },
        });
        (options.verify as any).mockResolvedValue(undefined);

        await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Invalid user id or password/);

        expect((req.session as any).mfaMethodId).toBeUndefined();
        expect((req.session as any).mfaMethodType).toBeUndefined();
    });
});


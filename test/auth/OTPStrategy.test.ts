///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for OTPStrategy — no HTTP server, no database. Uses the real shared.ts OTP
// helpers (and real otplib), exactly as the HTTP-level AuthOTPRoute suites do.
import { ApiError, type JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { OTPStrategy, OTPStrategyOptions } from "../../src/auth/OTPStrategy.js";
import { OTPCounters } from "../../src/auth/OTPCounters.js";
import { counterKeyPart as h, generateOTP } from "../../src/auth/shared.js";
import { OTPContactType } from "../../src/auth/types.js";

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "POST",
        path: "/auth/otp",
        url: "/auth/otp",
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

const jwtUser: JWTUser = { uid: "user-uid-1", name: "test", roles: [] };

describe("OTPStrategy Tests", () => {
    let options: OTPStrategyOptions;
    let strategy: OTPStrategy;

    beforeEach(() => {
        options = new OTPStrategyOptions();
        options.getContact = vi.fn();
        options.getContacts = vi.fn();
        options.getUser = vi.fn();
        options.notifyContact = vi.fn();
        strategy = new OTPStrategy(options);
    });

    it("authenticateSync throws 'Not supported'.", () => {
        expect(() => strategy.authenticateSync(makeReq(), makeRes())).toThrow(/Not supported/);
    });

    describe("Dispatch", () => {
        it("Throws when nothing matches and auth is required.", async () => {
            const req = makeReq({ body: {} });
            await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(
                /Invalid authentication request/,
            );
        });

        it("Returns undefined when nothing matches and auth is not required.", async () => {
            const req = makeReq({ body: {} });
            const result = await strategy.authenticate(req, makeRes(), false);
            expect(result).toBeUndefined();
        });

        it("Ignores discovery when allowDiscovery is not enabled.", async () => {
            const req = makeReq({ body: {} });
            const result = await strategy.authenticate(req, makeRes(), false);
            expect(options.getContacts).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });
    });

    describe("discovery", () => {
        beforeEach(() => {
            options.allowDiscovery = true;
        });

        it("Obfuscates a WhatsApp contact like an SMS one.", async () => {
            (options.getContacts as any).mockResolvedValue([
                { contact: "+15551234567", type: OTPContactType.SMS, verified: true },
                { contact: "+15551234567", type: OTPContactType.WHATSAPP, verified: true },
            ]);
            const res = makeRes();

            await strategy.authenticate(makeReq({ body: {}, query: { id: "user-uid-1" } }), res, false);

            expect(res.json).toHaveBeenCalledWith([
                { contact: "********4567", type: OTPContactType.SMS },
                { contact: "********4567", type: OTPContactType.WHATSAPP },
            ]);
        });

        it("Returns obfuscated contacts for the given id.", async () => {
            (options.getContacts as any).mockResolvedValue([
                { contact: "john.smith@gmail.com", type: OTPContactType.EMAIL, verified: true },
            ]);
            const req = makeReq({ body: {}, query: { id: "user-uid-1" } });
            const res = makeRes();

            const result = await strategy.authenticate(req, res, false);

            expect(result).toBeUndefined();
            expect(options.getContacts).toHaveBeenCalledWith("user-uid-1");
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith([{ contact: "j***th@gmail.com", type: OTPContactType.EMAIL }]);
        });

        it("Passes undefined when no id query param is given.", async () => {
            (options.getContacts as any).mockResolvedValue([]);
            const req = makeReq({ body: {}, query: {} });

            await strategy.authenticate(req, makeRes(), false);

            expect(options.getContacts).toHaveBeenCalledWith(undefined);
        });

        it("Defaults to an empty list when getContacts() resolves nullish.", async () => {
            (options.getContacts as any).mockResolvedValue(undefined);
            const req = makeReq({ body: {}, query: { id: "user-uid-1" } });
            const res = makeRes();

            await strategy.authenticate(req, res, false);

            expect(res.json).toHaveBeenCalledWith([]);
        });

        it("Invokes checkRateLimit with the queried id before listing contacts.", async () => {
            (options.getContacts as any).mockResolvedValue([]);
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            const req = makeReq({ body: {}, query: { id: "user-uid-1" } });

            await strategy.authenticate(req, makeRes(), false);

            expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
        });

        // Regression: this used to skip rate limiting entirely when `id` was omitted, so a caller could
        // dodge the throttle simply by never sending the query parameter, even though `getContacts(undefined)`
        // still runs. A fixed bucket key is used instead so an omitted `id` is still throttled.
        it("Still invokes checkRateLimit (on a fixed bucket) when no id query param is given.", async () => {
            (options.getContacts as any).mockResolvedValue([]);
            options.checkRateLimit = vi.fn();
            const req = makeReq({ body: {}, query: {} });

            await strategy.authenticate(req, makeRes(), false);

            expect(options.checkRateLimit).toHaveBeenCalledWith(expect.any(String), req);
        });

        it("Aborts before listing contacts when checkRateLimit throws.", async () => {
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));
            const req = makeReq({ body: {}, query: { id: "user-uid-1" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.getContacts).not.toHaveBeenCalled();
        });
    });

    describe("challenge (phase 2)", () => {
        it("Throws if req.session is missing.", async () => {
            const req = makeReq({ body: { id: "contact-1" }, session: undefined });
            // Regression: a deployment misconfiguration, not a client-caused auth failure - must surface
            // as a distinguishable 500, not get flattened into a generic 401.
            await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({
                status: 500,
                message: expect.stringMatching(/session support/),
            });
        });

        it("Commits the exact same response as a real contact when the contact id is unknown, without sending a notification.", async () => {
            (options.getContact as any).mockResolvedValue(undefined);
            const req = makeReq({ body: { id: "unknown-contact" } });
            const res = makeRes();

            const result = await strategy.authenticate(req, res, false);

            expect(result).toBeUndefined();
            expect(options.notifyContact).not.toHaveBeenCalled();
            // Same response as the "contact exists" case below — an unknown contact must not be
            // distinguishable via response shape/status.
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Enforces the issue limit identically for known and unknown contacts, before the lookup.", async () => {
            const counters = new OTPCounters();
            const limit = vi
                .spyOn(counters, "throttle")
                .mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow down"));
            options.counters = counters;
            for (const contact of [undefined, { contact: "a@example.com", type: OTPContactType.EMAIL, verified: true }]) {
                (options.getContact as any).mockResolvedValue(contact);
                const req = makeReq({ body: { id: "contact-1" } });
                await expect(strategy.authenticate(req, makeRes())).rejects.toMatchObject({ status: 429 });
            }
            expect(options.getContact).not.toHaveBeenCalled();
            expect(options.notifyContact).not.toHaveBeenCalled();
            expect(limit).toHaveBeenCalledWith(`issue:login:${h("contact-1")}:${h("unknown")}`, { maxAttempts: 5, windowSeconds: 900 });
        });

        it("Issues the code for the login purpose, recording the user the contact belongs to.", async () => {
            (options.getContact as any).mockResolvedValue({
                contact: "test@example.com",
                type: OTPContactType.EMAIL,
                verified: true,
                userUid: "user-uid-1",
            });
            const req = makeReq({ body: { id: "contact-1" } });
            await strategy.authenticate(req, makeRes());
            expect((req.session as any).otp.purpose).toBe("login");
            expect((req.session as any).otp.userUid).toBe("user-uid-1");
        });

        it("Generates and sends a token, then completes the response.", async () => {
            const contact = { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true };
            (options.getContact as any).mockResolvedValue(contact);
            const req = makeReq({ body: { id: "contact-1" } });
            const res = makeRes();

            const result = await strategy.authenticate(req, res);

            expect(result).toBeUndefined();
            expect(options.notifyContact).toHaveBeenCalledWith(contact, expect.any(String));
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
            expect((req.session as any).otp.id).toBe("contact-1");
        });

        it("Looks the contact up without a channel when the request names none.", async () => {
            (options.getContact as any).mockResolvedValue(undefined);

            await strategy.authenticate(makeReq({ body: { id: "contact-1" } }), makeRes());

            expect(options.getContact).toHaveBeenCalledWith("contact-1", undefined);
        });

        it("Passes the requested channel to getContact and notifies the contact it returns.", async () => {
            const contact = { contact: "+15551234567", type: OTPContactType.WHATSAPP, verified: true };
            (options.getContact as any).mockResolvedValue(contact);
            const req = makeReq({ body: { id: "contact-1", channel: "whatsapp" } });
            const res = makeRes();

            await strategy.authenticate(req, res);

            expect(options.getContact).toHaveBeenCalledWith("contact-1", "whatsapp");
            expect(options.notifyContact).toHaveBeenCalledWith(contact, expect.any(String));
            expect((req.session as any).otp.id).toBe("contact-1");
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Ignores a channel that is not a string.", async () => {
            (options.getContact as any).mockResolvedValue(undefined);

            await strategy.authenticate(makeReq({ body: { id: "contact-1", channel: { $ne: null } } }), makeRes());

            expect(options.getContact).toHaveBeenCalledWith("contact-1", undefined);
        });

        it("Commits the same response, and sends nothing, when the requested channel isn't available.", async () => {
            (options.getContact as any).mockResolvedValue(undefined);
            const res = makeRes();

            await strategy.authenticate(makeReq({ body: { id: "contact-1", channel: "whatsapp" } }), res);

            expect(options.notifyContact).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Invokes checkRateLimit before generating/sending a new OTP.", async () => {
            const contact = { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true };
            (options.getContact as any).mockResolvedValue(contact);
            options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
            const req = makeReq({ body: { id: "contact-1" } });

            await strategy.authenticate(req, makeRes());

            expect(options.checkRateLimit).toHaveBeenCalledWith("contact-1", req);
        });

        it("Aborts before sending a new OTP when checkRateLimit throws.", async () => {
            const contact = { contact: "test@example.com", type: OTPContactType.EMAIL, verified: true };
            (options.getContact as any).mockResolvedValue(contact);
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));
            const req = makeReq({ body: { id: "contact-1" } });

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.notifyContact).not.toHaveBeenCalled();
        });
    });

    describe("verify (phase 3)", () => {
        it("Authenticates when the OTP token is valid.", async () => {
            const req = makeReq({ body: { id: "contact-1" } });
            const token = await generateOTP(req, { id: "contact-1" }, undefined, "login");
            req.body.token = token;
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.getUser).toHaveBeenCalledWith("contact-1");
            expect(result).toEqual({
                data: { id: "contact-1", token },
                method: "otp",
                payload: { id: "contact-1", token },
                user: jwtUser,
            });
        });

        it("Falls through to the required check when the OTP token is invalid.", async () => {
            const req = makeReq({ body: { id: "contact-1", token: "000000" } });
            await generateOTP(req, { id: "contact-1" }, undefined, "login");
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes(), false);

            // The user is resolved up front (for the per-user limit) but never returned without a valid code.
            expect(result).toBeUndefined();
        });

        // Regression (security): a code issued for another flow in the same session must not sign anyone in.
        it("Rejects a code issued for another purpose (registration, MFA, elevation, contact verification).", async () => {
            for (const purpose of ["register", "mfa", "elevate", "contact"] as const) {
                const req = makeReq({ body: { id: "contact-1" } });
                req.body.token = await generateOTP(req, { id: "contact-1" }, undefined, purpose);
                (options.getUser as any).mockResolvedValue(jwtUser);

                await expect(strategy.authenticate(req, makeRes(), false)).rejects.toThrow(
                    /Invalid authentication request/,
                );
            }
        });

        it("Counts verification against the contact and the user the code was issued for, and refuses once limited.", async () => {
            const req = makeReq({ body: { id: "contact-1" } });
            req.body.token = await generateOTP(req, { id: "contact-1" }, undefined, "login", "user-uid-1");
            const counters = new OTPCounters();
            const throttle = vi.spyOn(counters, "throttle");
            options.counters = counters;
            (options.getUser as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(result?.user).toEqual(jwtUser);
            const keys = throttle.mock.calls.map((c) => c[0]);
            expect(keys).toContain(`verify:login:${h("contact-1")}:${h("unknown")}`);
            expect(keys).toContain(`user:login:${h("user-uid-1")}:${h("unknown")}`);

            const again = makeReq({ body: { id: "contact-1" } });
            again.body.token = await generateOTP(again, { id: "contact-1" }, undefined, "login", "user-uid-1");
            throttle.mockRejectedValue(new ApiError("AUTH_PERMISSION_FAILURE", 429, "slow down"));
            await expect(strategy.authenticate(again, makeRes())).rejects.toMatchObject({ status: 429 });
        });

        it("Looks the user up only after the code has been verified, never before.", async () => {
            const wrong = makeReq({ body: { id: "contact-1", token: "AAAAAA" } });
            await generateOTP(wrong, { id: "contact-1" }, undefined, "login", "user-uid-1");
            await strategy.authenticate(wrong, makeRes(), false);
            expect(options.getUser).not.toHaveBeenCalled();

            const none = makeReq({ body: { id: "contact-1", token: "AAAAAA" } });
            await expect(strategy.authenticate(none, makeRes())).rejects.toThrow(/Invalid authentication request/);
            expect(options.getUser).not.toHaveBeenCalled();
        });

        it("Fails fast, at construction, on an unsafe one-time code configuration.", () => {
            const bad = new OTPStrategyOptions();
            bad.otpConfig = { alphabet: "ab" };
            expect(() => new OTPStrategy(bad)).toThrow(/entropy/);
        });

        it("Aborts before verifying the token when checkRateLimit throws.", async () => {
            const req = makeReq({ body: { id: "contact-1" } });
            req.body.token = await generateOTP(req, { id: "contact-1" }, undefined, "login");
            options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));

            await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
            expect(options.getUser).not.toHaveBeenCalled();
        });
    });

    describe("Default OTPStrategyOptions", () => {
        const defaultOptions = new OTPStrategyOptions();

        it("getContact throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getContact("contact-1")).toThrow(
                /Did you forget to override OTPStrategyOptions.getContact/,
            );
        });

        it("getContacts throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getContacts("user-uid-1")).toThrow(
                /Did you forget to override OTPStrategyOptions.getContacts/,
            );
        });

        it("getUser throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getUser("user-uid-1")).toThrow(
                /Did you forget to override OTPStrategyOptions.getUsers/,
            );
        });

        it("notifyContact throws if the consumer forgot to override it.", () => {
            expect(() =>
                defaultOptions.notifyContact({ contact: "test@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).toThrow(/Did you forget to override OTPStrategyOptions.notify/);
        });
    });
});

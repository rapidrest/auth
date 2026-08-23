///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for OTPStrategy — no HTTP server, no database. Uses the real shared.ts OTP
// helpers (and real otplib), exactly as the HTTP-level AuthOTPRoute suites do.
import type { JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import * as otplib from "otplib";
import { OTPStrategy, OTPStrategyOptions } from "../../src/auth/OTPStrategy.js";
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
            expect((req.session as any).id).toBe("contact-1");
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
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({
                body: { id: "contact-1", token },
                session: { id: "contact-1", secret },
            });
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
            const req = makeReq({
                body: { id: "contact-1", token: "000000" },
                session: { id: "contact-1", secret: otplib.generateSecret() },
            });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(options.getUser).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });

        it("Aborts before verifying the token when checkRateLimit throws.", async () => {
            const secret = otplib.generateSecret();
            const token = await otplib.generate({ secret });
            const req = makeReq({
                body: { id: "contact-1", token },
                session: { id: "contact-1", secret },
            });
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

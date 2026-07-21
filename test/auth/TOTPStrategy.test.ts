///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for TOTPStrategy — no HTTP server, no database. Uses the real shared.ts
// verifyTOTP/otplib, exactly as the HTTP-level AuthTOTPRoute suites do.
import type { JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import * as otplib from "otplib";
import { TOTPStrategy, TOTPStrategyOptions } from "../../src/auth/TOTPStrategy.js";
import { TOTPSecret } from "../../src/auth/types.js";

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "GET",
        path: "/auth/totp",
        url: "/auth/totp",
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

describe("TOTPStrategy Tests", () => {
    let options: TOTPStrategyOptions;
    let strategy: TOTPStrategy;

    beforeEach(() => {
        options = new TOTPStrategyOptions();
        options.getSecrets = vi.fn();
        options.getUser = vi.fn();
        strategy = new TOTPStrategy(options);
    });

    it("Uses default options when none are provided to the constructor.", async () => {
        const defaultStrategy = new TOTPStrategy();
        const req = makeReq({ body: { id: "user-uid-1", token: "123456" } });

        await expect(defaultStrategy.authenticate(req, makeRes())).rejects.toThrow(
            /Did you forget to override TOTPStrategyOptions.getUser/,
        );
    });

    it("authenticateSync throws 'Not supported'.", () => {
        expect(() => strategy.authenticateSync(makeReq(), makeRes())).toThrow(/Not supported/);
    });

    it("Authenticates with a valid TOTP token.", async () => {
        const secret: TOTPSecret = { secret: otplib.generateSecret() };
        const token = await otplib.generate(secret);
        (options.getUser as any).mockResolvedValue(jwtUser);
        (options.getSecrets as any).mockResolvedValue([secret]);
        const req = makeReq({ body: { id: "user-uid-1", token } });

        const result = await strategy.authenticate(req, makeRes());

        expect(options.getUser).toHaveBeenCalledWith("user-uid-1");
        expect(options.getSecrets).toHaveBeenCalledWith(jwtUser.uid);
        expect(result).toEqual({
            data: { id: "user-uid-1", token },
            method: "totp",
            payload: { id: "user-uid-1", token },
            user: jwtUser,
        });
    });

    it("Authenticates when at least one of multiple secrets is valid.", async () => {
        const goodSecret: TOTPSecret = { secret: otplib.generateSecret() };
        const badSecret: TOTPSecret = { secret: otplib.generateSecret() };
        const token = await otplib.generate(goodSecret);
        (options.getUser as any).mockResolvedValue(jwtUser);
        (options.getSecrets as any).mockResolvedValue([badSecret, goodSecret]);
        const req = makeReq({ body: { id: "user-uid-1", token } });

        const result = await strategy.authenticate(req, makeRes());

        expect(result?.user).toEqual(jwtUser);
    });

    it("Throws when the user id does not resolve and auth is required.", async () => {
        (options.getUser as any).mockResolvedValue(undefined);
        const req = makeReq({ body: { id: "unknown-user", token: "123456" } });

        await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(/Invalid authentiation request/);
        expect(options.getSecrets).not.toHaveBeenCalled();
    });

    it("Returns undefined when the user id does not resolve and auth is not required.", async () => {
        (options.getUser as any).mockResolvedValue(undefined);
        const req = makeReq({ body: { id: "unknown-user", token: "123456" } });

        const result = await strategy.authenticate(req, makeRes(), false);

        expect(result).toBeUndefined();
    });

    it("Throws when the user has no registered secrets.", async () => {
        (options.getUser as any).mockResolvedValue(jwtUser);
        (options.getSecrets as any).mockResolvedValue(undefined);
        const req = makeReq({ body: { id: "user-uid-1", token: "123456" } });

        await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(/Invalid authentiation request/);
    });

    it("Throws when the TOTP token is invalid for all registered secrets.", async () => {
        (options.getUser as any).mockResolvedValue(jwtUser);
        (options.getSecrets as any).mockResolvedValue([{ secret: otplib.generateSecret() }]);
        const req = makeReq({ body: { id: "user-uid-1", token: "000000" } });

        await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(/Invalid authentiation request/);
    });

    it("Invokes checkRateLimit with the claimed identifier before resolving the user.", async () => {
        const secret: TOTPSecret = { secret: otplib.generateSecret() };
        const token = await otplib.generate(secret);
        (options.getUser as any).mockResolvedValue(jwtUser);
        (options.getSecrets as any).mockResolvedValue([secret]);
        options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
        const req = makeReq({ body: { id: "user-uid-1", token } });

        await strategy.authenticate(req, makeRes());

        expect(options.checkRateLimit).toHaveBeenCalledWith("user-uid-1", req);
    });

    it("Invokes checkRateLimit even when the claimed id does not resolve to a real user (no enumeration bypass).", async () => {
        (options.getUser as any).mockResolvedValue(undefined);
        options.checkRateLimit = vi.fn().mockResolvedValue(undefined);
        const req = makeReq({ body: { id: "unknown-user", token: "123456" } });

        const result = await strategy.authenticate(req, makeRes(), false);

        expect(options.checkRateLimit).toHaveBeenCalledWith("unknown-user", req);
        expect(result).toBeUndefined();
    });

    it("Aborts before resolving the user when checkRateLimit throws.", async () => {
        options.checkRateLimit = vi.fn().mockRejectedValue(new Error("Too many attempts."));
        const req = makeReq({ body: { id: "user-uid-1", token: "123456" } });

        await expect(strategy.authenticate(req, makeRes())).rejects.toThrow(/Too many attempts/);
        expect(options.getUser).not.toHaveBeenCalled();
        expect(options.getSecrets).not.toHaveBeenCalled();
    });

    it("Does not invoke checkRateLimit when the request has no id.", async () => {
        options.checkRateLimit = vi.fn();
        const req = makeReq({ body: { token: "123456" } });

        await strategy.authenticate(req, makeRes(), false);

        expect(options.checkRateLimit).not.toHaveBeenCalled();
    });

    describe("Default TOTPStrategyOptions", () => {
        const defaultOptions = new TOTPStrategyOptions();

        it("getSecrets throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getSecrets("user-uid-1")).toThrow(
                /Did you forget to override TOTPStrategyOptions.getSecrets/,
            );
        });

        it("getUser throws if the consumer forgot to override it.", () => {
            expect(() => defaultOptions.getUser("user-uid-1")).toThrow(
                /Did you forget to override TOTPStrategyOptions.getUser/,
            );
        });
    });
});

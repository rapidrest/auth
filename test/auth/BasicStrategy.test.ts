///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BasicStrategy — no HTTP server, no database.
import type { JWTUser } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { BasicStrategy, BasicStrategyOptions } from "../../src/auth/BasicStrategy.js";

function makeReq(overrides: Partial<HttpRequest> = {}): HttpRequest {
    return {
        method: "GET",
        path: "/auth/basic",
        url: "/auth/basic",
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

describe("BasicStrategy Tests", () => {
    let options: BasicStrategyOptions;
    let strategy: BasicStrategy;

    beforeEach(() => {
        options = new BasicStrategyOptions();
        options.verify = vi.fn();
        options.verifySync = vi.fn();
        strategy = new BasicStrategy(options);
    });

    describe("authenticate", () => {
        it("Returns an AuthResult when verify() resolves a user.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "secret" } });
            (options.verify as any).mockResolvedValue(jwtUser);

            const result = await strategy.authenticate(req, makeRes());

            expect(options.verify).toHaveBeenCalledWith("user-uid-1", "secret");
            expect(result).toEqual({
                data: { id: "user-uid-1", password: "secret" },
                method: "basic",
                payload: { id: "user-uid-1", password: "secret" },
                user: jwtUser,
            });
        });

        it("Throws when verify() resolves undefined and auth is required.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "wrong" } });
            (options.verify as any).mockResolvedValue(undefined);

            await expect(strategy.authenticate(req, makeRes(), true)).rejects.toThrow(/Invalid authorization/);
        });

        it("Returns undefined when verify() resolves undefined and auth is not required.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "wrong" } });
            (options.verify as any).mockResolvedValue(undefined);

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(result).toBeUndefined();
        });

        it("Returns undefined without calling verify() when no id/password is present.", async () => {
            const req = makeReq({ body: {} });

            const result = await strategy.authenticate(req, makeRes(), false);

            expect(options.verify).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });

        it("The default verify() throws if the consumer forgot to override it.", async () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "secret" } });
            const defaultStrategy = new BasicStrategy();

            await expect(defaultStrategy.authenticate(req, makeRes())).rejects.toThrow(
                /Did you forget to override BasicStrategyOptions.verify/,
            );
        });
    });

    describe("authenticateSync", () => {
        it("Returns an AuthResult when verifySync() resolves a user.", () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "secret" } });
            (options.verifySync as any).mockReturnValue(jwtUser);

            const result = strategy.authenticateSync(req, makeRes());

            expect(options.verifySync).toHaveBeenCalledWith("user-uid-1", "secret");
            expect(result).toEqual({
                data: { id: "user-uid-1", password: "secret" },
                method: "basic",
                payload: { id: "user-uid-1", password: "secret" },
                user: jwtUser,
            });
        });

        it("Throws when verifySync() returns undefined and auth is required.", () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "wrong" } });
            (options.verifySync as any).mockReturnValue(undefined);

            expect(() => strategy.authenticateSync(req, makeRes(), true)).toThrow(/Invalid authorization/);
        });

        it("Returns undefined when verifySync() returns undefined and auth is not required.", () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "wrong" } });
            (options.verifySync as any).mockReturnValue(undefined);

            const result = strategy.authenticateSync(req, makeRes(), false);

            expect(result).toBeUndefined();
        });

        it("Returns undefined without calling verifySync() when no id/password is present.", () => {
            const req = makeReq({ body: {} });

            const result = strategy.authenticateSync(req, makeRes(), false);

            expect(options.verifySync).not.toHaveBeenCalled();
            expect(result).toBeUndefined();
        });

        it("The default verifySync() throws if the consumer forgot to override it.", () => {
            const req = makeReq({ body: { id: "user-uid-1", password: "secret" } });
            const defaultStrategy = new BasicStrategy();

            expect(() => defaultStrategy.authenticateSync(req, makeRes())).toThrow(
                /Did you forget to override BasicStrategyOptions.verifySync/,
            );
        });
    });
});

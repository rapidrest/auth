///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for OAuthBearerStrategy — no HTTP server, no database.
import { ApiError } from "@rapidrest/core";
import { OAuthBearerStrategy } from "../../src/auth/OAuthBearerStrategy.js";

function makeRequest(overrides: any = {}) {
    return {
        method: "GET",
        path: "/userinfo",
        url: "/userinfo",
        headers: {},
        params: {},
        query: {},
        body: {},
        cookies: {},
        signedCookies: {},
        socket: {},
        ...overrides,
    };
}

function makeStrategy(overrides: { verifyAccessToken?: any; isRevoked?: any } = {}) {
    const oauthTokenUtils = { verifyAccessToken: overrides.verifyAccessToken ?? vi.fn(async () => undefined) };
    const accessTokenDenylist = { isRevoked: overrides.isRevoked ?? vi.fn(async () => false) };
    const strategy = new OAuthBearerStrategy("oauth_bearer", oauthTokenUtils as any, accessTokenDenylist as any);
    return { strategy, oauthTokenUtils, accessTokenDenylist };
}

describe("OAuthBearerStrategy Tests", () => {
    it("Exposes its configured name.", () => {
        const { strategy } = makeStrategy();
        expect(strategy.name).toBe("oauth_bearer");
    });

    describe("authenticate", () => {
        it("Returns undefined when no Authorization header is present.", async () => {
            const { strategy } = makeStrategy();
            const result = await strategy.authenticate(makeRequest());
            expect(result).toBeUndefined();
        });

        it("Returns undefined when the token fails verification.", async () => {
            const { strategy } = makeStrategy({ verifyAccessToken: vi.fn(async () => undefined) });
            const req = makeRequest({ headers: { authorization: "Bearer bad-token" } });
            const result = await strategy.authenticate(req);
            expect(result).toBeUndefined();
        });

        it("Returns undefined when the token's jti has been revoked.", async () => {
            const { strategy } = makeStrategy({
                verifyAccessToken: vi.fn(async () => ({ sub: "user-1", scope: "openid", jti: "jti-1" })),
                isRevoked: vi.fn(async () => true),
            });
            const req = makeRequest({ headers: { authorization: "Bearer revoked-token" } });
            const result = await strategy.authenticate(req);
            expect(result).toBeUndefined();
        });

        it("Returns undefined when the verified claims carry no jti.", async () => {
            const { strategy } = makeStrategy({
                verifyAccessToken: vi.fn(async () => ({ sub: "user-1", scope: "openid" })),
            });
            const req = makeRequest({ headers: { authorization: "Bearer token-without-jti" } });
            const result = await strategy.authenticate(req);
            expect(result).toBeUndefined();
        });

        it("Returns an AuthResult with a JWTUser built from the verified claims.", async () => {
            const { strategy, accessTokenDenylist } = makeStrategy({
                verifyAccessToken: vi.fn(async () => ({ sub: "user-1", scope: "openid profile", jti: "jti-1", client_id: "abc123" })),
            });
            const req = makeRequest({ headers: { authorization: "Bearer good-token" } });

            const result = await strategy.authenticate(req);

            expect(result).toEqual({
                data: "good-token",
                method: "oauth_bearer",
                payload: { sub: "user-1", scope: "openid profile", jti: "jti-1", client_id: "abc123" },
                user: { uid: "user-1", roles: [], scopes: ["openid", "profile"] },
            });
            expect(accessTokenDenylist.isRevoked).toHaveBeenCalledWith("jti-1");
        });

        it("Defaults to an empty scopes array when the claims carry no scope.", async () => {
            const { strategy } = makeStrategy({
                verifyAccessToken: vi.fn(async () => ({ sub: "user-1", jti: "jti-1" })),
            });
            const req = makeRequest({ headers: { authorization: "Bearer good-token" } });

            const result = await strategy.authenticate(req);

            expect(result?.user?.scopes).toEqual([]);
        });

        it("Throws a 401 ApiError when required and no valid token was presented.", async () => {
            const { strategy } = makeStrategy();
            await expect(strategy.authenticate(makeRequest(), undefined, true)).rejects.toMatchObject({ status: 401 });
            await expect(strategy.authenticate(makeRequest(), undefined, true)).rejects.toBeInstanceOf(ApiError);
        });
    });

    describe("authenticateSync", () => {
        it("Throws a 500 ApiError - this strategy does not support synchronous authentication.", () => {
            const { strategy } = makeStrategy();
            expect(() => strategy.authenticateSync()).toThrow(/asynchronously/);
        });
    });
});

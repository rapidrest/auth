///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthIntrospectRoute — no HTTP server, no database.
import { ApiError } from "@rapidrest/core";
import { ApiErrors, RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthIntrospectRoute } from "../../src/routes/BaseOAuthIntrospectRoute.js";
import { AccessTokenDenylist } from "../../src/auth/AccessTokenDenylist.js";
import { ClientAuthUtils } from "../../src/auth/ClientAuthUtils.js";
import { OAuthTokenUtils } from "../../src/auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { Client, ClientType, OAuthRefreshToken, TokenEndpointAuthMethod } from "../../src/models/types.js";
import { hashOpaqueToken } from "../../src/auth/shared.js";

class FakeClientClass {
    static readonly name = "FakeClient";
}
class FakeOAuthRefreshTokenClass {
    static readonly name = "FakeOAuthRefreshToken";
}
class FakeSigningKeyClass {
    static readonly name = "FakeSigningKey";
}

class TestOAuthIntrospectRoute extends BaseOAuthIntrospectRoute<any, any> {
    protected clientClass: any = FakeClientClass;
    protected refreshTokenClass: any = FakeOAuthRefreshTokenClass;
    protected signingKeyClass: any = FakeSigningKeyClass;
}

function makeMockRepo<T>() {
    const store = new Map<string, T>();
    return {
        create: vi.fn(async (obj: Partial<T>) => obj),
        find: vi.fn(async () => []),
        findOne: vi.fn(async (id: string) => store.get(id)),
        update: vi.fn(async (obj: Partial<T>, existing: T) => ({ ...existing, ...obj })),
        _store: store,
    };
}

const client: Client = {
    uid: "client-record-1",
    dateCreated: new Date(),
    dateModified: new Date(),
    version: 0,
    clientId: "abc123",
    clientType: ClientType.CONFIDENTIAL,
    clientName: "Test App",
    redirectUris: ["https://app.example.com/callback"],
    grantTypes: ["authorization_code", "refresh_token"],
    responseTypes: ["code"],
    scope: "openid profile",
    tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    requirePkce: false,
    firstParty: false,
};

const publicClient: Client = { ...client, clientId: "mobile-1", clientType: ClientType.PUBLIC };

function makeOAuthRefreshToken(overrides: Partial<OAuthRefreshToken> = {}): OAuthRefreshToken {
    return {
        uid: "refresh-record-1",
        dateCreated: new Date(),
        dateModified: new Date(),
        version: 0,
        tokenHash: "",
        clientId: client.clientId,
        userUid: "user-1",
        scope: "profile",
        familyId: "family-1",
        expiresAt: new Date(Date.now() + 60_000),
        revoked: false,
        ...overrides,
    };
}

function makeRoute() {
    const clientRepo = makeMockRepo<Client>();
    const refreshTokenRepo = makeMockRepo<OAuthRefreshToken>();

    const route = new TestOAuthIntrospectRoute();
    (route as any)._objectFactory = {
        newInstance: vi.fn(async (type: any, opts: any) => {
            if (type === RepoUtils) {
                if (opts.name === FakeClientClass.name) return clientRepo;
                if (opts.name === FakeOAuthRefreshTokenClass.name) return refreshTokenRepo;
            }
            return undefined;
        }),
    };
    (route as any).clientRepo = clientRepo;
    (route as any).refreshTokenRepo = refreshTokenRepo;
    (route as any).clientAuthUtils = { authenticateClient: vi.fn(async () => client) };
    (route as any).accessTokenDenylist = { revoke: vi.fn(), isRevoked: vi.fn(async () => false) };
    (route as any).oauthTokenUtils = { verifyAccessToken: vi.fn(async () => undefined) };
    (route as any).rateLimiter = { checkAndIncrement: vi.fn() };

    return { route, clientRepo, refreshTokenRepo };
}

function makeRequest(overrides: any = {}) {
    return {
        method: "POST",
        path: "/oauth/introspect",
        url: "/oauth/introspect",
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

function makeResponse() {
    return { setHeader: vi.fn(), status: vi.fn(), json: vi.fn() };
}

describe("BaseOAuthIntrospectRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthIntrospectRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Builds clientRepo, refreshTokenRepo, clientAuthUtils, accessTokenDenylist, and oauthTokenUtils via the object factory.", async () => {
            const clientRepo = makeMockRepo<Client>();
            const refreshTokenRepo = makeMockRepo<OAuthRefreshToken>();
            const signingKeyRepo = makeMockRepo<any>();
            const clientAuthUtils = {};
            const signingKeyUtils = {};
            const oauthTokenUtils = {};
            const accessTokenDenylist = {};

            const route = new TestOAuthIntrospectRoute();
            (route as any)._objectFactory = {
                newInstance: vi.fn(async (type: any, opts: any) => {
                    if (type === RepoUtils) {
                        if (opts.name === FakeClientClass.name) return clientRepo;
                        if (opts.name === FakeOAuthRefreshTokenClass.name) return refreshTokenRepo;
                        if (opts.name === FakeSigningKeyClass.name) return signingKeyRepo;
                    }
                    if (type === ClientAuthUtils) return clientAuthUtils;
                    if (type === SigningKeyUtils) return signingKeyUtils;
                    if (type === OAuthTokenUtils) return oauthTokenUtils;
                    if (type === AccessTokenDenylist) return accessTokenDenylist;
                    return undefined;
                }),
            };

            await (route as any).initialize();

            expect((route as any).clientRepo).toBe(clientRepo);
            expect((route as any).refreshTokenRepo).toBe(refreshTokenRepo);
            expect((route as any).clientAuthUtils).toBe(clientAuthUtils);
            expect((route as any).accessTokenDenylist).toBe(accessTokenDenylist);
            expect((route as any).oauthTokenUtils).toBe(oauthTokenUtils);
        });

        it("Does not recreate any repo/utils if initialize() runs again.", async () => {
            const { route, clientRepo, refreshTokenRepo } = makeRoute();
            const newInstance = (route as any)._objectFactory.newInstance;

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).clientRepo).toBe(clientRepo);
            expect((route as any).refreshTokenRepo).toBe(refreshTokenRepo);
        });
    });

    describe("introspect", () => {
        it("Always sets Cache-Control: no-store.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.introspect(makeRequest({ body: { token: "some-token" } }), res);
            expect(res.setHeader).toHaveBeenCalledWith("Cache-Control", "no-store");
        });

        it("Fails with invalid_client when the caller is a public client.", async () => {
            const { route } = makeRoute();
            (route as any).clientAuthUtils = { authenticateClient: vi.fn(async () => publicClient) };
            const res = makeResponse();
            await route.introspect(makeRequest({ body: { token: "some-token" } }), res);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_client" }));
        });

        it("Maps a 401 ApiError (client auth failure) to invalid_client.", async () => {
            const { route } = makeRoute();
            (route as any).clientAuthUtils = {
                authenticateClient: vi.fn(async () => {
                    throw new ApiError(ApiErrors.AUTH_FAILED, 401, "Invalid client.");
                }),
            };
            const res = makeResponse();
            await route.introspect(makeRequest({ body: { token: "some-token" } }), res);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: "invalid_client", error_description: "Invalid client." });
        });

        it("Maps a plain Error to a 500 server_error.", async () => {
            const { route } = makeRoute();
            (route as any).rateLimiter = {
                checkAndIncrement: vi.fn(async () => {
                    throw new Error("boom");
                }),
            };
            const res = makeResponse();
            await route.introspect(makeRequest({ body: { token: "some-token" } }), res);
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ error: "server_error" });
        });

        it("Fails with invalid_request when token is missing.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.introspect(makeRequest({ body: {} }), res);
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_request" }));
        });

        it("Returns {active:false} for a completely unknown token.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.introspect(makeRequest({ body: { token: "does-not-exist" } }), res);
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ active: false });
        });

        describe("refresh tokens", () => {
            it("Returns active:true with the refresh token's metadata.", async () => {
                const { route, refreshTokenRepo } = makeRoute();
                const raw = "raw-refresh-1";
                const stored = makeOAuthRefreshToken();
                refreshTokenRepo._store.set(hashOpaqueToken(raw), stored);
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: raw } }), res);

                expect(res.json).toHaveBeenCalledWith({
                    active: true,
                    token_type: "refresh_token",
                    client_id: client.clientId,
                    scope: "profile",
                    exp: Math.floor(stored.expiresAt.getTime() / 1000),
                    sub: "user-1",
                });
            });

            it("Omits sub when the refresh token has no userUid.", async () => {
                const { route, refreshTokenRepo } = makeRoute();
                const raw = "raw-refresh-1";
                refreshTokenRepo._store.set(hashOpaqueToken(raw), makeOAuthRefreshToken({ userUid: undefined }));
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: raw } }), res);

                const body = res.json.mock.calls[0][0];
                expect(body.active).toBe(true);
                expect("sub" in body).toBe(false);
            });

            it("Returns {active:false} for a revoked refresh token.", async () => {
                const { route, refreshTokenRepo } = makeRoute();
                const raw = "raw-refresh-1";
                refreshTokenRepo._store.set(hashOpaqueToken(raw), makeOAuthRefreshToken({ revoked: true }));
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: raw } }), res);

                expect(res.json).toHaveBeenCalledWith({ active: false });
            });

            it("Returns {active:false} for an expired refresh token.", async () => {
                const { route, refreshTokenRepo } = makeRoute();
                const raw = "raw-refresh-1";
                refreshTokenRepo._store.set(hashOpaqueToken(raw), makeOAuthRefreshToken({ expiresAt: new Date(Date.now() - 1000) }));
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: raw } }), res);

                expect(res.json).toHaveBeenCalledWith({ active: false });
            });
        });

        describe("access tokens", () => {
            it("Returns active:true with the access token's claims.", async () => {
                const { route } = makeRoute();
                (route as any).oauthTokenUtils = {
                    verifyAccessToken: vi.fn(async () => ({
                        client_id: client.clientId,
                        scope: "openid profile",
                        sub: "user-1",
                        jti: "jti-1",
                        exp: 1700000900,
                        iat: 1700000000,
                    })),
                };
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: "some-access-token" } }), res);

                expect(res.json).toHaveBeenCalledWith({
                    active: true,
                    token_type: "access_token",
                    client_id: client.clientId,
                    scope: "openid profile",
                    sub: "user-1",
                    exp: 1700000900,
                    iat: 1700000000,
                });
            });

            it("Returns {active:false} for an invalid/expired access token signature.", async () => {
                const { route } = makeRoute();
                (route as any).oauthTokenUtils = { verifyAccessToken: vi.fn(async () => undefined) };
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: "garbage" } }), res);

                expect(res.json).toHaveBeenCalledWith({ active: false });
            });

            it("Returns {active:false} once the access token's jti has been denylisted (revoked).", async () => {
                const { route } = makeRoute();
                (route as any).oauthTokenUtils = {
                    verifyAccessToken: vi.fn(async () => ({ client_id: client.clientId, jti: "jti-1", scope: "profile", sub: "user-1" })),
                };
                (route as any).accessTokenDenylist = { revoke: vi.fn(), isRevoked: vi.fn(async () => true) };
                const res = makeResponse();

                await route.introspect(makeRequest({ body: { token: "revoked-access-token" } }), res);

                expect(res.json).toHaveBeenCalledWith({ active: false });
            });
        });
    });
});

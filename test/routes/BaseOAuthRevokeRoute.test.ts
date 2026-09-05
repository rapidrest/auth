///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthRevokeRoute — no HTTP server, no database.
import { ApiError } from "@rapidrest/core";
import { ApiErrors, RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthRevokeRoute } from "../../src/routes/BaseOAuthRevokeRoute.js";
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

class TestOAuthRevokeRoute extends BaseOAuthRevokeRoute<any, any> {
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
        update: vi.fn(async (obj: Partial<T>, existing: T) => {
            if ((obj as any).uid !== (existing as any).uid || (obj as any).version !== (existing as any).version) {
                throw new Error("Invalid object version. Do you have the latest version?");
            }
            return { ...existing, ...obj, version: (existing as any).version + 1 };
        }),
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

    const route = new TestOAuthRevokeRoute();
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
        path: "/oauth/revoke",
        url: "/oauth/revoke",
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

describe("BaseOAuthRevokeRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthRevokeRoute();
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

            const route = new TestOAuthRevokeRoute();
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

    describe("revoke", () => {
        it("Fails with invalid_request when token is missing.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.revoke(makeRequest({ body: {} }), res);
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_request" }));
        });

        it("Maps a 401 ApiError (client auth failure) to invalid_client.", async () => {
            const { route } = makeRoute();
            (route as any).clientAuthUtils = {
                authenticateClient: vi.fn(async () => {
                    throw new ApiError(ApiErrors.AUTH_FAILED, 401, "Invalid client.");
                }),
            };
            const res = makeResponse();
            await route.revoke(makeRequest({ body: { token: "some-token" } }), res);
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
            await route.revoke(makeRequest({ body: { token: "some-token" } }), res);
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ error: "server_error" });
        });

        it("Returns 200 with an empty body for a token that doesn't exist at all.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.revoke(makeRequest({ body: { token: "does-not-exist" } }), res);
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Revokes a matching refresh token.", async () => {
            const { route, refreshTokenRepo } = makeRoute();
            const raw = "raw-refresh-1";
            const stored = makeOAuthRefreshToken();
            refreshTokenRepo._store.set(hashOpaqueToken(raw), stored);
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: raw } }), res);

            expect(refreshTokenRepo.update).toHaveBeenCalledWith(
                expect.objectContaining({ uid: stored.uid, version: stored.version, revoked: true }),
                stored,
                { ignoreACL: true },
            );
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Does not revoke a refresh token belonging to a different client.", async () => {
            const { route, refreshTokenRepo } = makeRoute();
            const raw = "raw-refresh-1";
            refreshTokenRepo._store.set(hashOpaqueToken(raw), makeOAuthRefreshToken({ clientId: "someone-else" }));
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: raw } }), res);

            expect(refreshTokenRepo.update).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({});
        });

        it("Is a no-op for a refresh token that's already revoked.", async () => {
            const { route, refreshTokenRepo } = makeRoute();
            const raw = "raw-refresh-1";
            refreshTokenRepo._store.set(hashOpaqueToken(raw), makeOAuthRefreshToken({ revoked: true }));
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: raw } }), res);

            expect(refreshTokenRepo.update).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
        });

        it("Falls back to denylisting an access token when the refresh-token lookup finds nothing.", async () => {
            const { route } = makeRoute();
            (route as any).oauthTokenUtils = {
                verifyAccessToken: vi.fn(async () => ({ client_id: client.clientId, jti: "jti-1", exp: Math.floor(Date.now() / 1000) + 300 })),
            };
            const denylist = { revoke: vi.fn(), isRevoked: vi.fn(async () => false) };
            (route as any).accessTokenDenylist = denylist;
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: "some-access-token" } }), res);

            expect(denylist.revoke).toHaveBeenCalledWith("jti-1", expect.any(Number));
            expect(res.status).toHaveBeenCalledWith(200);
        });

        it("Does not denylist an access token belonging to a different client.", async () => {
            const { route } = makeRoute();
            (route as any).oauthTokenUtils = {
                verifyAccessToken: vi.fn(async () => ({ client_id: "someone-else", jti: "jti-1", exp: Math.floor(Date.now() / 1000) + 300 })),
            };
            const denylist = { revoke: vi.fn(), isRevoked: vi.fn(async () => false) };
            (route as any).accessTokenDenylist = denylist;
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: "some-access-token" } }), res);

            expect(denylist.revoke).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(200);
        });

        it("Treats a missing exp claim as an already-expired token (ttlSeconds 0) rather than denylisting forever.", async () => {
            const { route } = makeRoute();
            (route as any).oauthTokenUtils = {
                verifyAccessToken: vi.fn(async () => ({ client_id: client.clientId, jti: "jti-1" })),
            };
            const denylist = { revoke: vi.fn(), isRevoked: vi.fn(async () => false) };
            (route as any).accessTokenDenylist = denylist;
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: "some-access-token" } }), res);

            expect(denylist.revoke).toHaveBeenCalledWith("jti-1", 0);
        });

        it("Tries the access-token path first when token_type_hint is access_token, falling back to refresh token.", async () => {
            const { route, refreshTokenRepo } = makeRoute();
            const raw = "raw-refresh-1";
            const stored = makeOAuthRefreshToken();
            refreshTokenRepo._store.set(hashOpaqueToken(raw), stored);
            const verifyAccessToken = vi.fn(async () => undefined);
            (route as any).oauthTokenUtils = { verifyAccessToken };
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: raw, token_type_hint: "access_token" } }), res);

            expect(verifyAccessToken).toHaveBeenCalledWith(raw);
            expect(refreshTokenRepo.update).toHaveBeenCalledWith(
                expect.objectContaining({ uid: stored.uid, revoked: true }),
                stored,
                { ignoreACL: true },
            );
        });

        it("Skips the access-token verification call once the hinted refresh-token lookup already found a match.", async () => {
            const { route, refreshTokenRepo } = makeRoute();
            const raw = "raw-refresh-1";
            const stored = makeOAuthRefreshToken();
            refreshTokenRepo._store.set(hashOpaqueToken(raw), stored);
            const verifyAccessToken = vi.fn(async () => undefined);
            (route as any).oauthTokenUtils = { verifyAccessToken };
            const res = makeResponse();

            await route.revoke(makeRequest({ body: { token: raw, token_type_hint: "refresh_token" } }), res);

            expect(verifyAccessToken).not.toHaveBeenCalled();
            expect(refreshTokenRepo.update).toHaveBeenCalled();
        });
    });
});

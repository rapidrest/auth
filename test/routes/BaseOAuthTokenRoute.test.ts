///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthTokenRoute — no HTTP server, no database.
import { ApiError } from "@rapidrest/core";
import { ApiErrors, RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthTokenRoute, OAuthError } from "../../src/routes/BaseOAuthTokenRoute.js";
import { ClientAuthUtils } from "../../src/auth/ClientAuthUtils.js";
import { OAuthTokenUtils } from "../../src/auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { AuthorizationCode, Client, ClientType, TokenEndpointAuthMethod } from "../../src/models/types.js";
import { hashOpaqueToken } from "../../src/auth/shared.js";

class FakeClientClass {
    static readonly name = "FakeClient";
}
class FakeAuthorizationCodeClass {
    static readonly name = "FakeAuthorizationCode";
}
class FakeSigningKeyClass {
    static readonly name = "FakeSigningKey";
}

class TestOAuthTokenRoute extends BaseOAuthTokenRoute<any, any> {
    protected authorizationCodeClass: any = FakeAuthorizationCodeClass;
    protected clientClass: any = FakeClientClass;
    protected signingKeyClass: any = FakeSigningKeyClass;
}

function makeMockRepo<T>(identifierKey: keyof T) {
    const store = new Map<string, T>();
    return {
        create: vi.fn(async (obj: Partial<T>) => obj),
        find: vi.fn(async () => []),
        findOne: vi.fn(async (id: string) => store.get(id)),
        update: vi.fn(async (obj: Partial<T>, existing: T) => {
            // Mirrors RepoUtils.update()'s real optimistic-locking contract: `obj` must carry the same
            // `uid`/`version` as `existing`, not just the fields being changed.
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
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    scope: "openid profile",
    tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    requirePkce: false,
    firstParty: false,
};

function makeAuthCode(overrides: Partial<AuthorizationCode> = {}): AuthorizationCode {
    return {
        uid: "code-record-1",
        dateCreated: new Date(),
        dateModified: new Date(),
        version: 0,
        codeHash: "",
        clientId: client.clientId,
        userUid: "user-1",
        redirectUri: "https://app.example.com/callback",
        scope: "profile",
        expiresAt: new Date(Date.now() + 60_000),
        used: false,
        ...overrides,
    };
}

function makeRoute() {
    const clientRepo = makeMockRepo<Client>("clientId");
    const authorizationCodeRepo = makeMockRepo<AuthorizationCode>("codeHash");

    const route = new TestOAuthTokenRoute();
    (route as any)._objectFactory = {
        newInstance: vi.fn(async (type: any, opts: any) => {
            if (type === RepoUtils) {
                if (opts.name === FakeClientClass.name) return clientRepo;
                if (opts.name === FakeAuthorizationCodeClass.name) return authorizationCodeRepo;
            }
            return undefined;
        }),
    };
    (route as any).clientRepo = clientRepo;
    (route as any).authorizationCodeRepo = authorizationCodeRepo;
    (route as any).clientAuthUtils = { authenticateClient: vi.fn(async () => client) };
    (route as any).oauthTokenUtils = {
        createAccessToken: vi.fn(async () => ({ token: "access-token-1", jti: "jti-1", expiresIn: 900 })),
        createIdToken: vi.fn(async () => "id-token-1"),
    };
    (route as any).rateLimiter = { checkAndIncrement: vi.fn() };

    return { route, clientRepo, authorizationCodeRepo };
}

function makeRequest(overrides: any = {}) {
    return {
        method: "POST",
        path: "/oauth/token",
        url: "/oauth/token",
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

describe("BaseOAuthTokenRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthTokenRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Builds clientRepo, authorizationCodeRepo, clientAuthUtils, and oauthTokenUtils via the object factory.", async () => {
            const clientRepo = makeMockRepo<Client>("clientId");
            const authorizationCodeRepo = makeMockRepo<AuthorizationCode>("codeHash");
            const signingKeyRepo = makeMockRepo<any>("kid");
            const clientAuthUtils = {};
            const signingKeyUtils = {};
            const oauthTokenUtils = {};

            const route = new TestOAuthTokenRoute();
            (route as any)._objectFactory = {
                newInstance: vi.fn(async (type: any, opts: any) => {
                    if (type === RepoUtils) {
                        if (opts.name === FakeClientClass.name) return clientRepo;
                        if (opts.name === FakeAuthorizationCodeClass.name) return authorizationCodeRepo;
                        if (opts.name === FakeSigningKeyClass.name) return signingKeyRepo;
                    }
                    if (type === ClientAuthUtils) return clientAuthUtils;
                    if (type === SigningKeyUtils) return signingKeyUtils;
                    if (type === OAuthTokenUtils) return oauthTokenUtils;
                    return undefined;
                }),
            };

            await (route as any).initialize();

            expect((route as any).clientRepo).toBe(clientRepo);
            expect((route as any).authorizationCodeRepo).toBe(authorizationCodeRepo);
            expect((route as any).clientAuthUtils).toBe(clientAuthUtils);
            expect((route as any).oauthTokenUtils).toBe(oauthTokenUtils);
        });

        it("Does not recreate any repo/utils if initialize() runs again.", async () => {
            const { route, clientRepo, authorizationCodeRepo } = makeRoute();
            const newInstance = (route as any)._objectFactory.newInstance;

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).clientRepo).toBe(clientRepo);
            expect((route as any).authorizationCodeRepo).toBe(authorizationCodeRepo);
        });
    });

    describe("token", () => {
        it("Always sets Cache-Control: no-store and Pragma: no-cache.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "unsupported" } }), res);
            expect(res.setHeader).toHaveBeenCalledWith("Cache-Control", "no-store");
            expect(res.setHeader).toHaveBeenCalledWith("Pragma", "no-cache");
        });

        it("Returns unsupported_grant_type for an unrecognized grant_type.", async () => {
            const { route } = makeRoute();
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "bogus" } }), res);
            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "unsupported_grant_type" }));
        });

        it("Maps a plain Error to a 500 server_error.", async () => {
            const { route } = makeRoute();
            (route as any).rateLimiter = {
                checkAndIncrement: vi.fn(async () => {
                    throw new Error("boom");
                }),
            };
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "authorization_code" } }), res);
            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ error: "server_error" });
        });

        it("Maps a 401 ApiError to invalid_client.", async () => {
            const { route } = makeRoute();
            (route as any).clientAuthUtils = {
                authenticateClient: vi.fn(async () => {
                    throw new ApiError(ApiErrors.AUTH_FAILED, 401, "Invalid client.");
                }),
            };
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "authorization_code" } }), res);
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: "invalid_client", error_description: "Invalid client." });
        });

        it("Maps a 429 ApiError (rate limited) to invalid_request at its own status.", async () => {
            const { route } = makeRoute();
            (route as any).rateLimiter = {
                checkAndIncrement: vi.fn(async () => {
                    throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 429, "Too many attempts.");
                }),
            };
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "authorization_code" } }), res);
            expect(res.status).toHaveBeenCalledWith(429);
            expect(res.json).toHaveBeenCalledWith({ error: "invalid_request", error_description: "Too many attempts." });
        });

        it("Maps a 500+ ApiError to server_error.", async () => {
            const { route } = makeRoute();
            (route as any).clientAuthUtils = {
                authenticateClient: vi.fn(async () => {
                    throw new ApiError(ApiErrors.INTERNAL_ERROR, 501, "Not yet supported.");
                }),
            };
            const res = makeResponse();
            await route.token(makeRequest({ body: { grant_type: "authorization_code" } }), res);
            expect(res.status).toHaveBeenCalledWith(501);
            expect(res.json).toHaveBeenCalledWith({ error: "server_error", error_description: "Not yet supported." });
        });

        describe("authorization_code grant", () => {
            it("Fails with invalid_request when code is missing.", async () => {
                const { route } = makeRoute();
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.status).toHaveBeenCalledWith(400);
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_request" }));
            });

            it("Fails with invalid_request when redirect_uri is missing.", async () => {
                const { route } = makeRoute();
                const res = makeResponse();
                await route.token(makeRequest({ body: { grant_type: "authorization_code", code: "raw-code" } }), res);
                expect(res.status).toHaveBeenCalledWith(400);
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_request" }));
            });

            it("Fails with invalid_grant when the code does not exist.", async () => {
                const { route } = makeRoute();
                const res = makeResponse();
                await route.token(
                    makeRequest({
                        body: { grant_type: "authorization_code", code: "does-not-exist", redirect_uri: "https://app.example.com/callback" },
                    }),
                    res,
                );
                expect(res.status).toHaveBeenCalledWith(400);
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when the code belongs to a different client.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ clientId: "someone-else" }));
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when the code has already been used.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ used: true }));
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when the code has expired.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ expiresAt: new Date(Date.now() - 1000) }));
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when redirect_uri does not match the code's stored value.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode());
                const res = makeResponse();
                await route.token(
                    makeRequest({
                        body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://different.example.com/callback" },
                    }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when code_verifier is missing for a PKCE-protected code.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(
                    hashOpaqueToken(raw),
                    makeAuthCode({ codeChallenge: "challenge-1", codeChallengeMethod: "plain" }),
                );
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Fails with invalid_grant when code_verifier does not match the code_challenge.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(
                    hashOpaqueToken(raw),
                    makeAuthCode({ codeChallenge: "challenge-1", codeChallengeMethod: "plain" }),
                );
                const res = makeResponse();
                await route.token(
                    makeRequest({
                        body: {
                            grant_type: "authorization_code",
                            code: raw,
                            redirect_uri: "https://app.example.com/callback",
                            code_verifier: "wrong-verifier-that-is-at-least-43-characters-long",
                        },
                    }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Succeeds with a matching plain code_verifier.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                const verifier = "a-valid-code-verifier-that-is-at-least-43-characters-long";
                authorizationCodeRepo._store.set(
                    hashOpaqueToken(raw),
                    makeAuthCode({ codeChallenge: verifier, codeChallengeMethod: "plain" }),
                );
                const res = makeResponse();
                await route.token(
                    makeRequest({
                        body: {
                            grant_type: "authorization_code",
                            code: raw,
                            redirect_uri: "https://app.example.com/callback",
                            code_verifier: verifier,
                        },
                    }),
                    res,
                );
                expect(res.status).toHaveBeenCalledWith(200);
            });

            it("Defaults to 'plain' PKCE verification when the code has no stored codeChallengeMethod.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                const verifier = "a-valid-code-verifier-that-is-at-least-43-characters-long";
                authorizationCodeRepo._store.set(
                    hashOpaqueToken(raw),
                    makeAuthCode({ codeChallenge: verifier, codeChallengeMethod: undefined }),
                );
                const res = makeResponse();
                await route.token(
                    makeRequest({
                        body: {
                            grant_type: "authorization_code",
                            code: raw,
                            redirect_uri: "https://app.example.com/callback",
                            code_verifier: verifier,
                        },
                    }),
                    res,
                );
                expect(res.status).toHaveBeenCalledWith(200);
            });

            it("Grants an empty scope and no id_token when the code carries no scope at all.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ scope: "" }));
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                const body = res.json.mock.calls[0][0];
                expect(body.scope).toBe("");
                expect(body.id_token).toBeUndefined();
            });

            it("Loses the optimistic-locking race and reports invalid_grant when update() throws.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode());
                authorizationCodeRepo.update.mockRejectedValueOnce(new Error("version conflict"));
                const res = makeResponse();
                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );
                expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: "invalid_grant" }));
            });

            it("Marks the code used and issues an access token without an id_token for a non-openid scope.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ codeHash: hashOpaqueToken(raw), scope: "profile" }));
                const res = makeResponse();

                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );

                expect(authorizationCodeRepo.update).toHaveBeenCalledWith(
                    expect.objectContaining({ used: true, uid: "code-record-1", version: 0 }),
                    expect.objectContaining({ codeHash: hashOpaqueToken(raw) }),
                    { ignoreACL: true },
                );
                expect(res.status).toHaveBeenCalledWith(200);
                const body = res.json.mock.calls[0][0];
                expect(body).toEqual({ access_token: "access-token-1", token_type: "Bearer", expires_in: 900, scope: "profile" });
                expect(body.id_token).toBeUndefined();
            });

            it("Includes an id_token when the granted scope includes openid.", async () => {
                const { route, authorizationCodeRepo } = makeRoute();
                const raw = "raw-code-1";
                authorizationCodeRepo._store.set(hashOpaqueToken(raw), makeAuthCode({ scope: "openid profile", nonce: "nonce-1" }));
                const res = makeResponse();

                await route.token(
                    makeRequest({ body: { grant_type: "authorization_code", code: raw, redirect_uri: "https://app.example.com/callback" } }),
                    res,
                );

                const body = res.json.mock.calls[0][0];
                expect(body.id_token).toBe("id-token-1");
                expect((route as any).oauthTokenUtils.createIdToken).toHaveBeenCalledWith(
                    client,
                    { uid: "user-1", roles: [], scopes: ["openid", "profile"] },
                    "nonce-1",
                );
            });
        });
    });

    describe("OAuthError", () => {
        it("Defaults status to 400 and uses `error` as the message when no description is given.", () => {
            const err = new OAuthError("invalid_request");
            expect(err.status).toBe(400);
            expect(err.message).toBe("invalid_request");
            expect(err.errorDescription).toBeUndefined();
        });
    });
});

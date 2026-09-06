///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthAuthorizeRoute — no HTTP server, no database.
import { JWTUtils } from "@rapidrest/core";
import { RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthAuthorizeRoute } from "../../src/routes/BaseOAuthAuthorizeRoute.js";
import { AuthorizationCode, Client, ClientType, ConsentGrant, TokenEndpointAuthMethod } from "../../src/models/types.js";

const JWT_SECRET = "consent-ticket-test-secret";

class FakeClientClass {
    static readonly name = "FakeClient";
}
class FakeAuthorizationCodeClass {
    static readonly name = "FakeAuthorizationCode";
}
class FakeConsentGrantClass {
    static readonly name = "FakeConsentGrant";
}

class TestOAuthAuthorizeRoute extends BaseOAuthAuthorizeRoute<any, any, any> {
    protected authorizationCodeClass: any = FakeAuthorizationCodeClass;
    protected clientClass: any = FakeClientClass;
    protected consentGrantClass: any = FakeConsentGrantClass;
    protected resourceOwnerStrategies: string[] = ["jwt"];
}

function makeMockRepo<T extends { uid: string }>(identifierKey: keyof T = "uid") {
    const store = new Map<string, T>();
    return {
        create: vi.fn(async (obj: Partial<T>) => {
            const record = { uid: (obj as any)[identifierKey] ?? `uid-${store.size}`, dateCreated: new Date(), dateModified: new Date(), version: 0, ...obj } as T;
            store.set(String((record as any)[identifierKey]), record);
            return record;
        }),
        find: vi.fn(async (query: any) => {
            const all = Array.from(store.values());
            if (!query || Object.keys(query).length === 0) {
                return all;
            }
            return all.filter((record) => Object.entries(query).every(([k, v]) => (record as any)[k] === v));
        }),
        findOne: vi.fn(async (id: string) => store.get(id)),
        update: vi.fn(async (obj: Partial<T>, existing: T) => {
            // Mirrors RepoUtils.update()'s real optimistic-locking contract: `obj` must carry the same
            // `uid`/`version` as `existing`, not just the fields being changed.
            if ((obj as any).uid !== (existing as any).uid || (obj as any).version !== (existing as any).version) {
                throw new Error("Invalid object version. Do you have the latest version?");
            }
            const updated = { ...existing, ...obj, version: (existing as any).version + 1 };
            store.set(String((existing as any)[identifierKey]), updated);
            return updated;
        }),
        _store: store,
    };
}

function makeMockObjectFactory(clientRepo: any, authorizationCodeRepo: any, consentGrantRepo: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeClientClass.name) return clientRepo;
            if (opts.name === FakeAuthorizationCodeClass.name) return authorizationCodeRepo;
            if (opts.name === FakeConsentGrantClass.name) return consentGrantRepo;
        }
        return undefined;
    });
    return { newInstance };
}

function makeClient(overrides: Partial<Client> = {}): Client {
    return {
        uid: "client-record-1",
        dateCreated: new Date(),
        dateModified: new Date(),
        version: 0,
        clientType: ClientType.CONFIDENTIAL,
        clientName: "Test App",
        redirectUris: ["https://app.example.com/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scope: "openid profile email",
        tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
        requirePkce: false,
        firstParty: false,
        ...overrides,
    };
}

function makeRoute(overrides: { client?: Client } = {}) {
    const clientRepo = makeMockRepo<Client>();
    const authorizationCodeRepo = makeMockRepo<AuthorizationCode>("codeHash");
    const consentGrantRepo = makeMockRepo<ConsentGrant>();

    const client = overrides.client ?? makeClient();
    clientRepo._store.set(client.uid, client);

    const route = new TestOAuthAuthorizeRoute();
    (route as any)._objectFactory = makeMockObjectFactory(clientRepo, authorizationCodeRepo, consentGrantRepo);
    (route as any).clientRepo = clientRepo;
    (route as any).authorizationCodeRepo = authorizationCodeRepo;
    (route as any).consentGrantRepo = consentGrantRepo;
    (route as any).jwtConfig = { secret: JWT_SECRET };

    return { route, clientRepo, authorizationCodeRepo, consentGrantRepo, client };
}

function makeRequest(overrides: any = {}) {
    return {
        method: "GET",
        path: "/oauth/authorize",
        url: "/oauth/authorize",
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

const res = { setHeader: vi.fn(), status: vi.fn(), json: vi.fn() } as any;

describe("BaseOAuthAuthorizeRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestOAuthAuthorizeRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates clientRepo, authorizationCodeRepo, and consentGrantRepo using the object factory.", async () => {
            const clientRepo = makeMockRepo();
            const authorizationCodeRepo = makeMockRepo();
            const consentGrantRepo = makeMockRepo();
            const route = new TestOAuthAuthorizeRoute();
            (route as any)._objectFactory = makeMockObjectFactory(clientRepo, authorizationCodeRepo, consentGrantRepo);

            await (route as any).initialize();

            expect((route as any).clientRepo).toBe(clientRepo);
            expect((route as any).authorizationCodeRepo).toBe(authorizationCodeRepo);
            expect((route as any).consentGrantRepo).toBe(consentGrantRepo);
        });
    });

    describe("authorize", () => {
        it("Throws when client_id is missing.", async () => {
            const { route } = makeRoute();
            await expect(route.authorize(makeRequest(), res)).rejects.toThrow(/client_id/);
        });

        it("Throws when the client is unknown.", async () => {
            const { route } = makeRoute();
            await expect(
                route.authorize(makeRequest({ query: { client_id: "does-not-exist" } }), res),
            ).rejects.toThrow(/Unknown or disabled/);
        });

        it("Throws when the client is disabled.", async () => {
            const { route } = makeRoute({ client: makeClient({ disabled: true }) });
            await expect(
                route.authorize(makeRequest({ query: { client_id: "client-record-1" } }), res),
            ).rejects.toThrow(/Unknown or disabled/);
        });

        it("Throws when redirect_uri is missing.", async () => {
            const { route } = makeRoute();
            await expect(
                route.authorize(makeRequest({ query: { client_id: "client-record-1" } }), res),
            ).rejects.toThrow(/redirect_uri/);
        });

        it("Throws when redirect_uri is not in the client's allow-list.", async () => {
            const { route } = makeRoute();
            await expect(
                route.authorize(
                    makeRequest({ query: { client_id: "client-record-1", redirect_uri: "https://evil.example.com" } }),
                    res,
                ),
            ).rejects.toThrow(/redirect_uri/);
        });

        it("Returns an error redirect for an unsupported response_type.", async () => {
            const { route } = makeRoute();
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: "client-record-1", redirect_uri: "https://app.example.com/callback", response_type: "token" },
                }),
                res,
            );
            const url = new URL(result.redirectTo);
            expect(url.searchParams.get("error")).toBe("unsupported_response_type");
        });

        it("Treats a request with no query object at all the same as an empty one.", async () => {
            const { route } = makeRoute();
            await expect(route.authorize(makeRequest({ query: undefined }), res)).rejects.toThrow(/client_id/);
        });

        it("Grants no scope for a client with no registered scope at all.", async () => {
            const { route, authorizationCodeRepo } = makeRoute({ client: makeClient({ firstParty: true, scope: "" }) });
            await route.authorize(
                makeRequest({
                    query: {
                        client_id: "client-record-1",
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            const stored = Array.from(authorizationCodeRepo._store.values())[0];
            expect(stored.scope).toBe("");
        });

        it("Returns an error redirect when PKCE is required but code_challenge is missing.", async () => {
            const { route } = makeRoute({ client: makeClient({ requirePkce: true }) });
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: "client-record-1", redirect_uri: "https://app.example.com/callback", response_type: "code" },
                }),
                res,
            );
            const url = new URL(result.redirectTo);
            expect(url.searchParams.get("error")).toBe("invalid_request");
        });

        it("Returns an error redirect for an invalid code_challenge_method.", async () => {
            const { route } = makeRoute();
            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: "client-record-1",
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        code_challenge: "challenge-value",
                        code_challenge_method: "bogus",
                    },
                }),
                res,
            );
            const url = new URL(result.redirectTo);
            expect(url.searchParams.get("error")).toBe("invalid_request");
        });

        it("Accepts an explicit S256 code_challenge_method and succeeds when PKCE is required.", async () => {
            const { route, authorizationCodeRepo } = makeRoute({ client: makeClient({ firstParty: true, requirePkce: true }) });
            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: "client-record-1",
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        code_challenge: "challenge-value",
                        code_challenge_method: "S256",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            expect(result.redirectTo).toContain("code=");
            const stored = Array.from(authorizationCodeRepo._store.values())[0];
            expect(stored.codeChallengeMethod).toBe("S256");
        });

        it("Omits the state parameter from the redirect when none was provided.", async () => {
            const { route } = makeRoute({ client: makeClient({ firstParty: true }) });
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: "client-record-1", redirect_uri: "https://app.example.com/callback", response_type: "code" },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            const url = new URL(result.redirectTo);
            expect(url.searchParams.has("state")).toBe(false);
        });

        it("Omits the state parameter from an error redirect when none was provided.", async () => {
            const { route } = makeRoute();
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: "client-record-1", redirect_uri: "https://app.example.com/callback", response_type: "token" },
                }),
                res,
            );
            const url = new URL(result.redirectTo);
            expect(url.searchParams.has("state")).toBe(false);
        });

        it("Defaults code_challenge_method to 'plain' when omitted.", async () => {
            const { route, authorizationCodeRepo } = makeRoute({ client: makeClient({ firstParty: true }) });
            await route.authorize(
                makeRequest({
                    query: {
                        client_id: "client-record-1",
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        code_challenge: "challenge-value",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            const stored = Array.from(authorizationCodeRepo._store.values())[0];
            expect(stored.codeChallengeMethod).toBe("plain");
        });

        it("Returns {loginRequired:true} when there is no authenticated user.", async () => {
            const { route } = makeRoute();
            (route as any).authMiddleware = { authenticate: vi.fn(async () => undefined) };
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: "client-record-1", redirect_uri: "https://app.example.com/callback", response_type: "code" },
                }),
                res,
            );
            expect(result).toEqual({ loginRequired: true });
        });

        it("Resolves the user via req.session.userUid (fast path) without calling authMiddleware.", async () => {
            const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
            const authenticate = vi.fn();
            (route as any).authMiddleware = { authenticate };
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: client.uid, redirect_uri: "https://app.example.com/callback", response_type: "code" },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            expect(authenticate).not.toHaveBeenCalled();
            expect(result.redirectTo).toContain("code=");
        });

        it("Falls back to authMiddleware.authenticate() when no session is present.", async () => {
            const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
            const authenticate = vi.fn(async () => ({ method: "jwt", user: { uid: "user-1", roles: [], scopes: [] } }));
            (route as any).authMiddleware = { authenticate };
            const result = await route.authorize(
                makeRequest({
                    query: { client_id: client.uid, redirect_uri: "https://app.example.com/callback", response_type: "code" },
                }),
                res,
            );
            expect(authenticate).toHaveBeenCalledWith(["jwt"], expect.anything(), res, false);
            expect(result.redirectTo).toContain("code=");
        });

        it("Falls back to a 60 second code expiry when codeTTL is not a valid duration.", async () => {
            const { route, client, authorizationCodeRepo } = makeRoute({ client: makeClient({ firstParty: true }) });
            (route as any).codeTTL = "not-a-duration";
            const before = Date.now();

            await route.authorize(
                makeRequest({
                    query: { client_id: client.uid, redirect_uri: "https://app.example.com/callback", response_type: "code" },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            const stored = Array.from(authorizationCodeRepo._store.values())[0];
            expect(stored.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 59_000);
            expect(stored.expiresAt.getTime()).toBeLessThanOrEqual(before + 61_000);
        });

        it("Falls back to a 10 minute consent ticket expiry when consentTicketTTL is not a valid duration.", async () => {
            const { route, client } = makeRoute();
            (route as any).consentTicketTTL = "not-a-duration";

            const result = await route.authorize(
                makeRequest({
                    query: { client_id: client.uid, redirect_uri: "https://app.example.com/callback", response_type: "code" },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            expect(result.consentRequired).toBe(true);
            const decoded: any = await JWTUtils.decodeToken({ secret: JWT_SECRET, options: {} }, result.requestId);
            expect(decoded.exp - decoded.iat).toBe(600);
        });

        it("Skips consent and issues a code directly for a first-party client.", async () => {
            const { route, client, authorizationCodeRepo } = makeRoute({ client: makeClient({ firstParty: true }) });
            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: client.uid,
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid profile",
                        state: "xyz",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            const url = new URL(result.redirectTo);
            expect(url.searchParams.get("code")).toBeTruthy();
            expect(url.searchParams.get("state")).toBe("xyz");
            expect(authorizationCodeRepo.create).toHaveBeenCalledTimes(1);
            const stored = Array.from(authorizationCodeRepo._store.values())[0];
            expect(stored.scope).toBe("openid profile");
            expect(stored.userUid).toBe("user-1");
            expect(stored.used).toBe(false);
        });

        it("Down-selects requested scope to the intersection with the client's registered scope.", async () => {
            const { route, client } = makeRoute({ client: makeClient({ firstParty: true, scope: "openid profile" }) });
            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: client.uid,
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid profile admin",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            expect(result.redirectTo).toBeDefined();
        });

        it("Requires consent for a non-first-party client with no existing grant.", async () => {
            const { route, client } = makeRoute();
            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: client.uid,
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid profile",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );
            expect(result.consentRequired).toBe(true);
            expect(result.requestId).toBeTruthy();
            expect(result.client).toEqual({ clientName: "Test App", logoUri: undefined, scope: "openid profile" });
        });

        it("Skips consent and issues a code when an existing grant already covers the requested scope.", async () => {
            const { route, client, consentGrantRepo, authorizationCodeRepo } = makeRoute();
            consentGrantRepo._store.set("grant-1", {
                uid: "grant-1",
                dateCreated: new Date(),
                dateModified: new Date(),
                version: 0,
                userUid: "user-1",
                clientId: client.uid,
                scope: "openid profile email",
                grantedAt: new Date(),
            });

            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: client.uid,
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid profile",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            expect(result.redirectTo).toContain("code=");
            expect(authorizationCodeRepo.create).toHaveBeenCalledTimes(1);
            const grant = consentGrantRepo._store.get("grant-1") as any;
            expect(grant.lastUsedAt).toBeInstanceOf(Date);
        });

        it("Still requires consent when the existing grant does not cover every requested scope.", async () => {
            const { route, client, consentGrantRepo } = makeRoute();
            consentGrantRepo._store.set("grant-1", {
                uid: "grant-1",
                dateCreated: new Date(),
                dateModified: new Date(),
                version: 0,
                userUid: "user-1",
                clientId: client.uid,
                scope: "openid",
                grantedAt: new Date(),
            });

            const result = await route.authorize(
                makeRequest({
                    query: {
                        client_id: client.uid,
                        redirect_uri: "https://app.example.com/callback",
                        response_type: "code",
                        scope: "openid profile",
                    },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            expect(result.consentRequired).toBe(true);
        });

        describe("prompt handling (OIDC Core §3.1.2.1)", () => {
            it("Rejects prompt=none combined with another value with invalid_request.", async () => {
                const { route, client } = makeRoute();
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "none login",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                const url = new URL(result.redirectTo);
                expect(url.searchParams.get("error")).toBe("invalid_request");
            });

            it("Returns a login_required error redirect for prompt=none when there is no authenticated user.", async () => {
                const { route, client } = makeRoute();
                (route as any).authMiddleware = { authenticate: vi.fn(async () => undefined) };
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "none",
                            state: "xyz",
                        },
                    }),
                    res,
                );
                const url = new URL(result.redirectTo);
                expect(url.searchParams.get("error")).toBe("login_required");
                expect(url.searchParams.get("state")).toBe("xyz");
            });

            it("Returns a consent_required error redirect for prompt=none when consent would otherwise be required.", async () => {
                const { route, client } = makeRoute();
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            scope: "openid profile",
                            prompt: "none",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                const url = new URL(result.redirectTo);
                expect(url.searchParams.get("error")).toBe("consent_required");
            });

            it("Succeeds normally under prompt=none when already authenticated and no consent is needed.", async () => {
                const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "none",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                expect(result.redirectTo).toContain("code=");
            });

            it("Forces {loginRequired:true} for prompt=login even when a session already resolves a user.", async () => {
                const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
                const authenticate = vi.fn();
                (route as any).authMiddleware = { authenticate };
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "login",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                expect(result).toEqual({ loginRequired: true });
                expect(authenticate).not.toHaveBeenCalled();
            });

            it("Forces {loginRequired:true} for prompt=select_account even when a session already resolves a user.", async () => {
                const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "select_account",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                expect(result).toEqual({ loginRequired: true });
            });

            it("Forces consent even when a sufficient ConsentGrant already exists, for prompt=consent.", async () => {
                const { route, client, consentGrantRepo } = makeRoute();
                consentGrantRepo._store.set("grant-1", {
                    uid: "grant-1",
                    dateCreated: new Date(),
                    dateModified: new Date(),
                    version: 0,
                    userUid: "user-1",
                    clientId: client.uid,
                    scope: "openid profile email",
                    grantedAt: new Date(),
                });

                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            scope: "openid profile",
                            prompt: "consent",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );

                expect(result.consentRequired).toBe(true);
            });

            it("A first-party client still skips consent even when prompt=consent is requested.", async () => {
                const { route, client } = makeRoute({ client: makeClient({ firstParty: true }) });
                const result = await route.authorize(
                    makeRequest({
                        query: {
                            client_id: client.uid,
                            redirect_uri: "https://app.example.com/callback",
                            response_type: "code",
                            prompt: "consent",
                        },
                        session: { userUid: "user-1" },
                    }),
                    res,
                );
                expect(result.redirectTo).toContain("code=");
            });
        });
    });

    describe("decideConsent", () => {
        async function makeTicket(route: any, overrides: Record<string, any> = {}): Promise<string> {
            return (route).createConsentTicket({
                clientId: "client-record-1",
                userUid: "user-1",
                redirectUri: "https://app.example.com/callback",
                scope: "openid profile",
                state: "xyz",
                ...overrides,
            });
        }

        it("Throws when requestId is missing.", async () => {
            const { route } = makeRoute();
            await expect(
                route.decideConsent(makeRequest({ body: {} }), res),
            ).rejects.toThrow(/requestId/);
        });

        it("Throws when the request body is not a parseable object.", async () => {
            const { route } = makeRoute();
            await expect(
                route.decideConsent(makeRequest({ body: undefined }), res),
            ).rejects.toThrow(/requestId/);
        });

        it("Throws when a validly-signed token is presented that isn't actually a consent ticket.", async () => {
            const { route } = makeRoute();
            const notATicket = await JWTUtils.createToken(
                { secret: JWT_SECRET, options: {} },
                { uid: "user-1", roles: [], scopes: [] },
                { typ: "something_else" },
            );
            await expect(
                route.decideConsent(
                    makeRequest({ body: { requestId: notATicket }, session: { userUid: "user-1" } }),
                    res,
                ),
            ).rejects.toThrow(/invalid or has expired/);
        });

        it("Throws when there is no authenticated user.", async () => {
            const { route } = makeRoute();
            (route as any).authMiddleware = { authenticate: vi.fn(async () => undefined) };
            await expect(
                route.decideConsent(makeRequest({ body: { requestId: "whatever" } }), res),
            ).rejects.toThrow(/Authentication is required/);
        });

        it("Throws when the ticket is invalid or expired.", async () => {
            const { route } = makeRoute();
            await expect(
                route.decideConsent(
                    makeRequest({ body: { requestId: "not-a-real-ticket" }, session: { userUid: "user-1" } }),
                    res,
                ),
            ).rejects.toThrow(/invalid or has expired/);
        });

        it("Throws when the ticket does not belong to the current user.", async () => {
            const { route } = makeRoute();
            const ticket = await makeTicket(route);
            await expect(
                route.decideConsent(
                    makeRequest({ body: { requestId: ticket }, session: { userUid: "someone-else" } }),
                    res,
                ),
            ).rejects.toThrow(/does not belong to the current user/);
        });

        it("Throws when the ticket's client no longer exists.", async () => {
            const { route } = makeRoute();
            const ticket = await makeTicket(route, { clientId: "no-longer-exists" });
            await expect(
                route.decideConsent(
                    makeRequest({ body: { requestId: ticket }, session: { userUid: "user-1" } }),
                    res,
                ),
            ).rejects.toThrow(/Unknown or disabled/);
        });

        it("Returns an access_denied error redirect on denial, without creating a ConsentGrant.", async () => {
            const { route, consentGrantRepo } = makeRoute();
            const ticket = await makeTicket(route);

            const result = await route.decideConsent(
                makeRequest({ body: { requestId: ticket, approved: false }, session: { userUid: "user-1" } }),
                res,
            );

            const url = new URL(result.redirectTo);
            expect(url.searchParams.get("error")).toBe("access_denied");
            expect(url.searchParams.get("state")).toBe("xyz");
            expect(consentGrantRepo.create).not.toHaveBeenCalled();
        });

        it("Records a new ConsentGrant and issues a code on approval.", async () => {
            const { route, consentGrantRepo, authorizationCodeRepo } = makeRoute();
            const ticket = await makeTicket(route);

            const result = await route.decideConsent(
                makeRequest({ body: { requestId: ticket, approved: true }, session: { userUid: "user-1" } }),
                res,
            );

            expect(result.redirectTo).toContain("code=");
            expect(consentGrantRepo.create).toHaveBeenCalledTimes(1);
            expect(authorizationCodeRepo.create).toHaveBeenCalledTimes(1);
            const grant = Array.from(consentGrantRepo._store.values())[0];
            expect(grant.scope).toBe("openid profile");
        });

        it("Merges scope into an existing ConsentGrant rather than overwriting it.", async () => {
            const { route, consentGrantRepo } = makeRoute();
            consentGrantRepo._store.set("grant-1", {
                uid: "grant-1",
                dateCreated: new Date(),
                dateModified: new Date(),
                version: 0,
                userUid: "user-1",
                clientId: "client-record-1",
                scope: "email",
                grantedAt: new Date(),
            });
            const ticket = await makeTicket(route, { scope: "openid profile" });

            await route.decideConsent(
                makeRequest({ body: { requestId: ticket, approved: true }, session: { userUid: "user-1" } }),
                res,
            );

            expect(consentGrantRepo.create).not.toHaveBeenCalled();
            const grant = consentGrantRepo._store.get("grant-1") as ConsentGrant;
            const scopes = new Set(grant.scope.split(" "));
            expect(scopes).toEqual(new Set(["email", "openid", "profile"]));
        });

        it("Never grants more scope than the ticket originally offered, even if scope override asks for more.", async () => {
            const { route, consentGrantRepo } = makeRoute();
            const ticket = await makeTicket(route, { scope: "openid" });

            await route.decideConsent(
                makeRequest({
                    body: { requestId: ticket, approved: true, scope: ["openid", "admin"] },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            const grant = Array.from(consentGrantRepo._store.values())[0];
            expect(grant.scope).toBe("openid");
        });

        it("Down-selects scope when a narrower override is provided.", async () => {
            const { route, consentGrantRepo } = makeRoute();
            const ticket = await makeTicket(route, { scope: "openid profile email" });

            await route.decideConsent(
                makeRequest({
                    body: { requestId: ticket, approved: true, scope: ["openid"] },
                    session: { userUid: "user-1" },
                }),
                res,
            );

            const grant = Array.from(consentGrantRepo._store.values())[0];
            expect(grant.scope).toBe("openid");
        });

        it("Treats a ticket with no scope at all as granting nothing.", async () => {
            const { route, consentGrantRepo } = makeRoute();
            const ticket = await makeTicket(route, { scope: "" });

            await route.decideConsent(
                makeRequest({ body: { requestId: ticket, approved: true }, session: { userUid: "user-1" } }),
                res,
            );

            const grant = Array.from(consentGrantRepo._store.values())[0];
            expect(grant.scope).toBe("");
        });
    });
});

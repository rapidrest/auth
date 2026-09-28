///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthSessionTokenRoute — no HTTP server, no database. The full HTTP-level
// exchange (a real OAuth access token minted via /oauth/authorize + /oauth/token, then traded in here) is
// exercised by test/routes/mongo/OAuthUserInfoAndDiscoveryRoute.test.ts's sibling for this route — see
// test/routes/mongo/OAuthSessionTokenRoute.test.ts.
import { JWTUtils, JWTUser } from "@rapidrest/core";
import { RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthSessionTokenRoute } from "../../src/routes/BaseOAuthSessionTokenRoute.js";
import { AccessTokenDenylist } from "../../src/auth/AccessTokenDenylist.js";
import { OAuthBearerStrategy } from "../../src/auth/OAuthBearerStrategy.js";
import { OAuthTokenUtils } from "../../src/auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";
import { User } from "../../src/models/types.js";

class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeSigningKeyClass {
    static readonly name = "FakeSigningKey";
}

class TestOAuthSessionTokenRoute extends BaseOAuthSessionTokenRoute<any> {
    protected userClass: any = FakeUserClass;
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

function makeUser(overrides: Partial<User> = {}): User {
    return {
        uid: "user-1",
        dateCreated: new Date(),
        dateModified: new Date(),
        version: 0,
        roles: ["admin"],
        scopes: [],
        ...overrides,
    };
}

const authConfig = { secret: "test-secret" };

function makeOAuthUser(overrides: Partial<JWTUser> = {}): JWTUser {
    // Mirrors exactly what OAuthBearerStrategy.authenticate() actually mints: roles is always `[]` — an
    // OAuth access token carries no roles claim at all — which is precisely the gap this route exists to
    // close by looking up the real User record instead of trusting this.
    return { uid: "user-1", roles: [], scopes: ["openid"], ...overrides };
}

function makeRoute() {
    const userRepo = makeMockRepo<User>();
    const authMiddleware = { register: vi.fn() };
    const tokenUtils = new TokenUtils();
    (tokenUtils as any).jwtConfig = authConfig;
    (tokenUtils as any).cookieConfig = { enabled: false, access: { name: "jwt" }, refresh: { name: "refresh" } };

    const route = new TestOAuthSessionTokenRoute();
    (route as any)._objectFactory = {
        newInstance: vi.fn(async (type: any, opts: any) => {
            if (type === RepoUtils) {
                if (opts.name === FakeUserClass.name) return userRepo;
                if (opts.name === FakeSigningKeyClass.name) return makeMockRepo<any>();
            }
            if (type === SigningKeyUtils) return {};
            if (type === OAuthTokenUtils) return {};
            if (type === AccessTokenDenylist) return {};
            if (type === OAuthBearerStrategy) return { name: opts.name };
            return undefined;
        }),
    };
    (route as any).authMiddleware = authMiddleware;
    (route as any).userRepo = userRepo;
    (route as any).tokenUtils = tokenUtils;

    return { route, userRepo, authMiddleware, tokenUtils };
}

describe("BaseOAuthSessionTokenRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if authMiddleware was not injected.", async () => {
            const route = new TestOAuthSessionTokenRoute();
            (route as any)._objectFactory = { newInstance: vi.fn() };
            await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
        });

        it("Throws if objectFactory was not set.", async () => {
            const route = new TestOAuthSessionTokenRoute();
            (route as any).authMiddleware = { register: vi.fn() };
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Builds userRepo/oauthTokenUtils and registers the oauth_bearer strategy via the object factory.", async () => {
            const userRepo = makeMockRepo<User>();
            const signingKeyRepo = makeMockRepo<any>();
            const signingKeyUtils = {};
            const oauthTokenUtils = {};
            const accessTokenDenylist = {};
            const authMiddleware = { register: vi.fn() };

            const route = new TestOAuthSessionTokenRoute();
            (route as any).authMiddleware = authMiddleware;
            (route as any)._objectFactory = {
                newInstance: vi.fn(async (type: any, opts: any) => {
                    if (type === RepoUtils) {
                        if (opts.name === FakeUserClass.name) return userRepo;
                        if (opts.name === FakeSigningKeyClass.name) return signingKeyRepo;
                    }
                    if (type === SigningKeyUtils) return signingKeyUtils;
                    if (type === OAuthTokenUtils) return oauthTokenUtils;
                    if (type === AccessTokenDenylist) return accessTokenDenylist;
                    if (type === OAuthBearerStrategy) return { name: opts.name };
                    return undefined;
                }),
            };

            await (route as any).initialize();

            expect((route as any).userRepo).toBe(userRepo);
            expect((route as any).oauthTokenUtils).toBe(oauthTokenUtils);
            expect(authMiddleware.register).toHaveBeenCalledWith("oauth_bearer", { name: "oauth_bearer" });
        });

        it("Does not recreate userRepo/oauthTokenUtils if initialize() runs again.", async () => {
            const { route, userRepo } = makeRoute();
            (route as any).oauthTokenUtils = {};

            await (route as any).initialize();

            expect((route as any).userRepo).toBe(userRepo);
        });
    });

    describe("sessionToken", () => {
        it("Throws 401 when the access token's sub does not resolve to a real user account.", async () => {
            const { route } = makeRoute();
            const req: any = {};

            await expect(route.sessionToken(makeOAuthUser({ uid: "deleted-user" }), req)).rejects.toThrow(
                /invalid or missing authentication/i,
            );
        });

        it("Looks up the user with ignoreACL, since the OAuth-token identity isn't an ACL-scoped app user.", async () => {
            const { route, userRepo } = makeRoute();
            userRepo._store.set("user-1", makeUser());
            const req: any = {};

            await route.sessionToken(makeOAuthUser(), req);

            expect(userRepo.findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
        });

        it("Returns only `token` — never `refresh` — for a valid access token.", async () => {
            const { route, userRepo } = makeRoute();
            userRepo._store.set("user-1", makeUser());
            const req: any = {};

            const result = await route.sessionToken(makeOAuthUser(), req);

            expect(Object.keys(result)).toEqual(["token"]);
            expect(typeof result.token).toBe("string");
            expect((result as any).refresh).toBeUndefined();
        });

        // The entire point of this route: the OAuth access token itself carries `roles: []`
        // (OAuthBearerStrategy never populates it), so the minted session JWT must reflect the *real*
        // account's roles — not the empty roles on the token — or every role-gated /api/... route would
        // silently see a roleless caller.
        it("Mints a session JWT carrying the real account's roles, not the OAuth token's empty roles.", async () => {
            const { route, userRepo } = makeRoute();
            // Deliberately not "admin" - createAuthResult()'s non-elevated path strips every configured
            // `trusted_roles` entry (default `["admin"]`; see TokenUtils.resolveTokenUser()) regardless of
            // caller, exactly like every other plain (non-elevated) sign-in route. Using an untrusted role
            // here isolates the behavior this route actually adds - carrying over the real account's roles
            // instead of the OAuth token's always-empty ones - from that unrelated, pre-existing stripping.
            userRepo._store.set("user-1", makeUser({ roles: ["editor"] }));
            const req: any = {};

            const result = await route.sessionToken(makeOAuthUser({ roles: [] }), req);

            const payload = await JWTUtils.decodeToken(authConfig, result.token);
            const profile = payload.profile as JWTUser;
            expect(profile.uid).toBe("user-1");
            expect(profile.roles).toEqual(["editor"]);
        });

        it("Produces a real, independently-verifiable session JWT signed with the configured secret.", async () => {
            const { route, userRepo } = makeRoute();
            userRepo._store.set("user-1", makeUser());
            const req: any = {};

            const result = await route.sessionToken(makeOAuthUser(), req);

            await expect(JWTUtils.decodeToken(authConfig, result.token)).resolves.toBeDefined();
            await expect(JWTUtils.decodeToken({ secret: "wrong-secret" }, result.token)).rejects.toThrow();
        });

        it("Grants the configured auth:default_scopes on the minted session JWT, not the OAuth token's own scope.", async () => {
            const { route, userRepo } = makeRoute();
            (route as any).defaultScopes = ["api:default"];
            userRepo._store.set("user-1", makeUser());
            const req: any = {};

            const result = await route.sessionToken(makeOAuthUser({ scopes: ["openid", "profile"] }), req);

            const payload = await JWTUtils.decodeToken(authConfig, result.token);
            const profile = payload.profile as JWTUser;
            expect(profile.scopes).toEqual(["api:default"]);
        });

        // This route must never write a `Set-Cookie` header — the caller is a native app with no relevant
        // cookie jar for this purpose, and the response body's `token` is the only thing that matters. Since
        // TokenUtils.createAuthResult() only ever appends Set-Cookie when it's given a `res`, the structural
        // guarantee here is that this route's implementation never passes one through at all.
        it("Calls createAuthResult() without a `res`, so no cookie is ever written even when cookies are enabled server-wide.", async () => {
            const { route, userRepo, tokenUtils } = makeRoute();
            (tokenUtils as any).cookieConfig = { enabled: true, access: { name: "jwt" }, refresh: { name: "refresh" } };
            userRepo._store.set("user-1", makeUser());
            const createAuthResult = vi.spyOn(tokenUtils, "createAuthResult");
            const req: any = {};

            await route.sessionToken(makeOAuthUser(), req);

            expect(createAuthResult).toHaveBeenCalledTimes(1);
            // (user, scopes, req) — no 4th (`res`) argument at all.
            expect(createAuthResult.mock.calls[0]).toHaveLength(3);
            expect(createAuthResult.mock.calls[0][3]).toBeUndefined();
        });

        // This exchange verifies no new credential of its own — the real credential check already happened
        // when the access token's underlying authorization was granted through the interactive
        // /oauth/authorize flow — so, exactly like BaseAuthRefreshRoute's routine refresh, it must never
        // fire a SIGNED_IN audit entry (TokenUtils.createAuthResult() only fires one when given an
        // `authMethod`).
        it("Calls createAuthResult() without an authMethod, so this exchange never fires a SIGNED_IN audit entry.", async () => {
            const { route, userRepo, tokenUtils } = makeRoute();
            userRepo._store.set("user-1", makeUser());
            const auditLogUtils = { record: vi.fn() };
            (tokenUtils as any).auditLogUtils = auditLogUtils;
            const req: any = {};

            await route.sessionToken(makeOAuthUser(), req);

            expect(auditLogUtils.record).not.toHaveBeenCalled();
        });
    });
});

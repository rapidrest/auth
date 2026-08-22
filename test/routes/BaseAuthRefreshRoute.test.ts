///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthRefreshRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseAuthRefreshRoute } from "../../src/routes/BaseAuthRefreshRoute.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

class FakeUserClass {
    static readonly name = "FakeUser";
}

class TestAuthRefreshRoute extends BaseAuthRefreshRoute<any> {
    protected userClass: any = FakeUserClass;
}

const authConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };

function makeReq(overrides: any = {}): any {
    return {
        body: undefined,
        cookies: {},
        signedCookies: {},
        session: {},
        ...overrides,
    };
}

function makeRes(): any {
    return { setHeader: vi.fn(), appendHeader: vi.fn() };
}

async function setupRoute() {
    const route = new TestAuthRefreshRoute();
    (route as any).authConfig = authConfig;
    (route as any).cookieConfig = { name: "refresh" };
    const userRepo = { findOne: vi.fn() };
    (route as any).userRepo = userRepo;
    const tokenUtils = new TokenUtils();
    (tokenUtils as any).jwtConfig = authConfig;
    (route as any).tokenUtils = tokenUtils;
    return { route, userRepo, tokenUtils };
}

describe("BaseAuthRefreshRoute Tests", () => {
    describe("initialize", () => {
        it("Creates userRepo via objectFactory when userClass is set.", async () => {
            const route = new TestAuthRefreshRoute();
            const userRepoInstance = { findOne: vi.fn() };
            const newInstance = vi.fn().mockResolvedValue(userRepoInstance);
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).toHaveBeenCalledWith(RepoUtils, {
                name: FakeUserClass.name,
                args: [FakeUserClass],
            });
            expect((route as any).userRepo).toBe(userRepoInstance);
        });

        it("Does not recreate userRepo if it's already set.", async () => {
            const route = new TestAuthRefreshRoute();
            const existing = { findOne: vi.fn() };
            (route as any).userRepo = existing;
            const newInstance = vi.fn();
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).userRepo).toBe(existing);
        });
    });

    describe("getToken", () => {
        it("Reads the token directly when the body is a plain string.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: "raw-token-value" });

            expect((route as any).getToken(req)).toBe("raw-token-value");
        });

        it("Reads the token from a `token` property when the body is an object.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: { token: "body-token-value" } });

            expect((route as any).getToken(req)).toBe("body-token-value");
        });

        // Regression: `typeof null === "object"` in JS, so a `null` body (a common shape for a bodyless
        // GET/refresh-cookie-only request) used to crash on `req.body.token` instead of falling through to
        // the cookie checks below.
        it("Does not throw when the body is null, falling through to check cookies instead.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: null, cookies: { refresh: "cookie-token-value" } });

            expect(() => (route as any).getToken(req)).not.toThrow();
            expect((route as any).getToken(req)).toBe("cookie-token-value");
        });

        it("Falls back to the named cookie when the body has no usable token.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: {}, cookies: { refresh: "cookie-token-value" } });

            expect((route as any).getToken(req)).toBe("cookie-token-value");
        });

        // Regression: this used to be gated behind `cookieConfig.secure` (the unrelated HTTPS-only cookie
        // attribute), so a deployment with `secure: true` - the norm for production - would never actually
        // find a token in `req.signedCookies`, since nothing here ever populates it as a signed cookie.
        it("Checks signedCookies regardless of cookieConfig.secure.", async () => {
            const { route } = await setupRoute();
            (route as any).cookieConfig = { name: "refresh", secure: true };
            const req = makeReq({ body: {}, signedCookies: { refresh: "signed-cookie-token" }, cookies: {} });

            expect((route as any).getToken(req)).toBe("signed-cookie-token");
        });

        it("Returns undefined when no token is found anywhere.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: {} });

            expect((route as any).getToken(req)).toBeUndefined();
        });

        it("Skips both cookie checks entirely when neither cookies nor signedCookies is present on the request.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: {}, cookies: undefined, signedCookies: undefined });

            expect((route as any).getToken(req)).toBeUndefined();
        });
    });

    describe("authenticate", () => {
        it("Throws 401 when no refresh token is present anywhere in the request.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: {} });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        it("Throws 401 when the token is malformed or has an invalid signature.", async () => {
            const { route } = await setupRoute();
            const req = makeReq({ body: { token: "not-a-real-jwt" } });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        // Regression: `payload = JWTUtils.decodeToken(...)` was missing its `await`, so `payload` was a
        // pending Promise, not the resolved claims. `payload.userUid`/`payload.uid` were therefore always
        // `undefined`, which - whenever a real session was present - could never match the session's real
        // `userUid`/`refreshUid` values, so this always 401'd even for an entirely legitimate, freshly
        // rotated refresh token. This is the clearest way to prove that's fixed: a real sign → verify round
        // trip through the actual TokenUtils/JWTUtils stack, not a mocked decode.
        it("Succeeds for a real, freshly-issued refresh token whose uid matches the session.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const user = { uid: "user-1", roles: [] };
            // `session.userUid` here mirrors what `createAuthResult()` would have set during the original
            // login that first issued this refresh token - `createRefreshToken()` alone only manages
            // `refreshUid`.
            const session: any = { userUid: "user-1" };
            const refresh = await tokenUtils.createRefreshToken(user, { session } as any);
            userRepo.findOne.mockResolvedValue(user);
            const req = makeReq({ body: { token: refresh }, session });
            const res = makeRes();

            const result = await route.authenticate(req, res);

            expect(result.user).toEqual(user);
            expect(typeof result.token).toBe("string");
            expect(typeof result.refresh).toBe("string");
            expect(userRepo.findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
        });

        // Regression: `BaseAccountRoute.revokeSessions()` ("log out everywhere") sets `sessionsRevokedAt` -
        // a refresh token issued before that call must be rejected even though it's otherwise a validly
        // signed, session-bound, unexpired token.
        it("Throws 401 for an otherwise-valid refresh token issued before the account's sessionsRevokedAt.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const refresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            // `iat` is second-precision, so this must be at least a full second past the token's issue time
            // to reliably land after it once truncated.
            userRepo.findOne.mockResolvedValue({ uid: "user-1", sessionsRevokedAt: Date.now() + 1000 });
            const req = makeReq({ body: { token: refresh }, session });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        it("Succeeds for a refresh token issued after the account's sessionsRevokedAt (a legitimate re-login).", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const user = { uid: "user-1", roles: [], sessionsRevokedAt: Date.now() - 60000 };
            const refresh = await tokenUtils.createRefreshToken(user, { session } as any);
            userRepo.findOne.mockResolvedValue(user);
            const req = makeReq({ body: { token: refresh }, session });

            const result = await route.authenticate(req, makeRes());

            expect(result.user).toEqual(user);
        });

        it("Throws 401 when the token is well-formed but doesn't match the session's userUid.", async () => {
            const { route, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const refresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            // A session that has since moved on to a *different* user than the one encoded in the token.
            const req = makeReq({
                body: { token: refresh },
                session: { userUid: "someone-else", refreshUid: session.refreshUid },
            });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        // This is the core rotation/reuse-prevention check: a refresh token's own `uid` must match
        // `session.refreshUid`, which is overwritten every time a new refresh token is minted. So a stale
        // (already-rotated-past) refresh token no longer matches, even though it's otherwise a validly
        // signed, unexpired token for the right user.
        it("Throws 401 when the token is a valid, unexpired token for the right user but has already been rotated past (stale refreshUid).", async () => {
            const { route, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const staleRefresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            // A second refresh rotates session.refreshUid forward, invalidating the first token.
            await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            const req = makeReq({ body: { token: staleRefresh }, session });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        it("Throws 401 when there is no session at all, even for an otherwise-valid token.", async () => {
            const { route, tokenUtils } = await setupRoute();
            const refresh = await tokenUtils.createRefreshToken(
                { uid: "user-1" } as any,
                { session: { userUid: "user-1" } } as any,
            );
            const req = makeReq({ body: { token: refresh }, session: undefined });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        it("Throws 401 when the referenced user account no longer exists.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "deleted-user" };
            const refresh = await tokenUtils.createRefreshToken({ uid: "deleted-user" } as any, { session } as any);
            userRepo.findOne.mockResolvedValue(undefined);
            const req = makeReq({ body: { token: refresh }, session });

            await expect(route.authenticate(req, makeRes())).rejects.toThrow(/invalid or missing authentication/i);
        });

        it("Looks up the user with ignoreACL, since the caller isn't authenticated yet at this point.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const refresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            userRepo.findOne.mockResolvedValue({ uid: "user-1" });
            const req = makeReq({ body: { token: refresh }, session });

            await route.authenticate(req, makeRes());

            expect(userRepo.findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
        });

        it("Rotates the refresh token: the newly-issued refresh token's uid differs from the one just consumed.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const oldRefresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            const oldRefreshUid = session.refreshUid;
            userRepo.findOne.mockResolvedValue({ uid: "user-1" });
            const req = makeReq({ body: { token: oldRefresh }, session });

            const result = await route.authenticate(req, makeRes());

            expect(result.refresh).not.toBe(oldRefresh);
            expect(session.refreshUid).not.toBe(oldRefreshUid);
        });

        it("Passes the request through to createAuthResult() so session/cookie state is refreshed on success.", async () => {
            const { route, userRepo, tokenUtils } = await setupRoute();
            const session: any = { userUid: "user-1" };
            const refresh = await tokenUtils.createRefreshToken({ uid: "user-1" } as any, { session } as any);
            userRepo.findOne.mockResolvedValue({ uid: "user-1" });
            const req = makeReq({ body: { token: refresh }, session });

            await route.authenticate(req, makeRes());

            expect(session.userUid).toBe("user-1");
            expect(session.lastAccess).toBeDefined();
        });
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { JWTUtils } from "@rapidrest/core";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

const jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
const user = { uid: "user-1", roles: [], scopes: [] };

function makeRes(): any {
    return { appendHeader: vi.fn(), setHeader: vi.fn() };
}

function makeReq(overrides: any = {}): any {
    return {
        headers: {},
        socket: { remoteAddress: "127.0.0.1" },
        session: {},
        ...overrides,
    };
}

function makeTokenUtils(jwt: any = jwtConfig): TokenUtils {
    const tokenUtils = new TokenUtils();
    (tokenUtils as any).jwtConfig = jwt;
    return tokenUtils;
}

describe("TokenUtils Tests", () => {
    describe("createAccessToken", () => {
        it("Returns a signed JWT that encodes the given user and scopes.", async () => {
            const tokenUtils = makeTokenUtils();

            const token = await tokenUtils.createAccessToken(user, ["read"]);

            expect(typeof token).toBe("string");
            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.profile).toMatchObject({ uid: "user-1", scopes: ["read"] });
        });

        // Regression/core behavior: only an elevated token may carry trusted roles - this is the mechanism
        // `@RequiresElevation`-gated admin actions ultimately rely on. A non-elevated token for the same
        // trusted user must have those roles stripped, not just left alone.
        it("Strips trusted roles from a non-elevated token.", async () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).trustedRoles = ["admin"];
            const trustedUser = { uid: "admin-1", roles: ["admin", "editor"], scopes: [] };

            const token = await tokenUtils.createAccessToken(trustedUser, [], false);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.profile.roles).toEqual(["editor"]);
            expect(payload.profile.elevated).toBeUndefined();
        });

        it("Keeps trusted roles and stamps an elevated timestamp on an elevated token.", async () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).trustedRoles = ["admin"];
            const trustedUser = { uid: "admin-1", roles: ["admin", "editor"], scopes: [] };
            const before = Date.now();

            const token = await tokenUtils.createAccessToken(trustedUser, [], true);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.profile.roles).toEqual(["admin", "editor"]);
            expect(payload.profile.elevated).toBeGreaterThanOrEqual(before);
        });

        it("Signs an elevated token with the configured elevated expiresIn.", async () => {
            const tokenUtils = makeTokenUtils({
                secret: "test-secret",
                options: { expiresIn: "7d" },
                elevated: { expiresIn: "15m" },
            });

            const token = await tokenUtils.createAccessToken(user, [], true);

            const payload = await JWTUtils.decodeToken(
                { secret: "test-secret", options: { expiresIn: "7d" } },
                token,
            );
            const ttl = payload.exp - payload.iat;
            expect(ttl).toBe(15 * 60);
        });

        // Regression: assigning `config.options.expiresIn = parseDuration(...) || config.options.expiresIn`
        // unconditionally used to leave `expiresIn` explicitly set to `undefined` whenever neither
        // `auth:elevated:expiresIn` nor `auth:options:expiresIn` was configured. `jsonwebtoken` validates
        // every *present* options key, so a present-but-undefined `expiresIn` threw `"expiresIn" should be
        // a number of seconds or string representing a timespan"` instead of just omitting the claim.
        it("Does not throw when issuing an elevated token and no expiresIn is configured anywhere.", async () => {
            const tokenUtils = makeTokenUtils({ secret: "test-secret" });

            await expect(tokenUtils.createAccessToken(user, [], true)).resolves.toEqual(expect.any(String));
        });

        it("Falls back to the default (non-elevated) expiresIn when auth:elevated:expiresIn is unset.", async () => {
            const tokenUtils = makeTokenUtils({ secret: "test-secret", options: { expiresIn: "7d" } });

            const token = await tokenUtils.createAccessToken(user, [], true);

            const payload = await JWTUtils.decodeToken(
                { secret: "test-secret", options: { expiresIn: "7d" } },
                token,
            );
            const ttl = payload.exp - payload.iat;
            expect(ttl).toBe(7 * 24 * 60 * 60);
        });
    });

    describe("createRefreshToken", () => {
        it("Returns a signed JWT carrying its own uid and the owning user's uid.", async () => {
            const tokenUtils = makeTokenUtils();

            const token = await tokenUtils.createRefreshToken(user);

            expect(typeof token).toBe("string");
            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.userUid).toBe("user-1");
            expect(typeof payload.uid).toBe("string");
            expect(payload.uid.length).toBeGreaterThan(0);
        });

        it("Encodes only the bare uid in the refresh token's profile, not the full user object.", async () => {
            const tokenUtils = makeTokenUtils();
            const richUser = { uid: "user-1", roles: ["admin"], scopes: ["*"] };

            const token = await tokenUtils.createRefreshToken(richUser);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.profile).toEqual({ uid: "user-1" });
        });

        it("Signs the token with the configured refresh expiresIn.", async () => {
            const tokenUtils = makeTokenUtils({ secret: "test-secret", refresh: { expiresIn: "1h" } });

            const token = await tokenUtils.createRefreshToken(user);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            const ttl = payload.exp - payload.iat;
            expect(ttl).toBe(3600);
        });

        // Regression: `expiresIn` used to be forwarded to `jwt.sign()` straight from config, unparsed and
        // unvalidated. A missing/malformed `auth:refresh:expiresIn` (or a missing `auth:refresh` block
        // entirely) reached `jwt.sign()` as `expiresIn: undefined`, which signs a token with no `exp` claim
        // at all - i.e. one that never expires - rather than falling back to the documented 14-day default.
        it("Falls back to a 14-day expiration when auth:refresh:expiresIn is unset.", async () => {
            const tokenUtils = makeTokenUtils({ secret: "test-secret", refresh: {} });

            const token = await tokenUtils.createRefreshToken(user);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.exp).toBeDefined();
            const ttl = payload.exp - payload.iat;
            expect(ttl).toBe(14 * 24 * 60 * 60);
        });

        it("Falls back to a 14-day expiration when auth:refresh itself is entirely unset.", async () => {
            const tokenUtils = makeTokenUtils({ secret: "test-secret" });

            const token = await tokenUtils.createRefreshToken(user);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.exp).toBeDefined();
            const ttl = payload.exp - payload.iat;
            expect(ttl).toBe(14 * 24 * 60 * 60);
        });

        it("Stores the refresh token's uid on the session when a session is present.", async () => {
            const tokenUtils = makeTokenUtils();
            const req = makeReq();

            const token = await tokenUtils.createRefreshToken(user, req);

            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(req.session.refreshUid).toBe(payload.uid);
        });

        it("Does not throw when no request (and therefore no session) is provided.", async () => {
            const tokenUtils = makeTokenUtils();

            await expect(tokenUtils.createRefreshToken(user)).resolves.toBeDefined();
        });

        it("Does not touch a request that has no session.", async () => {
            const tokenUtils = makeTokenUtils();
            const req: any = { headers: {}, socket: {} };

            await tokenUtils.createRefreshToken(user, req);

            expect(req.session).toBeUndefined();
        });
    });

    describe("createAuthResult", () => {
        it("Returns both a signed access token and a signed refresh token for the given user.", async () => {
            const tokenUtils = makeTokenUtils();

            const result = await tokenUtils.createAuthResult(user, ["read"]);

            expect(typeof result.token).toBe("string");
            expect(typeof result.refresh).toBe("string");
            // Value-equal, not the same reference: `resolveTokenUser()` always returns a fresh copy (see
            // the regression test below) so the returned `user` accurately reflects the token without ever
            // mutating the caller's own object.
            expect(result.user).toEqual(user);

            const accessPayload = await JWTUtils.decodeToken(jwtConfig, result.token);
            expect(accessPayload.profile).toMatchObject({ uid: "user-1", scopes: ["read"] });
            const refreshPayload = await JWTUtils.decodeToken(jwtConfig, result.refresh);
            expect(refreshPayload.userUid).toBe("user-1");
        });

        // Regression: createAccessToken() used to mutate the caller's `user` object in place (stripping
        // roles directly on it, or setting `.elevated` directly on it) rather than operating on a copy. A
        // caller that reused its own `user` reference after calling createAuthResult() - or that called it
        // twice in a row (elevated once, then not) - would silently see its own object's roles/elevated
        // state permanently altered as a side effect.
        it("Does not mutate the caller's user object.", async () => {
            const tokenUtils = makeTokenUtils();
            const trustedUser = { uid: "admin-1", roles: ["admin"], scopes: [] };
            const original = { ...trustedUser, roles: [...trustedUser.roles] };

            await tokenUtils.createAuthResult(trustedUser, ["read"]);

            expect(trustedUser).toEqual(original);
        });

        it("Does not mutate the caller's user object when issuing an elevated token either.", async () => {
            const tokenUtils = makeTokenUtils();
            const plainUser = { uid: "user-1", roles: [], scopes: [] };
            const original = { ...plainUser };

            await tokenUtils.createAuthResult(plainUser, ["read"], undefined, undefined, true);

            expect(plainUser).toEqual(original);
            expect((plainUser as any).elevated).toBeUndefined();
        });

        it("Does not set any cookie when no response is provided.", async () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true, access: { name: "jwt" }, refresh: { name: "refresh" } };

            await expect(tokenUtils.createAuthResult(user, [])).resolves.toBeDefined();
        });

        it("Does not set a cookie when cookie issuance is disabled (the default).", async () => {
            const tokenUtils = makeTokenUtils();
            const res = makeRes();

            await tokenUtils.createAuthResult(user, [], undefined, res);

            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        // Regression: `res.setHeader("Set-Cookie", ...)` called twice would silently clobber the first
        // value - only the second cookie would ever actually reach the client. Both the access and refresh
        // cookies must be written via `appendHeader()`, which the HTTP layer sends as two independent
        // `Set-Cookie` header lines.
        it("Sets two independent `Set-Cookie` headers (access and refresh) via appendHeader when cookie issuance is enabled.", async () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true, access: { name: "jwt" }, refresh: { name: "refresh" } };
            const res = makeRes();

            const result = await tokenUtils.createAuthResult(user, [], undefined, res);

            expect(res.setHeader).not.toHaveBeenCalled();
            expect(res.appendHeader).toHaveBeenCalledTimes(2);
            expect(res.appendHeader).toHaveBeenNthCalledWith(
                1,
                "Set-Cookie",
                expect.stringContaining(`jwt=${result.token}`),
            );
            expect(res.appendHeader).toHaveBeenNthCalledWith(
                2,
                "Set-Cookie",
                expect.stringContaining(`refresh=${result.refresh}`),
            );
        });

        it("Honors custom cookie names for the access and refresh cookies independently.", async () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = {
                enabled: true,
                access: { name: "access_token", path: "/api" },
                refresh: { name: "refresh_token", maxAge: 1209600, secure: true },
            };
            const res = makeRes();

            const result = await tokenUtils.createAuthResult(user, [], undefined, res);

            const [, accessValue] = res.appendHeader.mock.calls[0];
            const [, refreshValue] = res.appendHeader.mock.calls[1];
            expect(accessValue).toBe(`access_token=${result.token}; Path=/api; SameSite=Lax; HttpOnly; Secure`);
            expect(refreshValue).toBe(
                `refresh_token=${result.refresh}; Path=/; SameSite=Lax; Max-Age=1209600; HttpOnly; Secure`,
            );
        });

        it("Records IP, lastAccess, lastLogin and userUid on the session when a session is present.", async () => {
            const tokenUtils = makeTokenUtils();
            const req = makeReq();
            const before = Date.now();

            await tokenUtils.createAuthResult(user, [], req);

            expect(req.session.userUid).toBe("user-1");
            expect(req.session.lastAccess).toBeGreaterThanOrEqual(before);
            expect(req.session.lastLogin).toBeGreaterThanOrEqual(before);
        });

        it("Also rotates the session's refreshUid, matching the newly-issued refresh token.", async () => {
            const tokenUtils = makeTokenUtils();
            const req = makeReq();

            const result = await tokenUtils.createAuthResult(user, [], req);

            const refreshPayload = await JWTUtils.decodeToken(jwtConfig, result.refresh);
            expect(req.session.refreshUid).toBe(refreshPayload.uid);
        });

        it("Does not throw when no request is provided.", async () => {
            const tokenUtils = makeTokenUtils();

            await expect(tokenUtils.createAuthResult(user, [])).resolves.toBeDefined();
        });
    });

    describe("clearToken", () => {
        it("Does nothing when no response is provided.", () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true, access: { name: "jwt" }, refresh: { name: "refresh" } };

            expect(() => tokenUtils.clearToken()).not.toThrow();
        });

        it("Does nothing when cookie issuance is disabled (the default).", () => {
            const tokenUtils = makeTokenUtils();
            const res = makeRes();

            tokenUtils.clearToken(res);

            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        // Regression: this is the exact bug described above for createAuthResult(), on the clearing path -
        // clearToken() used to call `res.setHeader("Set-Cookie", ...)` twice, so only the refresh cookie's
        // clearing header actually reached the client and the access-token cookie stayed alive post-logout.
        it("Clears both the access and refresh cookies via two independent appendHeader calls.", () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = {
                enabled: true,
                access: { name: "jwt" },
                refresh: { name: "refresh" },
            };
            const res = makeRes();

            tokenUtils.clearToken(res);

            expect(res.setHeader).not.toHaveBeenCalled();
            expect(res.appendHeader).toHaveBeenCalledTimes(2);
            expect(res.appendHeader).toHaveBeenNthCalledWith(
                1,
                "Set-Cookie",
                "jwt=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly; Secure",
            );
            expect(res.appendHeader).toHaveBeenNthCalledWith(
                2,
                "Set-Cookie",
                "refresh=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly; Secure",
            );
        });

        it("Honors a custom cookie name and path when clearing.", () => {
            const tokenUtils = makeTokenUtils();
            (tokenUtils as any).cookieConfig = {
                enabled: true,
                access: { name: "access_token", path: "/api" },
                refresh: { name: "refresh_token", path: "/api/refresh" },
            };
            const res = makeRes();

            tokenUtils.clearToken(res);

            const [, accessValue] = res.appendHeader.mock.calls[0];
            const [, refreshValue] = res.appendHeader.mock.calls[1];
            expect(accessValue).toBe("access_token=; Path=/api; SameSite=Lax; Max-Age=0; HttpOnly; Secure");
            expect(refreshValue).toBe("refresh_token=; Path=/api/refresh; SameSite=Lax; Max-Age=0; HttpOnly; Secure");
        });
    });

    describe("buildCookie", () => {
        it("Falls back to all-default cookie attributes when only a name is configured.", () => {
            const tokenUtils = makeTokenUtils();

            const value = (tokenUtils as any).buildCookie("", { name: "jwt" });

            expect(value).toBe("jwt=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly; Secure");
        });

        it("Omits HttpOnly when explicitly disabled.", () => {
            const tokenUtils = makeTokenUtils();

            const value = (tokenUtils as any).buildCookie("token-value", { name: "jwt", httpOnly: false });

            expect(value).toBe("jwt=token-value; Path=/; SameSite=Lax; Secure");
        });

        it("Omits Secure when explicitly disabled (e.g. local/non-HTTPS development).", () => {
            const tokenUtils = makeTokenUtils();

            const value = (tokenUtils as any).buildCookie("token-value", { name: "jwt", secure: false });

            expect(value).toBe("jwt=token-value; Path=/; SameSite=Lax; HttpOnly");
        });

        it("Falls back to the 'jwt' cookie name when none is configured.", () => {
            const tokenUtils = makeTokenUtils();

            const value = (tokenUtils as any).buildCookie("token-value", {});

            expect(value).toBe("jwt=token-value; Path=/; SameSite=Lax; HttpOnly; Secure");
        });
    });
});

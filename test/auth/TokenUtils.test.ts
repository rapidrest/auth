///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { JWTUtils } from "@rapidrest/core";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

const jwtConfig = { secret: "test-secret" };
const user = { uid: "user-1", roles: [], scopes: [] };

function makeRes(): any {
    return { setHeader: vi.fn() };
}

describe("TokenUtils Tests", () => {
    describe("createToken", () => {
        it("Returns a signed JWT that encodes the given user and scopes.", async () => {
            const tokenUtils = new TokenUtils();

            const token = await tokenUtils.createToken(jwtConfig, user, ["read"]);

            expect(typeof token).toBe("string");
            const payload = await JWTUtils.decodeToken(jwtConfig, token);
            expect(payload.profile).toMatchObject({ uid: "user-1", scopes: ["read"] });
        });

        it("Does not set a cookie when no response is provided.", async () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };

            await expect(tokenUtils.createToken(jwtConfig, user, [])).resolves.toBeDefined();
        });

        it("Does not set a cookie when cookie issuance is disabled (the default).", async () => {
            const tokenUtils = new TokenUtils();
            const res = makeRes();

            await tokenUtils.createToken(jwtConfig, user, [], res);

            expect(res.setHeader).not.toHaveBeenCalled();
        });

        it("Sets a `Set-Cookie` header containing the token when cookie issuance is enabled.", async () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };
            const res = makeRes();

            const token = await tokenUtils.createToken(jwtConfig, user, [], res);

            expect(res.setHeader).toHaveBeenCalledTimes(1);
            const [name, value] = res.setHeader.mock.calls[0];
            expect(name).toBe("Set-Cookie");
            expect(value).toBe(`jwt=${token}; Path=/; SameSite=Lax; HttpOnly`);
        });

        it("Honors a custom cookie name, path, max age, sameSite, secure and httpOnly settings.", async () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = {
                enabled: true,
                name: "access_token",
                path: "/api",
                maxAge: 3600,
                sameSite: "Strict",
                secure: true,
                httpOnly: false,
            };
            const res = makeRes();

            const token = await tokenUtils.createToken(jwtConfig, user, [], res);

            const [, value] = res.setHeader.mock.calls[0];
            expect(value).toBe(`access_token=${token}; Path=/api; SameSite=Strict; Max-Age=3600; Secure`);
        });
    });

    describe("clearToken", () => {
        it("Does nothing when no response is provided.", () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };

            expect(() => tokenUtils.clearToken()).not.toThrow();
        });

        it("Does nothing when cookie issuance is disabled (the default).", () => {
            const tokenUtils = new TokenUtils();
            const res = makeRes();

            tokenUtils.clearToken(res);

            expect(res.setHeader).not.toHaveBeenCalled();
        });

        it("Sets a `Set-Cookie` header that immediately expires the cookie when cookie issuance is enabled.", () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };
            const res = makeRes();

            tokenUtils.clearToken(res);

            expect(res.setHeader).toHaveBeenCalledTimes(1);
            const [name, value] = res.setHeader.mock.calls[0];
            expect(name).toBe("Set-Cookie");
            expect(value).toBe("jwt=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly");
        });

        it("Honors a custom cookie name and path when clearing.", () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true, name: "access_token", path: "/api" };
            const res = makeRes();

            tokenUtils.clearToken(res);

            const [, value] = res.setHeader.mock.calls[0];
            expect(value).toBe("access_token=; Path=/api; SameSite=Lax; Max-Age=0; HttpOnly");
        });

        it("Falls back to all-default cookie attributes when cookieConfig itself is unset.", () => {
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = undefined;

            const value = (tokenUtils as any).buildCookie("");

            expect(value).toBe("jwt=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly");
        });
    });
});

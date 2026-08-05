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
});

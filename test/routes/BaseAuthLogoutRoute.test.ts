///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthLogoutRoute — no HTTP server, no database.
import { BaseAuthLogoutRoute } from "../../src/routes/BaseAuthLogoutRoute.js";

class TestAuthLogoutRoute extends BaseAuthLogoutRoute {}

function makeReq(overrides: any = {}): any {
    return { session: { userUid: "user-1", refreshUid: "refresh-uid-1" }, ...overrides };
}

function makeRes(): any {
    return { setHeader: vi.fn(), appendHeader: vi.fn() };
}

describe("BaseAuthLogoutRoute Tests", () => {
    describe("logout", () => {
        it("Clears the auth cookies via tokenUtils when tokenUtils is set.", async () => {
            const route = new TestAuthLogoutRoute();
            const clearToken = vi.fn();
            (route as any).tokenUtils = { clearToken };
            const req = makeReq();
            const res = makeRes();

            await route.logout(req, res);

            expect(clearToken).toHaveBeenCalledWith(res);
        });

        it("Does not throw when tokenUtils was not injected.", async () => {
            const route = new TestAuthLogoutRoute();
            const req = makeReq();
            const res = makeRes();

            await expect(route.logout(req, res)).resolves.toBeUndefined();
        });

        // Regression/completeness: without this, a refresh token leaked before logout (e.g. a narrow XSS
        // window, a synced device) remains fully usable to silently mint new sessions via
        // BaseAuthRefreshRoute until the session's own independent TTL eventually expires - long after the
        // user believed they'd logged out. Clearing the cookies alone isn't enough since
        // BaseAuthRefreshRoute authenticates off session state, not the cookie itself.
        it("Clears userUid and refreshUid from the session so a leaked refresh token can no longer be used after logout.", async () => {
            const route = new TestAuthLogoutRoute();
            (route as any).tokenUtils = { clearToken: vi.fn() };
            const req = makeReq();
            const res = makeRes();

            await route.logout(req, res);

            expect(req.session.userUid).toBeUndefined();
            expect(req.session.refreshUid).toBeUndefined();
        });

        it("Does not throw when the request has no session.", async () => {
            const route = new TestAuthLogoutRoute();
            (route as any).tokenUtils = { clearToken: vi.fn() };
            const req = makeReq({ session: undefined });
            const res = makeRes();

            await expect(route.logout(req, res)).resolves.toBeUndefined();
        });
    });
});

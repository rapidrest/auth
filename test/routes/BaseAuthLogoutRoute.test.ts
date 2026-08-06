///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthLogoutRoute — no HTTP server, no database.
import { BaseAuthLogoutRoute } from "../../src/routes/BaseAuthLogoutRoute.js";

class TestAuthLogoutRoute extends BaseAuthLogoutRoute {}

function makeRes(): any {
    return { setHeader: vi.fn() };
}

describe("BaseAuthLogoutRoute Tests", () => {
    describe("logout", () => {
        it("Clears the auth cookie via tokenUtils when tokenUtils is set.", async () => {
            const route = new TestAuthLogoutRoute();
            const clearToken = vi.fn();
            (route as any).tokenUtils = { clearToken };
            const res = makeRes();

            await route.logout(res);

            expect(clearToken).toHaveBeenCalledWith(res);
        });

        it("Does not throw when tokenUtils was not injected.", async () => {
            const route = new TestAuthLogoutRoute();
            const res = makeRes();

            await expect(route.logout(res)).resolves.toBeUndefined();
        });
    });
});

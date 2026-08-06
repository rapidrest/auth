///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseAuthDiscoverRouteSQL model-binding class — no HTTP server, no
// database. The actual discover logic is exercised by test/routes/BaseAuthDiscoverRoute.test.ts; this
// only confirms the SQL model classes are wired in correctly.
import { AliasSQL, SecretSQL, UserSQL } from "../../../src/sql.js";
import { BaseAuthDiscoverRouteSQL } from "../../../src/routes/sql/BaseAuthDiscoverRouteSQL.js";

class TestAuthDiscoverRouteSQL extends BaseAuthDiscoverRouteSQL {}

describe("BaseAuthDiscoverRouteSQL Tests", () => {
    it("Binds the SQL Alias/Secret/User model classes.", () => {
        const route = new TestAuthDiscoverRouteSQL();

        expect((route as any).aliasClass).toBe(AliasSQL);
        expect((route as any).secretClass).toBe(SecretSQL);
        expect((route as any).userClass).toBe(UserSQL);
    });
});

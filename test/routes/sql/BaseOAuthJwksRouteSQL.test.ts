///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthJwksRouteSQL model-binding class — no HTTP server, no
// database. The actual JWKS logic is exercised by test/routes/BaseOAuthJwksRoute.test.ts; this only
// confirms the SQL model class is wired in correctly.
import { SigningKeySQL } from "../../../src/sql.js";
import { BaseOAuthJwksRouteSQL } from "../../../src/routes/sql/BaseOAuthJwksRouteSQL.js";

class TestOAuthJwksRouteSQL extends BaseOAuthJwksRouteSQL {}

describe("BaseOAuthJwksRouteSQL Tests", () => {
    it("Binds the SQL SigningKey model class.", () => {
        const route = new TestOAuthJwksRouteSQL();

        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthIntrospectRouteSQL model-binding class — no HTTP server, no
// database. The actual introspection logic is exercised by test/routes/BaseOAuthIntrospectRoute.test.ts;
// this only confirms the SQL model classes are wired in correctly.
import { ClientSQL, OAuthRefreshTokenSQL, SigningKeySQL } from "../../../src/sql.js";
import { BaseOAuthIntrospectRouteSQL } from "../../../src/routes/sql/BaseOAuthIntrospectRouteSQL.js";

class TestOAuthIntrospectRouteSQL extends BaseOAuthIntrospectRouteSQL {}

describe("BaseOAuthIntrospectRouteSQL Tests", () => {
    it("Binds the SQL Client/OAuthRefreshToken/SigningKey model classes.", () => {
        const route = new TestOAuthIntrospectRouteSQL();

        expect((route as any).clientClass).toBe(ClientSQL);
        expect((route as any).refreshTokenClass).toBe(OAuthRefreshTokenSQL);
        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthRevokeRouteSQL model-binding class — no HTTP server, no
// database. The actual revocation logic is exercised by test/routes/BaseOAuthRevokeRoute.test.ts; this only
// confirms the SQL model classes are wired in correctly.
import { ClientSQL, OAuthRefreshTokenSQL, SigningKeySQL } from "../../../src/sql.js";
import { BaseOAuthRevokeRouteSQL } from "../../../src/routes/sql/BaseOAuthRevokeRouteSQL.js";

class TestOAuthRevokeRouteSQL extends BaseOAuthRevokeRouteSQL {}

describe("BaseOAuthRevokeRouteSQL Tests", () => {
    it("Binds the SQL Client/OAuthRefreshToken/SigningKey model classes.", () => {
        const route = new TestOAuthRevokeRouteSQL();

        expect((route as any).clientClass).toBe(ClientSQL);
        expect((route as any).refreshTokenClass).toBe(OAuthRefreshTokenSQL);
        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthTokenRouteSQL model-binding class — no HTTP server, no
// database. The actual token-endpoint logic is exercised by test/routes/BaseOAuthTokenRoute.test.ts; this
// only confirms the SQL model classes are wired in correctly.
import { AuthorizationCodeSQL, ClientSQL, SigningKeySQL } from "../../../src/sql.js";
import { BaseOAuthTokenRouteSQL } from "../../../src/routes/sql/BaseOAuthTokenRouteSQL.js";

class TestOAuthTokenRouteSQL extends BaseOAuthTokenRouteSQL {}

describe("BaseOAuthTokenRouteSQL Tests", () => {
    it("Binds the SQL Client/AuthorizationCode/SigningKey model classes.", () => {
        const route = new TestOAuthTokenRouteSQL();

        expect((route as any).clientClass).toBe(ClientSQL);
        expect((route as any).authorizationCodeClass).toBe(AuthorizationCodeSQL);
        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

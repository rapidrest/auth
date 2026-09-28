///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthSessionTokenRouteSQL model-binding class — no HTTP server, no
// database. The actual /oauth/session-token logic is exercised by
// test/routes/BaseOAuthSessionTokenRoute.test.ts; this only confirms the SQL model classes are wired in
// correctly.
import { SigningKeySQL, UserSQL } from "../../../src/sql.js";
import { BaseOAuthSessionTokenRouteSQL } from "../../../src/routes/sql/BaseOAuthSessionTokenRouteSQL.js";

class TestOAuthSessionTokenRouteSQL extends BaseOAuthSessionTokenRouteSQL {}

describe("BaseOAuthSessionTokenRouteSQL Tests", () => {
    it("Binds the SQL User/SigningKey model classes.", () => {
        const route = new TestOAuthSessionTokenRouteSQL();

        expect((route as any).userClass).toBe(UserSQL);
        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

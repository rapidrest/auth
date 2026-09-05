///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthUserInfoRouteSQL model-binding class — no HTTP server, no
// database. The actual /userinfo logic is exercised by test/routes/BaseOAuthUserInfoRoute.test.ts; this
// only confirms the SQL model classes are wired in correctly.
import { ProfileSQL, SigningKeySQL } from "../../../src/sql.js";
import { BaseOAuthUserInfoRouteSQL } from "../../../src/routes/sql/BaseOAuthUserInfoRouteSQL.js";

class TestOAuthUserInfoRouteSQL extends BaseOAuthUserInfoRouteSQL {}

describe("BaseOAuthUserInfoRouteSQL Tests", () => {
    it("Binds the SQL Profile/SigningKey model classes.", () => {
        const route = new TestOAuthUserInfoRouteSQL();

        expect((route as any).profileClass).toBe(ProfileSQL);
        expect((route as any).signingKeyClass).toBe(SigningKeySQL);
    });
});

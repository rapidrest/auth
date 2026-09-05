///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthUserInfoRouteMongo model-binding class — no HTTP server, no
// database. The actual /userinfo logic is exercised by test/routes/BaseOAuthUserInfoRoute.test.ts; this
// only confirms the Mongo model classes are wired in correctly.
import { ProfileMongo, SigningKeyMongo } from "../../../src/mongo.js";
import { BaseOAuthUserInfoRouteMongo } from "../../../src/routes/mongo/BaseOAuthUserInfoRouteMongo.js";

class TestOAuthUserInfoRouteMongo extends BaseOAuthUserInfoRouteMongo {}

describe("BaseOAuthUserInfoRouteMongo Tests", () => {
    it("Binds the Mongo Profile/SigningKey model classes.", () => {
        const route = new TestOAuthUserInfoRouteMongo();

        expect((route as any).profileClass).toBe(ProfileMongo);
        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

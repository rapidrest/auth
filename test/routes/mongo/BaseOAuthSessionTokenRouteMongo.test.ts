///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthSessionTokenRouteMongo model-binding class — no HTTP server,
// no database. The actual /oauth/session-token logic is exercised by
// test/routes/BaseOAuthSessionTokenRoute.test.ts; this only confirms the Mongo model classes are wired in
// correctly.
import { SigningKeyMongo, UserMongo } from "../../../src/mongo.js";
import { BaseOAuthSessionTokenRouteMongo } from "../../../src/routes/mongo/BaseOAuthSessionTokenRouteMongo.js";

class TestOAuthSessionTokenRouteMongo extends BaseOAuthSessionTokenRouteMongo {}

describe("BaseOAuthSessionTokenRouteMongo Tests", () => {
    it("Binds the Mongo User/SigningKey model classes.", () => {
        const route = new TestOAuthSessionTokenRouteMongo();

        expect((route as any).userClass).toBe(UserMongo);
        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

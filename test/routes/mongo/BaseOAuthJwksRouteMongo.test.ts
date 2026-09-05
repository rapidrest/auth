///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthJwksRouteMongo model-binding class — no HTTP server, no
// database. The actual JWKS logic is exercised by test/routes/BaseOAuthJwksRoute.test.ts; this only
// confirms the Mongo model class is wired in correctly.
import { SigningKeyMongo } from "../../../src/mongo.js";
import { BaseOAuthJwksRouteMongo } from "../../../src/routes/mongo/BaseOAuthJwksRouteMongo.js";

class TestOAuthJwksRouteMongo extends BaseOAuthJwksRouteMongo {}

describe("BaseOAuthJwksRouteMongo Tests", () => {
    it("Binds the Mongo SigningKey model class.", () => {
        const route = new TestOAuthJwksRouteMongo();

        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

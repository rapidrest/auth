///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthIntrospectRouteMongo model-binding class — no HTTP server, no
// database. The actual introspection logic is exercised by test/routes/BaseOAuthIntrospectRoute.test.ts;
// this only confirms the Mongo model classes are wired in correctly.
import { ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../../src/mongo.js";
import { BaseOAuthIntrospectRouteMongo } from "../../../src/routes/mongo/BaseOAuthIntrospectRouteMongo.js";

class TestOAuthIntrospectRouteMongo extends BaseOAuthIntrospectRouteMongo {}

describe("BaseOAuthIntrospectRouteMongo Tests", () => {
    it("Binds the Mongo Client/OAuthRefreshToken/SigningKey model classes.", () => {
        const route = new TestOAuthIntrospectRouteMongo();

        expect((route as any).clientClass).toBe(ClientMongo);
        expect((route as any).refreshTokenClass).toBe(OAuthRefreshTokenMongo);
        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

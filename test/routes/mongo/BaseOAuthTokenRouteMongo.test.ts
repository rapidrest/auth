///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthTokenRouteMongo model-binding class — no HTTP server, no
// database. The actual token-endpoint logic is exercised by test/routes/BaseOAuthTokenRoute.test.ts; this
// only confirms the Mongo model classes are wired in correctly.
import { AuthorizationCodeMongo, ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../../src/mongo.js";
import { BaseOAuthTokenRouteMongo } from "../../../src/routes/mongo/BaseOAuthTokenRouteMongo.js";

class TestOAuthTokenRouteMongo extends BaseOAuthTokenRouteMongo {}

describe("BaseOAuthTokenRouteMongo Tests", () => {
    it("Binds the Mongo Client/AuthorizationCode/OAuthRefreshToken/SigningKey model classes.", () => {
        const route = new TestOAuthTokenRouteMongo();

        expect((route as any).clientClass).toBe(ClientMongo);
        expect((route as any).authorizationCodeClass).toBe(AuthorizationCodeMongo);
        expect((route as any).refreshTokenClass).toBe(OAuthRefreshTokenMongo);
        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

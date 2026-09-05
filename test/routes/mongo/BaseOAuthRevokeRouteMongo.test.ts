///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseOAuthRevokeRouteMongo model-binding class — no HTTP server, no
// database. The actual revocation logic is exercised by test/routes/BaseOAuthRevokeRoute.test.ts; this only
// confirms the Mongo model classes are wired in correctly.
import { ClientMongo, OAuthRefreshTokenMongo, SigningKeyMongo } from "../../../src/mongo.js";
import { BaseOAuthRevokeRouteMongo } from "../../../src/routes/mongo/BaseOAuthRevokeRouteMongo.js";

class TestOAuthRevokeRouteMongo extends BaseOAuthRevokeRouteMongo {}

describe("BaseOAuthRevokeRouteMongo Tests", () => {
    it("Binds the Mongo Client/OAuthRefreshToken/SigningKey model classes.", () => {
        const route = new TestOAuthRevokeRouteMongo();

        expect((route as any).clientClass).toBe(ClientMongo);
        expect((route as any).refreshTokenClass).toBe(OAuthRefreshTokenMongo);
        expect((route as any).signingKeyClass).toBe(SigningKeyMongo);
    });
});

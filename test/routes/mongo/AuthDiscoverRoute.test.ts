///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test for the trivial BaseAuthDiscoverRouteMongo model-binding class — no HTTP server,
// no database. The actual discover logic is exercised by test/routes/BaseAuthDiscoverRoute.test.ts;
// this only confirms the Mongo model classes are wired in correctly.
import { AliasMongo, SecretMongo, UserMongo } from "../../../src/mongo.js";
import { BaseAuthDiscoverRouteMongo } from "../../../src/routes/mongo/BaseAuthDiscoverRouteMongo.js";

class TestAuthDiscoverRouteMongo extends BaseAuthDiscoverRouteMongo {}

describe("BaseAuthDiscoverRouteMongo Tests", () => {
    it("Binds the Mongo Alias/Secret/User model classes.", () => {
        const route = new TestAuthDiscoverRouteMongo();

        expect((route as any).aliasClass).toBe(AliasMongo);
        expect((route as any).secretClass).toBe(SecretMongo);
        expect((route as any).userClass).toBe(UserMongo);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import { request } from "@rapidrest/service-core/test";
import { MongoConnection, Server, ObjectFactory, ConnectionManager, MongoRepository } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { SigningKeyMongo } from "../../../src/models/mongo/SigningKeyMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthJwksMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/oauth/jwks";
    let signingKeyRepo: MongoRepository<SigningKeyMongo>;

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            signingKeyRepo = conn.getMongoRepository("SigningKeyMongo");
        } else {
            throw new Error("Could not find mongo connection");
        }
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        try {
            await signingKeyRepo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }
    });

    it("Returns a freshly generated public JWK set with no private key material.", async () => {
        const result = await request(server.getApplication()).get(baseUrl);

        expect(result.status).toBe(200);
        expect(result.body.keys).toHaveLength(1);
        const jwk = result.body.keys[0];
        expect(jwk.kty).toBe("RSA");
        expect(jwk.alg).toBe("RS256");
        expect(jwk.use).toBe("sig");
        expect(jwk.kid).toBeDefined();
        expect(jwk.d).toBeUndefined();
        expect(jwk.privateKeyEncrypted).toBeUndefined();
        expect(result.headers["cache-control"]).toMatch(/^public, max-age=\d+$/);

        const stored = await signingKeyRepo.find().toArray();
        expect(stored).toHaveLength(1);
    });

    it("Returns the same key on subsequent requests instead of generating a new one each time.", async () => {
        const first = await request(server.getApplication()).get(baseUrl);
        const second = await request(server.getApplication()).get(baseUrl);

        expect(first.body.keys[0].kid).toBe(second.body.keys[0].kid);

        const stored = await signingKeyRepo.find().toArray();
        expect(stored).toHaveLength(1);
    });
});

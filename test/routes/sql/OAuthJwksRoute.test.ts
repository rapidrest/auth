///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import { request } from "@rapidrest/service-core/test";
import { MongoConnection, Server, ObjectFactory, ConnectionManager, isSqlDataSource } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { Repository } from "typeorm";
import { SigningKeySQL } from "../../../src/models/sql/SigningKeySQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthJwksSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/oauth/jwks";
    let signingKeyRepo: Repository<SigningKeySQL>;

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            signingKeyRepo = conn.getRepository(SigningKeySQL);
        } else {
            throw new Error("Could not find sql connection");
        }
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        await signingKeyRepo.clear();
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

        const stored = await signingKeyRepo.find();
        expect(stored).toHaveLength(1);
    });

    it("Returns the same key on subsequent requests instead of generating a new one each time.", async () => {
        const first = await request(server.getApplication()).get(baseUrl);
        const second = await request(server.getApplication()).get(baseUrl);

        expect(first.body.keys[0].kid).toBe(second.body.keys[0].kid);

        const stored = await signingKeyRepo.find();
        expect(stored).toHaveLength(1);
    });
});

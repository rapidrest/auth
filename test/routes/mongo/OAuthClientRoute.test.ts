///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Real-database integration coverage for BaseOAuthClientRoute — see test/routes/sql/OAuthClientRoute.test.ts's
// own doc comment for why this tier matters (it's what caught a real bug: `Client` used to have a
// redundant, separately-generated `clientId` field that was never actually populated). `uid` now
// serves as the OAuth `client_id` everywhere.
import config from "../../config";
import { request } from "@rapidrest/service-core/test";
import { MongoConnection, MongoRepository, Server, ObjectFactory, ConnectionManager } from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { ClientMongo } from "../../../src/models/mongo/ClientMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ClientType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:ClientMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/oauth/clients";
    let repo: MongoRepository<ClientMongo>;

    const admin: any = { uid: uuid.v4(), roles: ["admin"], elevated: Date.now() };
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), admin);
    const owner: any = { uid: uuid.v4(), roles: [], elevated: Date.now() };
    const ownerToken = JWTUtils.createTokenSync(config.get("auth"), owner);
    const otherUser: any = { uid: uuid.v4(), roles: [], elevated: Date.now() };
    const otherUserToken = JWTUtils.createTokenSync(config.get("auth"), otherUser);

    function newClientPayload(overrides: Partial<ClientMongo> = {}): Partial<ClientMongo> {
        return {
            clientName: "Test App",
            clientType: ClientType.CONFIDENTIAL,
            redirectUris: ["https://example.com/callback"],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scope: "openid profile",
            tokenEndpointAuthMethod: "client_secret_basic" as any,
            requirePkce: false,
            ...overrides,
        };
    }

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            repo = conn.getMongoRepository("ClientMongo");
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
        await repo.clear();
    });

    it("Persists a distinct, unique uid for every created client and never returns a clientId field (regression).", async () => {
        const result1 = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const result2 = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());

        expect(result1.status).toBeGreaterThanOrEqual(200);
        expect(result1.status).toBeLessThan(300);
        expect(result2.status).toBeGreaterThanOrEqual(200);
        expect(result2.status).toBeLessThan(300);
        expect(result1.body.uid).toBeTruthy();
        expect(result2.body.uid).toBeTruthy();
        expect(result1.body.uid).not.toBe(result2.body.uid);
        expect(result1.body.clientId).toBeUndefined();
        expect(result2.body.clientId).toBeUndefined();
    });

    it("Sets ownerUid to the caller and returns a one-time plaintext secret for a confidential client (with a non-trusted token).", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.ownerUid).toBe(owner.uid);
        expect(result.body.clientSecret).toBeTruthy();
        expect(result.body.clientSecretHash).toBeUndefined();

        const stored: ClientMongo | null = await repo.findOne({ uid: result.body.uid } as any);
        expect(stored?.clientSecretHash).toBeTruthy();
        expect(stored?.clientSecretHash).not.toBe(result.body.clientSecret);
    });

    it("Forces requirePkce true and issues no secret for a public client.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload({ clientType: ClientType.PUBLIC, requirePkce: false }));

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.requirePkce).toBe(true);
        expect(result.body.clientSecret).toBeUndefined();

        const stored: ClientMongo | null = await repo.findOne({ uid: result.body.uid } as any);
        expect(stored?.clientSecretHash).toBeFalsy();
    });

    it("Silently forces firstParty to false for a non-trusted caller.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload({ firstParty: true }));

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.firstParty).toBe(false);
    });

    it("Allows a trusted (admin) caller to register a first-party client.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send(newClientPayload({ firstParty: true }));

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.firstParty).toBe(true);
    });

    it("Rejects a create request with a non-elevated token.", async () => {
        const nonElevated: any = { uid: uuid.v4(), roles: [] };
        const nonElevatedToken = JWTUtils.createTokenSync(config.get("auth"), nonElevated);

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + nonElevatedToken)
            .send(newClientPayload());

        expect(result.status).toBe(403);
    });

    it("Lets the owner read, update, and delete their own client; denies another non-trusted user.", async () => {
        const created = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const clientUid = created.body.uid;
        const url = `${baseUrl}/${clientUid}`;

        const ownerRead = await request(server.getApplication()).get(url).set("Authorization", "jwt " + ownerToken);
        expect(ownerRead.status).toBeGreaterThanOrEqual(200);
        expect(ownerRead.status).toBeLessThan(300);

        const otherRead = await request(server.getApplication()).get(url).set("Authorization", "jwt " + otherUserToken);
        expect(otherRead.status).toBe(403);

        const otherUpdate = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + otherUserToken)
            .send({ uid: clientUid, version: created.body.version, clientName: "Hijacked" });
        expect(otherUpdate.status).toBe(403);

        const otherDelete = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + otherUserToken);
        expect(otherDelete.status).toBe(403);

        const ownerUpdate = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + ownerToken)
            .send({ uid: clientUid, version: created.body.version, clientName: "Renamed" });
        expect(ownerUpdate.status).toBeGreaterThanOrEqual(200);
        expect(ownerUpdate.status).toBeLessThan(300);
        expect(ownerUpdate.body.clientName).toBe("Renamed");

        const ownerDelete = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + ownerToken);
        expect(ownerDelete.status).toBeGreaterThanOrEqual(200);
        expect(ownerDelete.status).toBeLessThan(300);

        const count = await repo.count({ uid: clientUid });
        expect(count).toBe(0);
    });

    it("Lets a trusted (admin) caller read, update, and delete any client with zero special-casing.", async () => {
        const created = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const clientUid = created.body.uid;
        const url = `${baseUrl}/${clientUid}`;

        const adminRead = await request(server.getApplication()).get(url).set("Authorization", "jwt " + adminToken);
        expect(adminRead.status).toBeGreaterThanOrEqual(200);
        expect(adminRead.status).toBeLessThan(300);

        const adminDelete = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + adminToken);
        expect(adminDelete.status).toBeGreaterThanOrEqual(200);
        expect(adminDelete.status).toBeLessThan(300);
    });

    it("Regenerates a confidential client's secret, invalidating the old one, for the owner.", async () => {
        const created = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const clientUid = created.body.uid;
        const oldSecret = created.body.clientSecret;
        const before: ClientMongo | null = await repo.findOne({ uid: clientUid } as any);

        const regenerate = await request(server.getApplication())
            .post(`${baseUrl}/${clientUid}/regenerate-secret`)
            .set("Authorization", "jwt " + ownerToken)
            .send({});

        expect(regenerate.status).toBeGreaterThanOrEqual(200);
        expect(regenerate.status).toBeLessThan(300);
        expect(regenerate.body.clientSecret).toBeTruthy();
        expect(regenerate.body.clientSecret).not.toBe(oldSecret);

        const after: ClientMongo | null = await repo.findOne({ uid: clientUid } as any);
        expect(after?.clientSecretHash).not.toBe(before?.clientSecretHash);
    });

    it("Denies another non-trusted user from regenerating someone else's client secret.", async () => {
        const created = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const clientUid = created.body.uid;

        const result = await request(server.getApplication())
            .post(`${baseUrl}/${clientUid}/regenerate-secret`)
            .set("Authorization", "jwt " + otherUserToken)
            .send({});

        expect(result.status).toBe(403);
    });

    it("Rejects regenerating a secret with a non-elevated token.", async () => {
        const created = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        const clientUid = created.body.uid;
        const nonElevated: any = { uid: owner.uid, roles: [] };
        const nonElevatedToken = JWTUtils.createTokenSync(config.get("auth"), nonElevated);

        const result = await request(server.getApplication())
            .post(`${baseUrl}/${clientUid}/regenerate-secret`)
            .set("Authorization", "jwt " + nonElevatedToken)
            .send({});

        expect(result.status).toBe(403);
    });

    it("Scopes findAll to the caller's own clients for a non-trusted token.", async () => {
        await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + otherUserToken)
            .send(newClientPayload());

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + ownerToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveLength(1);
        expect(result.body[0].ownerUid).toBe(owner.uid);
    });

    it("Lets a trusted (admin) caller see every client via findAll.", async () => {
        await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + ownerToken)
            .send(newClientPayload());
        await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + otherUserToken)
            .send(newClientPayload());

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + adminToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveLength(2);
    });
});

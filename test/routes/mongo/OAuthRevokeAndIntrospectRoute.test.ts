///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import * as argon2 from "argon2";
import { request } from "@rapidrest/service-core/test";
import { ConnectionManager, MongoConnection, MongoRepository, ObjectFactory, Server } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { MongoMemoryServer } from "mongodb-memory-server";
import { ClientMongo } from "../../../src/models/mongo/ClientMongo.js";
import { OAuthRefreshTokenMongo } from "../../../src/models/mongo/OAuthRefreshTokenMongo.js";
import { SigningKeyMongo } from "../../../src/models/mongo/SigningKeyMongo.js";
import { ClientType, TokenEndpointAuthMethod } from "../../../src/models/types.js";
import { hashOpaqueToken } from "../../../src/auth/shared.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthRevokeAndIntrospectMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    let clientRepo: MongoRepository<ClientMongo>;
    let refreshTokenRepo: MongoRepository<OAuthRefreshTokenMongo>;
    let signingKeyRepo: MongoRepository<SigningKeyMongo>;

    async function clearCollection(repo: MongoRepository<any>): Promise<void> {
        try {
            await repo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }
    }

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            clientRepo = conn.getMongoRepository("ClientMongo");
            refreshTokenRepo = conn.getMongoRepository("OAuthRefreshTokenMongo");
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
        await clearCollection(clientRepo);
        await clearCollection(refreshTokenRepo);
        await clearCollection(signingKeyRepo);
    });

    async function createClient(overrides: Partial<ClientMongo> = {}): Promise<ClientMongo> {
        const clientSecretHash = await argon2.hash("client-secret-value");
        return clientRepo.save(
            new ClientMongo({
                clientId: "service-1",
                clientSecretHash,
                clientType: ClientType.CONFIDENTIAL,
                clientName: "Backend Service",
                redirectUris: [],
                grantTypes: ["client_credentials"],
                responseTypes: [],
                scope: "reports:read",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                requirePkce: false,
                firstParty: false,
                ...overrides,
            }),
        );
    }

    async function issueAccessToken(client: ClientMongo): Promise<string> {
        const tokenResult = await request(server.getApplication()).post("/mongo/oauth/token").send({
            grant_type: "client_credentials",
            client_id: client.clientId,
            client_secret: "client-secret-value",
        });
        expect(tokenResult.status).toBe(200);
        return tokenResult.body.access_token;
    }

    async function createRefreshToken(
        client: ClientMongo,
        raw: string,
        overrides: Partial<OAuthRefreshTokenMongo> = {},
    ): Promise<void> {
        await refreshTokenRepo.save(
            new OAuthRefreshTokenMongo({
                tokenHash: hashOpaqueToken(raw),
                clientId: client.clientId,
                userUid: "user-1",
                scope: "reports:read",
                familyId: "family-1",
                expiresAt: new Date(Date.now() + 60_000),
                revoked: false,
                ...overrides,
            }),
        );
    }

    describe("/oauth/revoke", () => {
        it("Revokes a refresh token so it can no longer be redeemed for a new access token.", async () => {
            const client = await createClient();
            const raw = "raw-refresh-token-1";
            await createRefreshToken(client, raw);

            const revokeResult = await request(server.getApplication()).post("/mongo/oauth/revoke").send({
                token: raw,
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(revokeResult.status).toBe(200);
            expect(revokeResult.body).toEqual({});

            const refreshResult = await request(server.getApplication()).post("/mongo/oauth/token").send({
                grant_type: "refresh_token",
                refresh_token: raw,
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(refreshResult.status).toBe(400);
            expect(refreshResult.body.error).toBe("invalid_grant");
        });

        it("Revokes an access token so it is no longer reported active by introspection.", async () => {
            const client = await createClient();
            const accessToken = await issueAccessToken(client);

            const revokeResult = await request(server.getApplication()).post("/mongo/oauth/revoke").send({
                token: accessToken,
                token_type_hint: "access_token",
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(revokeResult.status).toBe(200);

            const introspectResult = await request(server.getApplication()).post("/mongo/oauth/introspect").send({
                token: accessToken,
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(introspectResult.body).toEqual({ active: false });
        });

        it("Returns 200 for a token that doesn't exist at all, without leaking that fact.", async () => {
            const client = await createClient();
            const result = await request(server.getApplication()).post("/mongo/oauth/revoke").send({
                token: "does-not-exist",
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(result.status).toBe(200);
            expect(result.body).toEqual({});
        });

        it("Fails with invalid_client for an unrecognized client.", async () => {
            const result = await request(server.getApplication()).post("/mongo/oauth/revoke").send({
                token: "some-token",
                client_id: "does-not-exist",
                client_secret: "whatever",
            });
            expect(result.status).toBe(401);
            expect(result.body.error).toBe("invalid_client");
        });
    });

    describe("/oauth/introspect", () => {
        it("Reports an active access token with its claims.", async () => {
            const client = await createClient();
            const accessToken = await issueAccessToken(client);

            const result = await request(server.getApplication()).post("/mongo/oauth/introspect").send({
                token: accessToken,
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });

            expect(result.status).toBe(200);
            expect(result.body.active).toBe(true);
            expect(result.body.token_type).toBe("access_token");
            expect(result.body.client_id).toBe(client.clientId);
            expect(result.body.scope).toBe("reports:read");
            expect(result.body.sub).toBe(client.clientId);
        });

        it("Reports an active refresh token with its claims.", async () => {
            const client = await createClient();
            const raw = "raw-refresh-token-1";
            const expiresAt = new Date(Date.now() + 60_000);
            await createRefreshToken(client, raw, { expiresAt });

            const result = await request(server.getApplication()).post("/mongo/oauth/introspect").send({
                token: raw,
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });

            expect(result.body).toEqual({
                active: true,
                token_type: "refresh_token",
                client_id: client.clientId,
                scope: "reports:read",
                exp: Math.floor(expiresAt.getTime() / 1000),
                sub: "user-1",
            });
        });

        it("Returns {active:false} for an unrecognized token.", async () => {
            const client = await createClient();
            const result = await request(server.getApplication()).post("/mongo/oauth/introspect").send({
                token: "does-not-exist",
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(result.status).toBe(200);
            expect(result.body).toEqual({ active: false });
        });

        it("Rejects a public client caller with invalid_client.", async () => {
            const publicClient = await clientRepo.save(
                new ClientMongo({
                    clientId: "mobile-1",
                    clientType: ClientType.PUBLIC,
                    clientName: "Mobile App",
                    redirectUris: ["app://callback"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scope: "profile",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                    requirePkce: true,
                    firstParty: true,
                }),
            );

            const result = await request(server.getApplication()).post("/mongo/oauth/introspect").send({
                token: "some-token",
                client_id: publicClient.clientId,
            });
            expect(result.status).toBe(401);
            expect(result.body.error).toBe("invalid_client");
        });
    });
});

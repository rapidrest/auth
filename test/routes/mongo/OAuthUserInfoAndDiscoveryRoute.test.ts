///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import { agent, request } from "@rapidrest/service-core/test";
import { ACLAction, ACLRecord, ConnectionManager, MongoConnection, MongoRepository, ObjectFactory, Server } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { MongoMemoryServer } from "mongodb-memory-server";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { ProfileMongo } from "../../../src/models/mongo/ProfileMongo.js";
import { ClientMongo } from "../../../src/models/mongo/ClientMongo.js";
import { AuthorizationCodeMongo } from "../../../src/models/mongo/AuthorizationCodeMongo.js";
import { ConsentGrantMongo } from "../../../src/models/mongo/ConsentGrantMongo.js";
import { OAuthRefreshTokenMongo } from "../../../src/models/mongo/OAuthRefreshTokenMongo.js";
import { SigningKeyMongo } from "../../../src/models/mongo/SigningKeyMongo.js";
import { ClientType, ContactType, SecretType, TokenEndpointAuthMethod } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthUserInfoAndDiscoveryMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    let userRepo: MongoRepository<UserMongo>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: MongoRepository<SecretMongo>;
    let profileRepo: MongoRepository<ProfileMongo>;
    let clientRepo: MongoRepository<ClientMongo>;
    let authorizationCodeRepo: MongoRepository<AuthorizationCodeMongo>;
    let consentGrantRepo: MongoRepository<ConsentGrantMongo>;
    let refreshTokenRepo: MongoRepository<OAuthRefreshTokenMongo>;
    let signingKeyRepo: MongoRepository<SigningKeyMongo>;

    const withOwnerACL = async function (uid: string, parentUid: string, ownerId: string): Promise<void> {
        const records: ACLRecord[] = [
            {
                userOrRoleId: ownerId,
                actions: [
                    ACLAction.COUNT,
                    ACLAction.CREATE,
                    ACLAction.DELETE,
                    ACLAction.EXISTS,
                    ACLAction.LIST,
                    ACLAction.READ,
                    ACLAction.TRUNCATE,
                    ACLAction.UPDATE,
                ],
            },
        ];
        await aclRepo.save({ uid, dateCreated: new Date(), dateModified: new Date(), version: 0, records, parentUid });
    };

    const createUserMongo = async function (data?: any): Promise<UserMongo> {
        const obj = new UserMongo({ roles: [], scopes: [], verified: true, ...data });
        const result = await userRepo.save(obj);
        await withOwnerACL(result.uid, "UserMongo", result.uid);
        return result;
    };

    const createSecretMongo = async function (data?: any): Promise<SecretMongo> {
        const obj = new SecretMongo({ data: await argon2.hash("password"), type: SecretType.PASSWORD, ...data });
        const result = await secretRepo.save(obj);
        await withOwnerACL(result.uid, "SecretMongo", result.userUid);
        return result;
    };

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
        let conn: any = connMgr?.connections.get("acl");
        if (conn instanceof MongoConnection) {
            aclRepo = conn.getMongoRepository("AccessControlListMongo");
        }
        conn = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            userRepo = conn.getMongoRepository("UserMongo");
            secretRepo = conn.getMongoRepository("SecretMongo");
            profileRepo = conn.getMongoRepository("ProfileMongo");
            clientRepo = conn.getMongoRepository("ClientMongo");
            authorizationCodeRepo = conn.getMongoRepository("AuthorizationCodeMongo");
            consentGrantRepo = conn.getMongoRepository("ConsentGrantMongo");
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
        await clearCollection(userRepo);
        await clearCollection(secretRepo);
        await clearCollection(profileRepo);
        await clearCollection(clientRepo);
        await clearCollection(authorizationCodeRepo);
        await clearCollection(consentGrantRepo);
        await clearCollection(refreshTokenRepo);
        await clearCollection(signingKeyRepo);
    });

    async function loginAgent(user: UserMongo) {
        const testAgent = agent(server.getApplication());
        const loginResult = await testAgent
            .get("/mongo/auth/password")
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        expect(loginResult.status).toBeGreaterThanOrEqual(200);
        expect(loginResult.status).toBeLessThan(300);
        return testAgent;
    }

    function buildPkce() {
        const verifier = crypto.randomBytes(32).toString("base64url");
        const challenge = crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
        return { verifier, challenge };
    }

    // See test/routes/sql/OAuthAuthorizeAndTokenRoute.test.ts for why this doesn't use `URLSearchParams`.
    function withQuery(path: string, params: Record<string, string>): string {
        const qs = Object.entries(params)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join("&");
        return `${path}?${qs}`;
    }

    async function issueAccessToken(user: UserMongo, client: ClientMongo, scope: string): Promise<string> {
        const testAgent = await loginAgent(user);
        const { verifier, challenge } = buildPkce();

        const authResult = await testAgent.get(
            withQuery("/mongo/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "app://callback",
                scope,
                code_challenge: challenge,
                code_challenge_method: "S256",
            }),
        );
        const redirectUrl = new URL(authResult.body.redirectTo);
        const code = redirectUrl.searchParams.get("code");

        const tokenResult = await request(server.getApplication()).post("/mongo/oauth/token").send({
            grant_type: "authorization_code",
            code,
            redirect_uri: "app://callback",
            code_verifier: verifier,
            client_id: client.uid,
        });
        expect(tokenResult.status).toBe(200);
        return tokenResult.body.access_token;
    }

    describe("/oauth/userinfo", () => {
        it("Returns claims scoped to what was granted, sourced from the resource owner's Profile.", async () => {
            const user = await createUserMongo();
            await createSecretMongo({ userUid: user.uid });
            await profileRepo.save(
                new ProfileMongo({
                    uid: user.uid,
                    givenName: "Ada",
                    familyName: "Lovelace",
                    contacts: [
                        { contact: "ada@example.com", type: ContactType.EMAIL, verified: true },
                        { contact: "555-1234", type: ContactType.PHONE, verified: false },
                    ],
                }),
            );
            const client = await clientRepo.save(
                new ClientMongo({
                    clientType: ClientType.PUBLIC,
                    clientName: "Mobile App",
                    redirectUris: ["app://callback"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scope: "openid profile email phone",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                    requirePkce: true,
                    firstParty: true,
                }),
            );

            const accessToken = await issueAccessToken(user, client, "openid profile email phone");

            const result = await request(server.getApplication())
                .get("/mongo/oauth/userinfo")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(200);
            expect(result.body).toEqual({
                sub: user.uid,
                given_name: "Ada",
                family_name: "Lovelace",
                name: "Ada Lovelace",
                email: "ada@example.com",
                email_verified: true,
                phone_number: "555-1234",
                phone_number_verified: false,
            });
        });

        it("Returns only sub when no additional scope beyond openid was granted.", async () => {
            const user = await createUserMongo();
            await createSecretMongo({ userUid: user.uid });
            await profileRepo.save(new ProfileMongo({ uid: user.uid, givenName: "Ada" }));
            const client = await clientRepo.save(
                new ClientMongo({
                    clientType: ClientType.PUBLIC,
                    clientName: "Mobile App",
                    redirectUris: ["app://callback"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scope: "openid",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                    requirePkce: true,
                    firstParty: true,
                }),
            );

            const accessToken = await issueAccessToken(user, client, "openid");

            const result = await request(server.getApplication())
                .get("/mongo/oauth/userinfo")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.body).toEqual({ sub: user.uid });
        });

        it("Rejects a request with no Authorization header.", async () => {
            const result = await request(server.getApplication()).get("/mongo/oauth/userinfo");
            expect(result.status).toBe(401);
        });

        it("Rejects an access token whose scope does not include openid.", async () => {
            const user = await createUserMongo();
            await createSecretMongo({ userUid: user.uid });
            const client = await clientRepo.save(
                new ClientMongo({
                    clientSecretHash: await argon2.hash("client-secret-value"),
                    clientType: ClientType.CONFIDENTIAL,
                    clientName: "Backend Service",
                    redirectUris: [],
                    grantTypes: ["client_credentials"],
                    responseTypes: [],
                    scope: "reports:read",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                    requirePkce: false,
                    firstParty: false,
                }),
            );
            const tokenResult = await request(server.getApplication()).post("/mongo/oauth/token").send({
                grant_type: "client_credentials",
                client_id: client.uid,
                client_secret: "client-secret-value",
            });
            expect(tokenResult.status).toBe(200);

            const result = await request(server.getApplication())
                .get("/mongo/oauth/userinfo")
                .set("Authorization", `Bearer ${tokenResult.body.access_token}`);

            expect(result.status).toBe(403);
        });

        it("Rejects a revoked access token.", async () => {
            const user = await createUserMongo();
            await createSecretMongo({ userUid: user.uid });
            const client = await clientRepo.save(
                new ClientMongo({
                    clientType: ClientType.PUBLIC,
                    clientName: "Mobile App",
                    redirectUris: ["app://callback"],
                    grantTypes: ["authorization_code"],
                    responseTypes: ["code"],
                    scope: "openid",
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                    requirePkce: true,
                    firstParty: true,
                }),
            );
            const accessToken = await issueAccessToken(user, client, "openid");

            await request(server.getApplication()).post("/mongo/oauth/revoke").send({
                token: accessToken,
                token_type_hint: "access_token",
                client_id: client.uid,
            });

            const result = await request(server.getApplication())
                .get("/mongo/oauth/userinfo")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(401);
        });
    });

    describe("/.well-known", () => {
        it("Serves the same discovery metadata at both the OAuth and OIDC well-known paths.", async () => {
            const oauthResult = await request(server.getApplication()).get("/mongo/.well-known/oauth-authorization-server");
            const oidcResult = await request(server.getApplication()).get("/mongo/.well-known/openid-configuration");

            expect(oauthResult.status).toBe(200);
            expect(oauthResult.body).toEqual(oidcResult.body);
            expect(oauthResult.body.issuer).toBe("https://auth.rapidrest.test");
            expect(oauthResult.body.authorization_endpoint).toBe("http://localhost:3000/mongo/oauth/authorize");
            expect(oauthResult.body.token_endpoint).toBe("http://localhost:3000/mongo/oauth/token");
            expect(oauthResult.body.jwks_uri).toBe("http://localhost:3000/mongo/oauth/jwks");
            expect(oauthResult.body.userinfo_endpoint).toBe("http://localhost:3000/mongo/oauth/userinfo");
            expect(oauthResult.body.revocation_endpoint).toBe("http://localhost:3000/mongo/oauth/revoke");
            expect(oauthResult.body.introspection_endpoint).toBe("http://localhost:3000/mongo/oauth/introspect");
            expect(oauthResult.body.grant_types_supported).toContain("authorization_code");
        });
    });
});

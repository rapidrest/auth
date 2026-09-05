///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import { agent, request } from "@rapidrest/service-core/test";
import { ACLRecord, ACLAction, ConnectionManager, MongoConnection, MongoRepository, ObjectFactory, Server, isSqlDataSource } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { Repository } from "typeorm";
import { MongoMemoryServer } from "mongodb-memory-server";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { ClientSQL } from "../../../src/models/sql/ClientSQL.js";
import { AuthorizationCodeSQL } from "../../../src/models/sql/AuthorizationCodeSQL.js";
import { ConsentGrantSQL } from "../../../src/models/sql/ConsentGrantSQL.js";
import { OAuthRefreshTokenSQL } from "../../../src/models/sql/OAuthRefreshTokenSQL.js";
import { SigningKeySQL } from "../../../src/models/sql/SigningKeySQL.js";
import { ClientType, ContactType, SecretType, TokenEndpointAuthMethod } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthUserInfoAndDiscoverySQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;
    let profileRepo: Repository<ProfileSQL>;
    let clientRepo: Repository<ClientSQL>;
    let authorizationCodeRepo: Repository<AuthorizationCodeSQL>;
    let consentGrantRepo: Repository<ConsentGrantSQL>;
    let refreshTokenRepo: Repository<OAuthRefreshTokenSQL>;
    let signingKeyRepo: Repository<SigningKeySQL>;

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

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj = new UserSQL({ roles: [], scopes: [], verified: true, ...data });
        const result = await userRepo.save(obj);
        await withOwnerACL(result.uid, "UserSQL", result.uid);
        return result;
    };

    const createSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const obj = new SecretSQL({ data: await argon2.hash("password"), type: SecretType.PASSWORD, ...data });
        const result = await secretRepo.save(obj);
        await withOwnerACL(result.uid, "SecretSQL", result.userUid);
        return result;
    };

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        let conn: any = connMgr?.connections.get("acl");
        if (conn instanceof MongoConnection) {
            aclRepo = conn.getMongoRepository("AccessControlListMongo");
        }
        conn = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            userRepo = conn.getRepository(UserSQL);
            secretRepo = conn.getRepository(SecretSQL);
            profileRepo = conn.getRepository(ProfileSQL);
            clientRepo = conn.getRepository(ClientSQL);
            authorizationCodeRepo = conn.getRepository(AuthorizationCodeSQL);
            consentGrantRepo = conn.getRepository(ConsentGrantSQL);
            refreshTokenRepo = conn.getRepository(OAuthRefreshTokenSQL);
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
        await userRepo.clear();
        await secretRepo.clear();
        await profileRepo.clear();
        await clientRepo.clear();
        await authorizationCodeRepo.clear();
        await consentGrantRepo.clear();
        await refreshTokenRepo.clear();
        await signingKeyRepo.clear();
    });

    async function loginAgent(user: UserSQL) {
        const testAgent = agent(server.getApplication());
        const loginResult = await testAgent
            .get("/sql/auth/password")
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

    async function issueAccessToken(user: UserSQL, client: ClientSQL, scope: string): Promise<string> {
        const testAgent = await loginAgent(user);
        const { verifier, challenge } = buildPkce();

        const authResult = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.clientId,
                redirect_uri: "app://callback",
                scope,
                code_challenge: challenge,
                code_challenge_method: "S256",
            }),
        );
        const redirectUrl = new URL(authResult.body.redirectTo);
        const code = redirectUrl.searchParams.get("code");

        const tokenResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "authorization_code",
            code,
            redirect_uri: "app://callback",
            code_verifier: verifier,
            client_id: client.clientId,
        });
        expect(tokenResult.status).toBe(200);
        return tokenResult.body.access_token;
    }

    describe("/oauth/userinfo", () => {
        it("Returns claims scoped to what was granted, sourced from the resource owner's Profile.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            await profileRepo.save(
                new ProfileSQL({
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
                new ClientSQL({
                    clientId: "mobile-app-1",
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
                .get("/sql/oauth/userinfo")
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
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            await profileRepo.save(new ProfileSQL({ uid: user.uid, givenName: "Ada" }));
            const client = await clientRepo.save(
                new ClientSQL({
                    clientId: "mobile-app-2",
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
                .get("/sql/oauth/userinfo")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.body).toEqual({ sub: user.uid });
        });

        it("Rejects a request with no Authorization header.", async () => {
            const result = await request(server.getApplication()).get("/sql/oauth/userinfo");
            expect(result.status).toBe(401);
        });

        it("Rejects an access token whose scope does not include openid.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            const client = await clientRepo.save(
                new ClientSQL({
                    clientId: "service-1",
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
            const tokenResult = await request(server.getApplication()).post("/sql/oauth/token").send({
                grant_type: "client_credentials",
                client_id: client.clientId,
                client_secret: "client-secret-value",
            });
            expect(tokenResult.status).toBe(200);

            const result = await request(server.getApplication())
                .get("/sql/oauth/userinfo")
                .set("Authorization", `Bearer ${tokenResult.body.access_token}`);

            expect(result.status).toBe(403);
        });

        it("Rejects a revoked access token.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            const client = await clientRepo.save(
                new ClientSQL({
                    clientId: "mobile-app-3",
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

            await request(server.getApplication()).post("/sql/oauth/revoke").send({
                token: accessToken,
                token_type_hint: "access_token",
                client_id: client.clientId,
            });

            const result = await request(server.getApplication())
                .get("/sql/oauth/userinfo")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(401);
        });
    });

    describe("/.well-known", () => {
        it("Serves the same discovery metadata at both the OAuth and OIDC well-known paths.", async () => {
            const oauthResult = await request(server.getApplication()).get("/sql/.well-known/oauth-authorization-server");
            const oidcResult = await request(server.getApplication()).get("/sql/.well-known/openid-configuration");

            expect(oauthResult.status).toBe(200);
            expect(oauthResult.body).toEqual(oidcResult.body);
            expect(oauthResult.body.issuer).toBe("https://auth.rapidrest.test");
            expect(oauthResult.body.authorization_endpoint).toBe("http://localhost:3000/sql/oauth/authorize");
            expect(oauthResult.body.token_endpoint).toBe("http://localhost:3000/sql/oauth/token");
            expect(oauthResult.body.jwks_uri).toBe("http://localhost:3000/sql/oauth/jwks");
            expect(oauthResult.body.userinfo_endpoint).toBe("http://localhost:3000/sql/oauth/userinfo");
            expect(oauthResult.body.revocation_endpoint).toBe("http://localhost:3000/sql/oauth/revoke");
            expect(oauthResult.body.introspection_endpoint).toBe("http://localhost:3000/sql/oauth/introspect");
            expect(oauthResult.body.grant_types_supported).toContain("authorization_code");
        });
    });
});

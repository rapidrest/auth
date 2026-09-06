///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import { agent, request } from "@rapidrest/service-core/test";
import {
    ACLRecord,
    MongoConnection,
    MongoRepository,
    Server,
    ObjectFactory,
    ConnectionManager,
    ACLAction,
    isSqlDataSource,
} from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { Repository } from "typeorm";
import { MongoMemoryServer } from "mongodb-memory-server";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { ClientSQL } from "../../../src/models/sql/ClientSQL.js";
import { AuthorizationCodeSQL } from "../../../src/models/sql/AuthorizationCodeSQL.js";
import { ConsentGrantSQL } from "../../../src/models/sql/ConsentGrantSQL.js";
import { OAuthRefreshTokenSQL } from "../../../src/models/sql/OAuthRefreshTokenSQL.js";
import { SigningKeySQL } from "../../../src/models/sql/SigningKeySQL.js";
import { ClientType, SecretType, TokenEndpointAuthMethod } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthAuthorizeAndTokenSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;
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

    // The minimal test transport from @rapidrest/service-core/test has no `.query()` helper — build the
    // query string by hand instead. Deliberately not `URLSearchParams` (which encodes spaces as `+`, the
    // `application/x-www-form-urlencoded` body convention): this framework's query-string parser does not
    // decode `+` back to a space, so a space-delimited `scope` value must be percent-encoded as `%20`
    // instead — universally safe per RFC 3986, and what `encodeURIComponent` produces.
    function withQuery(path: string, params: Record<string, string>): string {
        const qs = Object.entries(params)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join("&");
        return `${path}?${qs}`;
    }

    async function verifyAccessToken(token: string) {
        const decodedHeader: any = jwt.decode(token, { complete: true });
        const jwksResult = await request(server.getApplication()).get("/sql/oauth/jwks");
        const jwk = jwksResult.body.keys.find((k: any) => k.kid === decodedHeader.header.kid);
        expect(jwk).toBeDefined();
        const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
        return jwt.verify(token, publicKey, { algorithms: ["RS256"] }) as any;
    }

    it("Completes the full Authorization Code + PKCE + OIDC flow for a first-party public client.", async () => {
        const user = await createUserSQL();
        await createSecretSQL({ userUid: user.uid });
        const client = await clientRepo.save(
            new ClientSQL({
                clientType: ClientType.PUBLIC,
                clientName: "Mobile App",
                redirectUris: ["app://callback"],
                grantTypes: ["authorization_code"],
                responseTypes: ["code"],
                scope: "openid profile",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                requirePkce: true,
                firstParty: true,
            }),
        );

        const testAgent = await loginAgent(user);
        const { verifier, challenge } = buildPkce();

        const authResult = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "app://callback",
                scope: "openid profile",
                code_challenge: challenge,
                code_challenge_method: "S256",
                state: "xyz",
            }),
        );

        expect(authResult.status).toBe(200);
        expect(authResult.body.redirectTo).toBeDefined();
        const redirectUrl = new URL(authResult.body.redirectTo);
        expect(redirectUrl.searchParams.get("state")).toBe("xyz");
        const code = redirectUrl.searchParams.get("code");
        expect(code).toBeTruthy();

        const tokenResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "authorization_code",
            code,
            redirect_uri: "app://callback",
            code_verifier: verifier,
            client_id: client.uid,
        });

        expect(tokenResult.status).toBe(200);
        expect(tokenResult.headers["cache-control"]).toBe("no-store");
        expect(tokenResult.headers["pragma"]).toBe("no-cache");
        expect(tokenResult.body.token_type).toBe("Bearer");
        expect(tokenResult.body.scope).toBe("openid profile");
        expect(tokenResult.body.id_token).toBeDefined();

        const claims = await verifyAccessToken(tokenResult.body.access_token);
        expect(claims.sub).toBe(user.uid);
        expect(claims.aud).toBe(client.uid);
        expect(claims.client_id).toBe(client.uid);
        expect(claims.scope).toBe("openid profile");

        const idClaims = jwt.decode(tokenResult.body.id_token) as any;
        expect(idClaims.sub).toBe(user.uid);
        expect(idClaims.aud).toBe(client.uid);

        // Replay: the same code cannot be redeemed twice.
        const replay = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "authorization_code",
            code,
            redirect_uri: "app://callback",
            code_verifier: verifier,
            client_id: client.uid,
        });
        expect(replay.status).toBe(400);
        expect(replay.body.error).toBe("invalid_grant");
    });

    it("Issues a refresh_token, rotates it on use, and detects/punishes reuse of an already-rotated token.", async () => {
        const user = await createUserSQL();
        await createSecretSQL({ userUid: user.uid });
        const client = await clientRepo.save(
            new ClientSQL({
                clientType: ClientType.PUBLIC,
                clientName: "Mobile App",
                redirectUris: ["app://callback"],
                grantTypes: ["authorization_code", "refresh_token"],
                responseTypes: ["code"],
                scope: "openid profile offline_access",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                requirePkce: true,
                firstParty: true,
            }),
        );

        const testAgent = await loginAgent(user);
        const { verifier, challenge } = buildPkce();

        const authResult = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "app://callback",
                // `offline_access` is required alongside `openid` for this OIDC flow to be issued a refresh
                // token at all (OIDC Core §11) - see BaseOAuthTokenRoute.issueTokenResponse().
                scope: "openid profile offline_access",
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
            client_id: client.uid,
        });
        expect(tokenResult.status).toBe(200);
        const firstRefreshToken = tokenResult.body.refresh_token;
        expect(firstRefreshToken).toBeTruthy();

        // Redeeming the refresh token rotates it: a new access/id/refresh token comes back.
        const refreshResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "refresh_token",
            refresh_token: firstRefreshToken,
            client_id: client.uid,
        });
        expect(refreshResult.status).toBe(200);
        expect(refreshResult.headers["cache-control"]).toBe("no-store");
        expect(refreshResult.body.id_token).toBeDefined();
        const secondRefreshToken = refreshResult.body.refresh_token;
        expect(secondRefreshToken).toBeTruthy();
        expect(secondRefreshToken).not.toBe(firstRefreshToken);

        const claims = await verifyAccessToken(refreshResult.body.access_token);
        expect(claims.sub).toBe(user.uid);

        // The rotated-out first refresh token can't be redeemed a second time.
        const reuseResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "refresh_token",
            refresh_token: firstRefreshToken,
            client_id: client.uid,
        });
        expect(reuseResult.status).toBe(400);
        expect(reuseResult.body.error).toBe("invalid_grant");

        // Reuse of a rotated-out token revokes the whole family — the token it rotated into is now dead too.
        const secondRefreshAfterTheft = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "refresh_token",
            refresh_token: secondRefreshToken,
            client_id: client.uid,
        });
        expect(secondRefreshAfterTheft.status).toBe(400);
        expect(secondRefreshAfterTheft.body.error).toBe("invalid_grant");
    });

    it("Requires consent for a non-first-party confidential client, then skips it on a later request.", async () => {
        const user = await createUserSQL();
        await createSecretSQL({ userUid: user.uid });
        const clientSecretHash = await argon2.hash("client-secret-value");
        const client = await clientRepo.save(
            new ClientSQL({
                clientSecretHash,
                clientType: ClientType.CONFIDENTIAL,
                clientName: "Web App",
                redirectUris: ["https://app.example.com/callback"],
                grantTypes: ["authorization_code"],
                responseTypes: ["code"],
                scope: "profile email",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                requirePkce: false,
                firstParty: false,
            }),
        );

        const testAgent = await loginAgent(user);

        const firstAuth = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "https://app.example.com/callback",
                scope: "profile email",
                state: "abc",
            }),
        );

        expect(firstAuth.body.consentRequired).toBe(true);
        expect(firstAuth.body.requestId).toBeTruthy();
        expect(firstAuth.body.client.clientName).toBe("Web App");

        const decision = await testAgent.post("/sql/oauth/authorize/consent").send({
            requestId: firstAuth.body.requestId,
            approved: true,
        });

        expect(decision.body.redirectTo).toBeDefined();
        const redirectUrl = new URL(decision.body.redirectTo);
        expect(redirectUrl.searchParams.get("state")).toBe("abc");
        const code = redirectUrl.searchParams.get("code");

        const tokenResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "authorization_code",
            code,
            redirect_uri: "https://app.example.com/callback",
            client_id: client.uid,
            client_secret: "client-secret-value",
        });
        expect(tokenResult.status).toBe(200);
        expect(tokenResult.body.id_token).toBeUndefined();

        // A second /authorize for the same user/client/scope should now skip consent entirely.
        const secondAuth = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "https://app.example.com/callback",
                scope: "profile email",
            }),
        );
        expect(secondAuth.body.redirectTo).toBeDefined();
        expect(secondAuth.body.consentRequired).toBeUndefined();
    });

    it("Returns loginRequired when no one is authenticated.", async () => {
        const client = await clientRepo.save(
            new ClientSQL({
                clientType: ClientType.PUBLIC,
                clientName: "App",
                redirectUris: ["app://callback"],
                grantTypes: ["authorization_code"],
                responseTypes: ["code"],
                scope: "profile",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                requirePkce: false,
                firstParty: true,
            }),
        );

        const result = await request(server.getApplication()).get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "app://callback",
            }),
        );

        expect(result.body).toEqual({ loginRequired: true });
    });

    it("Issues a client-scoped access token via client_credentials, with no id_token or refresh_token.", async () => {
        const clientSecretHash = await argon2.hash("service-secret-value");
        const client = await clientRepo.save(
            new ClientSQL({
                clientSecretHash,
                clientType: ClientType.CONFIDENTIAL,
                clientName: "Backend Service",
                redirectUris: [],
                grantTypes: ["client_credentials", "refresh_token"],
                responseTypes: [],
                scope: "reports:read reports:write",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
                requirePkce: false,
                firstParty: false,
            }),
        );

        const tokenResult = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "client_credentials",
            scope: "reports:read",
            client_id: client.uid,
            client_secret: "service-secret-value",
        });

        expect(tokenResult.status).toBe(200);
        expect(tokenResult.body.scope).toBe("reports:read");
        expect(tokenResult.body.id_token).toBeUndefined();
        expect(tokenResult.body.refresh_token).toBeUndefined();

        const claims = await verifyAccessToken(tokenResult.body.access_token);
        expect(claims.sub).toBe(client.uid);
        expect(claims.aud).toBe(client.uid);
        expect(claims.scope).toBe("reports:read");

        // A public client can never use this grant, regardless of secret.
        const publicClient = await clientRepo.save(
            new ClientSQL({
                clientType: ClientType.PUBLIC,
                clientName: "Mobile App",
                redirectUris: ["app://callback"],
                grantTypes: ["client_credentials"],
                responseTypes: [],
                scope: "reports:read",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                requirePkce: true,
                firstParty: true,
            }),
        );
        const rejected = await request(server.getApplication()).post("/sql/oauth/token").send({
            grant_type: "client_credentials",
            client_id: publicClient.uid,
        });
        expect(rejected.status).toBe(400);
        expect(rejected.body.error).toBe("unauthorized_client");
    });
});

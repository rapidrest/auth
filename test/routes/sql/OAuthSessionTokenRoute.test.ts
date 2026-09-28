///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Full HTTP-level round trip: a real OAuth access token, minted the exact same way `tauri-client` will
// (authorization_code + PKCE via /oauth/authorize + /oauth/token, unmodified), traded in at
// /oauth/session-token for an ordinary session JWT. Unit-level behavior (roles lookup, `res`/`authMethod`
// omission, etc.) is covered by test/routes/BaseOAuthSessionTokenRoute.test.ts; this confirms the whole
// stack — real signing key, real OAuthBearerStrategy, real AccessTokenDenylist — actually rejects an
// expired/revoked/malformed presentation over HTTP, not just in a mock.
import config from "../../config.js";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import { agent, request } from "@rapidrest/service-core/test";
import {
    ACLAction,
    ACLRecord,
    ConnectionManager,
    MongoConnection,
    MongoRepository,
    ObjectFactory,
    Server,
    isSqlDataSource,
} from "@rapidrest/service-core";
import { JWTUser, JWTUtils, Logger } from "@rapidrest/core";
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
import { normalizePasswordSubmission } from "../../../src/auth/shared.js";
import { PasswordConfig } from "../../../src/auth/types.js";

const hashPasswordForLogin = async function (password: string, userUid: string): Promise<string> {
    const canonical = await normalizePasswordSubmission(password, userUid, new PasswordConfig());
    return argon2.hash(canonical);
};

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:OAuthSessionTokenSQL Tests", () => {
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
        const obj = new SecretSQL({
            data: await hashPasswordForLogin("password", data.userUid),
            type: SecretType.PASSWORD,
            ...data,
        });
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

    afterEach(() => {
        vi.restoreAllMocks();
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

    function withQuery(path: string, params: Record<string, string>): string {
        const qs = Object.entries(params)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join("&");
        return `${path}?${qs}`;
    }

    async function createNativeClient(): Promise<ClientSQL> {
        return clientRepo.save(
            new ClientSQL({
                clientType: ClientType.PUBLIC,
                clientName: "tauri-client",
                redirectUris: ["rapidmx://auth/callback"],
                grantTypes: ["authorization_code", "refresh_token"],
                responseTypes: ["code"],
                scope: "openid profile",
                tokenEndpointAuthMethod: TokenEndpointAuthMethod.NONE,
                requirePkce: true,
                firstParty: true,
            }),
        );
    }

    async function issueAccessToken(user: UserSQL, client: ClientSQL, scope: string): Promise<string> {
        const testAgent = await loginAgent(user);
        const { verifier, challenge } = buildPkce();

        const authResult = await testAgent.get(
            withQuery("/sql/oauth/authorize", {
                response_type: "code",
                client_id: client.uid,
                redirect_uri: "rapidmx://auth/callback",
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
            redirect_uri: "rapidmx://auth/callback",
            code_verifier: verifier,
            client_id: client.uid,
        });
        expect(tokenResult.status).toBe(200);
        return tokenResult.body.access_token;
    }

    describe("/oauth/session-token", () => {
        it("Exchanges a valid access token for a real, independently-verifiable session JWT carrying the account's actual roles.", async () => {
            // Deliberately not "admin" - createAuthResult()'s non-elevated path strips every configured
            // `trusted_roles` entry (this config's default `["admin"]`) regardless of caller, exactly like
            // every other plain (non-elevated) sign-in route. Using an untrusted role isolates the behavior
            // this route actually adds - carrying over the real account's roles instead of the OAuth
            // token's always-empty ones - from that unrelated, pre-existing stripping.
            const user = await createUserSQL({ roles: ["editor"] });
            await createSecretSQL({ userUid: user.uid });
            const client = await createNativeClient();
            const accessToken = await issueAccessToken(user, client, "openid profile");

            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(200);
            expect(Object.keys(result.body)).toEqual(["token"]);
            expect(typeof result.body.token).toBe("string");

            const payload = await JWTUtils.decodeToken(config.get("auth"), result.body.token);
            const profile = payload.profile as JWTUser;
            expect(profile.uid).toBe(user.uid);
            // The OAuth access token itself always carries `roles: []` (see OAuthBearerStrategy) — this
            // proves the minted session JWT reflects the *real* account's roles instead.
            expect(profile.roles).toEqual(["editor"]);
        });

        it("Rejects a request with no Authorization header.", async () => {
            const result = await request(server.getApplication()).post("/sql/oauth/session-token");
            expect(result.status).toBe(401);
        });

        it("Rejects a malformed Authorization header.", async () => {
            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", "not-a-bearer-token");
            expect(result.status).toBe(401);
        });

        it("Rejects a syntactically Bearer-shaped but bogus access token.", async () => {
            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", "Bearer this.is.not-a-real-jwt");
            expect(result.status).toBe(401);
        });

        it("Rejects an expired access token.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            const client = await createNativeClient();
            const accessToken = await issueAccessToken(user, client, "openid");

            // OAuthTokenUtils's default accessTokenTTL is 15 minutes — jump the clock well past that.
            // jsonwebtoken's verify() reads the current time via `Date.now()` directly (not a setTimeout),
            // so mocking just that (rather than vi.useFakeTimers(), which would also stall the real SQL
            // connection's own timers) is enough to simulate a genuinely expired token.
            const realNow = Date.now();
            vi.spyOn(Date, "now").mockReturnValue(realNow + 16 * 60 * 1000);

            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(401);
        });

        it("Rejects a revoked (denylisted) access token.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            const client = await createNativeClient();
            const accessToken = await issueAccessToken(user, client, "openid");

            const revokeResult = await request(server.getApplication()).post("/sql/oauth/revoke").send({
                token: accessToken,
                token_type_hint: "access_token",
                client_id: client.uid,
            });
            expect(revokeResult.status).toBe(200);

            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(401);
        });

        it("Rejects an access token whose account no longer exists.", async () => {
            const user = await createUserSQL();
            await createSecretSQL({ userUid: user.uid });
            const client = await createNativeClient();
            const accessToken = await issueAccessToken(user, client, "openid");

            await userRepo.delete({ uid: user.uid });

            const result = await request(server.getApplication())
                .post("/sql/oauth/session-token")
                .set("Authorization", `Bearer ${accessToken}`);

            expect(result.status).toBe(401);
        });
    });
});

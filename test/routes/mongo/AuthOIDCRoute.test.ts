///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// The OIDC provider is a third-party HTTP service — we mock axios (the only transport OIDCStrategy
// uses to talk to it) so the route can be exercised end to end without a real provider. The test
// transport (`@rapidrest/service-core/test`) also uses axios internally for its HTTP calls to the
// server under test, so the real module is preserved and only `get`/`post` are overridden.
vi.mock("axios", async (importOriginal) => {
    const actual = await importOriginal<typeof import("axios")>();
    return {
        ...actual,
        default: {
            ...actual.default,
            get: vi.fn(),
            post: vi.fn(),
        },
    };
});

import config from "../../config.js";
import { agent, request } from "@rapidrest/service-core/test";
import {
    ACLRecord,
    MongoConnection,
    MongoRepository,
    Server,
    ObjectFactory,
    ConnectionManager,
} from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import axios from "axios";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { ProfileMongo } from "../../../src/models/mongo/ProfileMongo.js";
import { AliasType } from "../../../src/models/types.js";
import * as uuid from "uuid";

const mockPost = axios.post as unknown as ReturnType<typeof vi.fn>;
const mockGet = axios.get as unknown as ReturnType<typeof vi.fn>;

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthOIDCMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/auth/oidc";
    let userRepo: MongoRepository<UserMongo>;
    let aclRepo: MongoRepository<any>;
    let aliasRepo: MongoRepository<AliasMongo>;
    let profileRepo: MongoRepository<ProfileMongo>;

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
            aliasRepo = conn.getMongoRepository("AliasMongo");
            profileRepo = conn.getMongoRepository("ProfileMongo");
        } else {
            throw new Error("Could not find user connection");
        }
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        try {
            await userRepo.clear();
            await aliasRepo.clear();
            await profileRepo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }

        mockPost.mockReset();
        mockGet.mockReset();
    });

    /** Extracts the CSRF `state` query param that the redirect step generated and stored in the session. */
    const extractState = function (location: string): string {
        const url = new URL(location);
        return url.searchParams.get("state") as string;
    };

    it("Redirects to the provider's authorization URL with the expected parameters.", async () => {
        const result = await request(server.getApplication()).get(baseUrl);

        expect(result).toBeDefined();
        expect(result.status).toBe(302);
        const location: string = result.headers["location"];
        expect(location).toBeDefined();

        const url = new URL(location);
        expect(url.origin + url.pathname).toBe("https://oidc-test.com/authorize");
        expect(url.searchParams.get("client_id")).toBe("123457890");
        expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:3000");
        expect(url.searchParams.get("response_type")).toBe("code");
        expect(url.searchParams.get("state")).toBeDefined();
    });

    it("Can complete the OIDC callback and provision a new user from the provider profile.", async () => {
        const client = agent(server.getApplication());

        const beginResult = await client.get(baseUrl);
        expect(beginResult.status).toBe(302);
        const state: string = extractState(beginResult.headers["location"]);

        mockPost.mockResolvedValue({
            status: 200,
            data: { access_token: "test-access-token", token_type: "Bearer", expires_in: 3600 },
        });
        mockGet.mockResolvedValue({
            status: 200,
            data: {
                id: "ext-user-1",
                username: "testuser",
                email: "test@example.com",
                verified: true,
                givenName: "Test",
                familyName: "User",
            },
        });

        const result = await client.get(`${baseUrl}?code=auth-code-123&state=${encodeURIComponent(state)}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
        expect(String(result.headers["set-cookie"])).toContain(`jwt=${result.body.token}`);

        expect(mockPost).toHaveBeenCalledWith(
            "https://oidc-test.com/profile",
            expect.objectContaining({ code: "auth-code-123", grant_type: "authorization_code" }),
            expect.anything(),
        );
        expect(mockGet).toHaveBeenCalledWith(
            "https://oidc-test.com/userinfo",
            expect.objectContaining({
                headers: expect.objectContaining({ Authorization: "Bearer test-access-token" }),
            }),
        );

        // A new user, profile, verified email alias, and provider-scoped oauth alias should have been
        // provisioned.
        const users = await userRepo.find({}).toArray();
        expect(users.length).toBe(1);
        const profiles = await profileRepo.find({}).toArray();
        expect(profiles.length).toBe(1);
        expect(profiles[0].givenName).toBe("Test");
        expect(profiles[0].familyName).toBe("User");
        const aliases = await aliasRepo.find({}).toArray();
        expect(aliases.length).toBe(2);
        const emailAlias = aliases.find((a) => a.type === AliasType.EMAIL);
        expect(emailAlias?.alias).toBe("test@example.com");
        expect(emailAlias?.verified).toBe(true);
        const oauthAlias = aliases.find((a) => a.type === AliasType.OAUTH);
        expect(oauthAlias?.alias).toBe("test:ext-user-1");
        expect(oauthAlias?.verified).toBe(true);
        expect(oauthAlias?.userUid).toBe(users[0].uid);
    });

    it("Can complete the OIDC callback for a returning user without creating a duplicate.", async () => {
        // First login provisions the user.
        const first = agent(server.getApplication());
        const beginResult1 = await first.get(baseUrl);
        const state1: string = extractState(beginResult1.headers["location"]);
        mockPost.mockResolvedValue({
            status: 200,
            data: { access_token: "test-access-token", token_type: "Bearer", expires_in: 3600 },
        });
        mockGet.mockResolvedValue({
            status: 200,
            data: { id: "ext-user-2", username: "returning", email: "returning@example.com", verified: true },
        });
        await first.get(`${baseUrl}?code=auth-code-1&state=${encodeURIComponent(state1)}`);

        // Second login with the same provider id should resolve to the same user.
        const second = agent(server.getApplication());
        const beginResult2 = await second.get(baseUrl);
        const state2: string = extractState(beginResult2.headers["location"]);
        const result = await second.get(`${baseUrl}?code=auth-code-2&state=${encodeURIComponent(state2)}`);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const users = await userRepo.find({}).toArray();
        expect(users.length).toBe(1);

        // The provider-scoped alias should have been created once on the first login and not
        // duplicated on the second.
        const oauthAliases = (await aliasRepo.find({}).toArray()).filter((a) => a.type === AliasType.OAUTH);
        expect(oauthAliases.length).toBe(1);
        expect(oauthAliases[0].alias).toBe("test:ext-user-2");
        expect(oauthAliases[0].userUid).toBe(users[0].uid);
    });

    it("Can recognize a returning user by provider id alone when no verified email is returned.", async () => {
        // First login: the provider returns no email at all, so the only durable link back to this
        // user is the provider-scoped oauth alias.
        const first = agent(server.getApplication());
        const beginResult1 = await first.get(baseUrl);
        const state1: string = extractState(beginResult1.headers["location"]);
        mockPost.mockResolvedValue({
            status: 200,
            data: { access_token: "test-access-token", token_type: "Bearer", expires_in: 3600 },
        });
        mockGet.mockResolvedValue({
            status: 200,
            data: { id: "ext-user-no-email", username: "noemail" },
        });
        await first.get(`${baseUrl}?code=auth-code-1&state=${encodeURIComponent(state1)}`);

        const usersAfterFirst = await userRepo.find({}).toArray();
        expect(usersAfterFirst.length).toBe(1);
        const aliasesAfterFirst = await aliasRepo.find({}).toArray();
        expect(aliasesAfterFirst.length).toBe(1);
        expect(aliasesAfterFirst[0].type).toBe(AliasType.OAUTH);
        expect(aliasesAfterFirst[0].alias).toBe("test:ext-user-no-email");

        // Second login, still no email — should resolve to the same user via the oauth alias rather
        // than provisioning a new one.
        const second = agent(server.getApplication());
        const beginResult2 = await second.get(baseUrl);
        const state2: string = extractState(beginResult2.headers["location"]);
        const result = await second.get(`${baseUrl}?code=auth-code-2&state=${encodeURIComponent(state2)}`);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.uid).toBe(usersAfterFirst[0].uid);

        const usersAfterSecond = await userRepo.find({}).toArray();
        expect(usersAfterSecond.length).toBe(1);
    });

    it("Links the provider id alias to an existing account found via the email fallback.", async () => {
        // Simulate an account that predates the oauth alias, or was created via another method,
        // recognizable only by its verified email.
        const existingUser = await userRepo.save(
            new UserMongo({ uid: uuid.v4(), roles: [], scopes: [], verified: true }),
        );
        await aliasRepo.save(
            new AliasMongo({
                uid: uuid.v4(),
                alias: "legacy@example.com",
                type: AliasType.EMAIL,
                userUid: existingUser.uid,
                verified: true,
            }),
        );

        const client = agent(server.getApplication());
        const beginResult = await client.get(baseUrl);
        const state: string = extractState(beginResult.headers["location"]);
        mockPost.mockResolvedValue({
            status: 200,
            data: { access_token: "test-access-token", token_type: "Bearer", expires_in: 3600 },
        });
        mockGet.mockResolvedValue({
            status: 200,
            data: { id: "ext-user-legacy", username: "legacy", email: "legacy@example.com", verified: true },
        });

        const result = await client.get(`${baseUrl}?code=auth-code-1&state=${encodeURIComponent(state)}`);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.uid).toBe(existingUser.uid);

        // No duplicate user should have been created, and the provider-scoped alias should now be
        // linked to the existing account for future logins.
        const users = await userRepo.find({}).toArray();
        expect(users.length).toBe(1);
        const oauthAlias = (await aliasRepo.find({}).toArray()).find((a) => a.type === AliasType.OAUTH);
        expect(oauthAlias).toBeDefined();
        expect(oauthAlias?.alias).toBe("test:ext-user-legacy");
        expect(oauthAlias?.userUid).toBe(existingUser.uid);
    });

    it("Rejects the callback when the state parameter does not match the session (CSRF).", async () => {
        const client = agent(server.getApplication());
        await client.get(baseUrl);

        const result = await client.get(`${baseUrl}?code=auth-code-123&state=bogus-state`);

        expect(result.status).toBe(401);
        expect(mockPost).not.toHaveBeenCalled();
    });

    it("Rejects the callback when the provider reports an error.", async () => {
        const result = await request(server.getApplication()).get(
            `${baseUrl}?error=access_denied&error_description=User+declined`,
        );

        expect(result.status).toBe(401);
        expect(mockPost).not.toHaveBeenCalled();
    });
});

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
    MongoConnection,
    MongoRepository,
    Server,
    ObjectFactory,
    ConnectionManager,
    isSqlDataSource,
} from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import axios from "axios";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";

const mockPost = axios.post as unknown as ReturnType<typeof vi.fn>;
const mockGet = axios.get as unknown as ReturnType<typeof vi.fn>;

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthOIDCSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/oidc";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let aliasRepo: Repository<AliasSQL>;
    let profileRepo: Repository<ProfileSQL>;

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
            aliasRepo = conn.getRepository(AliasSQL);
            profileRepo = conn.getRepository(ProfileSQL);
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
        await aliasRepo.clear();
        await profileRepo.clear();

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

        // A new user, profile and verified email alias should have been provisioned.
        const users = await userRepo.find();
        expect(users.length).toBe(1);
        const profiles = await profileRepo.find();
        expect(profiles.length).toBe(1);
        expect(profiles[0].givenName).toBe("Test");
        expect(profiles[0].familyName).toBe("User");
        const aliases = await aliasRepo.find();
        expect(aliases.length).toBe(1);
        expect(aliases[0].alias).toBe("test@example.com");
        expect(aliases[0].verified).toBe(true);
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

        const users = await userRepo.find();
        expect(users.length).toBe(1);
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

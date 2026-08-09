///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config";
import * as argon2 from "argon2";
import { agent, request } from "@rapidrest/service-core/test";
import {
    ACLRecord,
    MongoConnection,
    MongoRepository,
    Server,
    ObjectFactory,
    ConnectionManager,
    ACLAction,
} from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthRefreshMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const loginUrl = "/mongo/auth/password";
    const refreshUrl = "/mongo/auth/refresh";
    const logoutUrl = "/mongo/auth/logout";
    let userRepo: MongoRepository<UserMongo>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: MongoRepository<SecretMongo>;

    const createUserMongo = async function (data?: any): Promise<UserMongo> {
        const obj: UserMongo = new UserMongo({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserMongo = await userRepo.save(obj);

        const records: ACLRecord[] = [];

        // Owner has CRUD access
        records.push({
            userOrRoleId: obj.uid,
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
        });

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "UserMongo",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createSecretMongo = async function (data?: any): Promise<SecretMongo> {
        const obj: SecretMongo = new SecretMongo({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretMongo = await secretRepo.save(obj);

        const records: ACLRecord[] = [];

        // Owner has CRUD access
        records.push({
            userOrRoleId: obj.userUid,
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
        });

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "SecretMongo",
        };
        await aclRepo.save(acl);

        return result;
    };

    // Logs in via HTTP Basic through a cookie-persisting agent (session + access + refresh cookies all
    // carry forward to subsequent requests made with the same agent), and returns both the agent and the
    // login response body.
    const login = async function (user: UserMongo): Promise<{ client: any; body: any }> {
        const client = agent(server.getApplication());
        const result = await client
            .get(loginUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        return { client, body: result.body };
    };

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
            await secretRepo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }
    });

    it("Can obtain a refresh token on login, alongside the access token.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });

        const { body } = await login(user);

        expect(typeof body.token).toBe("string");
        expect(typeof body.refresh).toBe("string");
    });

    it("Can use the refresh token (via cookie) to obtain a new access token without re-submitting credentials.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { client, body: loginBody } = await login(user);

        const result = await client.get(refreshUrl);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.uid).toBe(user.uid);
        expect(typeof result.body.token).toBe("string");
        expect(typeof result.body.refresh).toBe("string");
        // A fresh refresh token is minted (its uid is random, unlike the access token, whose signature can
        // legitimately be byte-identical to the original when issued within the same second for the same
        // payload).
        expect(result.body.refresh).not.toBe(loginBody.refresh);
    });

    it("Can use the refresh token (via request body) to obtain a new access token.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { client, body: loginBody } = await login(user);

        // Explicitly supplying the token in the body, on the same (session-cookie-carrying) agent, so this
        // exercises the body-token branch of getToken() rather than the cookie fallback.
        const result = await client.post(refreshUrl).send({ token: loginBody.refresh });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.uid).toBe(user.uid);
    });

    // Regression/core behavior: rotation. The refresh token consumed by a successful refresh must no longer
    // be usable for a second refresh - only the newly-issued one is.
    it("Rejects the previous refresh token after it has already been used once (rotation).", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { client, body: loginBody } = await login(user);

        const first = await client.post(refreshUrl).send({ token: loginBody.refresh });
        expect(first.status).toBeGreaterThanOrEqual(200);
        expect(first.status).toBeLessThan(300);

        // Re-submitting the *original* (now-rotated-past) refresh token must fail, even though the session
        // is still otherwise alive and was just used successfully.
        const replay = await client.post(refreshUrl).send({ token: loginBody.refresh });

        expect(replay.status).toBe(401);
    });

    it("Rejects a refresh request with no token and no session.", async () => {
        const result = await request(server.getApplication()).get(refreshUrl);

        expect(result.status).toBe(401);
    });

    it("Rejects a malformed/garbage refresh token.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { client } = await login(user);

        const result = await client.post(refreshUrl).send({ token: "not-a-real-token" });

        expect(result.status).toBe(401);
    });

    it("Rejects a well-formed refresh token replayed against a different (unrelated) session.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { body: loginBody } = await login(user);

        // A brand new agent has no session at all, let alone one matching this refresh token's uid.
        const otherClient = agent(server.getApplication());
        const result = await otherClient.post(refreshUrl).send({ token: loginBody.refresh });

        expect(result.status).toBe(401);
    });

    // Ties BaseAuthLogoutRoute's session-clearing fix to the refresh flow end-to-end: without it, a
    // previously-issued refresh token would remain fully usable after logout for as long as the
    // independent session TTL allowed.
    it("Rejects the refresh token after logout, even though it hasn't expired or been rotated.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const { client, body: loginBody } = await login(user);

        const logoutResult = await client.post(logoutUrl);
        expect(logoutResult.status).toBeGreaterThanOrEqual(200);
        expect(logoutResult.status).toBeLessThan(300);

        const result = await client.post(refreshUrl).send({ token: loginBody.refresh });

        expect(result.status).toBe(401);
    });
});

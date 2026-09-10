///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config";
import * as argon2 from "argon2";
import { request } from "@rapidrest/service-core/test";
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
import { normalizePasswordSubmission } from "../../../src/auth/shared.js";
import { PasswordConfig } from "../../../src/auth/types.js";

// Stored hashes must be of the canonical (would-be client-hashed) form of a plaintext password, not
// the plaintext itself — see normalizePasswordSubmission() in shared.ts, which
// BaseSecretRoute.processPasswordSecret() applies to every password created/changed through the real
// route. A raw `argon2.hash(password)` here (the pre-client-hashing-support shape) would no longer be
// verifiable via Basic auth, since login normalizes a plaintext submission the same way before comparing.
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

describe("Route:AuthBasicMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/auth/password";
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
        const userUid: string = data?.userUid ?? uuid.v4();
        const obj: SecretMongo = new SecretMongo({
            data: await hashPasswordForLogin("password", userUid),
            type: SecretType.PASSWORD,
            userUid,
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

    it("Can authenticate with valid user id and password.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
        expect(String(result.headers["set-cookie"])).toContain(`jwt=${result.body.token}`);
    });

    it("Can authenticate with valid user id and password when multiple passwords exist.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({
            userUid: user.uid,
        });
        await createSecretMongo({
            data: await hashPasswordForLogin("another-password", user.uid),
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":another-password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
    });

    it("Cannot authenticate with invalid user id and password.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":bogus").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
    });

    it("Cannot authenticate via basic auth when the account requires MFA, even with the correct password.", async () => {
        const user: UserMongo = await createUserMongo({ requireMFA: true });
        await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result.status).toBe(401);
    });

    // End-to-end proof of the dual-mode client-side password hashing support: a capable client
    // computes its own Argon2id hash locally (using the documented salt derivation/parameters — see
    // deriveClientSalt()/CLIENT_ARGON2_PARAMS in shared.ts) and submits that instead of the plaintext.
    it("Can authenticate submitting an already client-side-hashed password instead of plaintext.", async () => {
        const shared = await import("../../../src/auth/shared.js");
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({ userUid: user.uid });
        const clientHash = await argon2.hash("password", {
            salt: shared.deriveClientSalt(user.uid),
            ...shared.CLIENT_ARGON2_PARAMS,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":" + clientHash).toString("base64")}`);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveProperty("token");
    });
});

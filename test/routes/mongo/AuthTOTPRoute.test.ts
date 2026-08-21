///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
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
import * as otplib from "otplib";
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

describe("Route:AuthBasicMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/auth/totp";
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
            data: {
                secret: otplib.generateSecret(),
                epochTolerance: [5, 0],
            },
            type: SecretType.TOTP,
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

    it("Can authenticate with valid user id and totp.", async () => {
        const user: UserMongo = await createUserMongo();
        const secret: SecretMongo = await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set(
                "Authorization",
                `totp ${Buffer.from(`id=${user.uid}&token=${await otplib.generate(secret.data)}`).toString("base64")}`,
            );

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
        expect(String(result.headers["set-cookie"])).toContain(`jwt=${result.body.token}`);
    });

    it("Can authenticate with valid user id and totp when multiple totp secrets exist.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({
            userUid: user.uid,
        });
        const secret: SecretMongo = await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set(
                "Authorization",
                `totp ${Buffer.from(`id=${user.uid}&token=${await otplib.generate(secret.data)}`).toString("base64")}`,
            );

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
    });

    it("Cannot authenticate with invalid user id and totp.", async () => {
        const user: UserMongo = await createUserMongo();
        await createSecretMongo({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `totp ${Buffer.from(user.uid + ":123456").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
    });
});

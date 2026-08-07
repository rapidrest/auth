///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
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
import { Logger, MessagingUtils } from "@rapidrest/core";
import * as uuid from "uuid";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { AliasType, SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthMFAMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/auth/mfa";
    let userRepo: MongoRepository<UserMongo>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: MongoRepository<SecretMongo>;
    let aliasRepo: MongoRepository<AliasMongo>;
    let messagingUtils: MessagingUtils;

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

    const createPasswordSecretMongo = async function (data?: any): Promise<SecretMongo> {
        const obj: SecretMongo = new SecretMongo({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretMongo = await secretRepo.save(obj);

        const records: ACLRecord[] = [
            {
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
            },
        ];

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

    const createAliasMongo = async function (data?: any): Promise<AliasMongo> {
        const obj: AliasMongo = new AliasMongo({
            alias: uuid.v4(),
            type: AliasType.EMAIL,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasMongo = await aliasRepo.save(obj);

        const records: ACLRecord[] = [
            {
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
            },
        ];

        const acl: any = {
            uid: result.uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid: "AliasMongo",
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
            aliasRepo = conn.getMongoRepository("AliasMongo");
        } else {
            throw new Error("Could not find user connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
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
            await aliasRepo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }

        // No SMTP provider is configured in the test environment; stub it out and recover the
        // generated token from the captured call args, the way the real contact would have received it.
        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
    });

    it("Returns the list of available 2FA methods after a valid password check.", async () => {
        const user: UserMongo = await createUserMongo();
        await createPasswordSecretMongo({ userUid: user.uid });
        const alias: AliasMongo = await createAliasMongo({ userUid: user.uid });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.uid).toBe(user.uid);
        expect(Array.isArray(result.body.methods)).toBe(true);
        expect(result.body.methods).toHaveLength(1);
        expect(result.body.methods[0]).toMatchObject({ id: alias.uid, type: "otp" });
    });

    it("Cannot authenticate phase 1 with an invalid password.", async () => {
        const user: UserMongo = await createUserMongo();
        await createPasswordSecretMongo({ userUid: user.uid });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":bogus").toString("base64")}`);

        expect(result.status).toBe(401);
    });

    it("Can complete the full 3-phase MFA flow using an OTP contact method.", async () => {
        const user: UserMongo = await createUserMongo();
        await createPasswordSecretMongo({ userUid: user.uid });
        const alias: AliasMongo = await createAliasMongo({ userUid: user.uid });

        const client = agent(server.getApplication());

        // Phase 1: Basic id/password check returns the available 2FA methods.
        const phase1 = await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        expect(phase1.status).toBeGreaterThanOrEqual(200);
        expect(phase1.status).toBeLessThan(300);
        expect(phase1.body.uid).toBe(user.uid);
        expect(phase1.body.methods[0].id).toBe(alias.uid);

        // Phase 2: Request the challenge be sent to the selected method's contact, using the uid
        // returned from phase 1 (not necessarily the same identifier used to log in).
        const phase2 = await client.post(baseUrl).send({ id: phase1.body.uid, methodId: alias.uid });
        expect(phase2.status).toBeGreaterThanOrEqual(200);
        expect(phase2.status).toBeLessThan(300);

        const sendEmailMock = messagingUtils.sendEmail as any;
        expect(sendEmailMock).toHaveBeenCalledTimes(1);
        const token: string = sendEmailMock.mock.calls[0][1].totp;
        expect(token).toBeDefined();

        // Phase 3: Complete the challenge using the token that was "sent" to the contact.
        const phase3 = await client.post(baseUrl).send({ id: user.uid, token });

        expect(phase3).toBeDefined();
        expect(phase3.status).toBeGreaterThanOrEqual(200);
        expect(phase3.status).toBeLessThan(300);
        expect(phase3.body).toBeDefined();
        expect(phase3.body).toHaveProperty("token");
        expect(phase3.body).toHaveProperty("user");
        expect(phase3.body.user.uid).toBe(user.uid);
        expect(String(phase3.headers["set-cookie"])).toContain(`jwt=${phase3.body.token}`);
    });

    it("Cannot complete phase 3 with an invalid OTP token.", async () => {
        const user: UserMongo = await createUserMongo();
        await createPasswordSecretMongo({ userUid: user.uid });
        const alias: AliasMongo = await createAliasMongo({ userUid: user.uid });

        const client = agent(server.getApplication());
        await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        await client.post(baseUrl).send({ id: user.uid, methodId: alias.uid });

        const result = await client.post(baseUrl).send({ id: user.uid, token: "000000" });
        expect(result.status).toBe(401);
    });

    it("Cannot request a challenge for an unknown method id.", async () => {
        const user: UserMongo = await createUserMongo();
        await createPasswordSecretMongo({ userUid: user.uid });
        await createAliasMongo({ userUid: user.uid });

        const client = agent(server.getApplication());
        await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        const result = await client.post(baseUrl).send({ id: user.uid, methodId: uuid.v4() });
        expect(result.status).toBe(401);
    });
});

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
    isSqlDataSource,
} from "@rapidrest/service-core";
import { Logger, MessagingUtils } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { AliasType, SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthMFASQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/mfa";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;
    let aliasRepo: Repository<AliasSQL>;
    let messagingUtils: MessagingUtils;

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj: UserSQL = new UserSQL({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserSQL = await userRepo.save(obj);

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
            parentUid: "UserSQL",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createPasswordSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

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
            parentUid: "SecretSQL",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createAliasSQL = async function (data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.EMAIL,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasSQL = await aliasRepo.save(obj);

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
            parentUid: "AliasSQL",
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
        conn = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            userRepo = conn.getRepository(UserSQL);
            secretRepo = conn.getRepository(SecretSQL);
            aliasRepo = conn.getRepository(AliasSQL);
        } else {
            throw new Error("Could not find sql connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        await userRepo.clear();
        await secretRepo.clear();
        await aliasRepo.clear();

        // No SMTP provider is configured in the test environment; stub it out and recover the
        // generated token from the captured call args, the way the real contact would have received it.
        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
    });

    it("Returns the list of available 2FA methods after a valid password check.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(Array.isArray(result.body)).toBe(true);
        expect(result.body).toHaveLength(1);
        expect(result.body[0]).toMatchObject({ id: alias.uid, type: "otp" });
    });

    it("Cannot authenticate phase 1 with an invalid password.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":bogus").toString("base64")}`);

        expect(result.status).toBe(401);
    });

    it("Can complete the full 3-phase MFA flow using an OTP contact method.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });

        const client = agent(server.getApplication());

        // Phase 1: Basic id/password check returns the available 2FA methods.
        const phase1 = await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        expect(phase1.status).toBeGreaterThanOrEqual(200);
        expect(phase1.status).toBeLessThan(300);
        expect(phase1.body[0].id).toBe(alias.uid);

        // Phase 2: Request the challenge be sent to the selected method's contact.
        const phase2 = await client.post(baseUrl).send({ id: user.uid, methodId: alias.uid });
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
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });

        const client = agent(server.getApplication());
        await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        await client.post(baseUrl).send({ id: user.uid, methodId: alias.uid });

        const result = await client.post(baseUrl).send({ id: user.uid, token: "000000" });
        expect(result.status).toBe(401);
    });

    it("Cannot request a challenge for an unknown method id.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        await createAliasSQL({ userUid: user.uid });

        const client = agent(server.getApplication());
        await client
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        const result = await client.post(baseUrl).send({ id: user.uid, methodId: uuid.v4() });
        expect(result.status).toBe(401);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
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
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { AliasType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthOTPSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/otp";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
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

    const createAliasSQL = async function (data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.EMAIL,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasSQL = await aliasRepo.save(obj);

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
        await aliasRepo.clear();

        // No SMTP/Twilio provider is configured in the test environment, so sending would otherwise
        // reject in the background (fire-and-forget, per `BaseAuthOTPRoute.notifyContact`). Stub it out
        // and use the captured call args to recover the generated token, the way the real contact would
        // have received it via e-mail/SMS.
        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
    });

    it("Can request and verify an OTP challenge sent to a verified contact.", async () => {
        const user: UserSQL = await createUserSQL();
        const alias: AliasSQL = await createAliasSQL({
            userUid: user.uid,
        });
        const client = agent(server.getApplication());

        // Phase 2: Request a challenge be sent to the contact.
        const challengeResult = await client.post(baseUrl).send({ id: alias.uid });
        expect(challengeResult).toBeDefined();
        expect(challengeResult.status).toBeGreaterThanOrEqual(200);
        expect(challengeResult.status).toBeLessThan(300);

        const sendEmailMock = messagingUtils.sendEmail as any;
        expect(sendEmailMock).toHaveBeenCalledTimes(1);
        const token: string = sendEmailMock.mock.calls[0][1].totp;
        expect(token).toBeDefined();

        // Phase 3: Complete the challenge using the token that was "sent" to the contact.
        const result = await client.post(baseUrl).send({ id: alias.uid, token });

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
        expect(String(result.headers["set-cookie"])).toContain(`jwt=${result.body.token}`);
    });

    it("Cannot verify an OTP challenge with an invalid token.", async () => {
        const user: UserSQL = await createUserSQL();
        const alias: AliasSQL = await createAliasSQL({
            userUid: user.uid,
        });
        const client = agent(server.getApplication());

        const challengeResult = await client.post(baseUrl).send({ id: alias.uid });
        expect(challengeResult.status).toBeGreaterThanOrEqual(200);
        expect(challengeResult.status).toBeLessThan(300);

        const result = await client.post(baseUrl).send({ id: alias.uid, token: "000000" });
        expect(result.status).toBe(401);
    });

    it("Cannot verify an OTP challenge without first requesting one (no session state).", async () => {
        const user: UserSQL = await createUserSQL();
        const alias: AliasSQL = await createAliasSQL({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .post(baseUrl)
            .send({ id: alias.uid, token: "000000" });

        expect(result.status).toBe(401);
    });

    it("Cannot request a challenge for an unknown contact id.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .send({ id: uuid.v4() });

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
        expect(messagingUtils.sendEmail).not.toHaveBeenCalled();
    });

    it("Cannot authenticate without any request data.", async () => {
        const result = await request(server.getApplication()).get(baseUrl);

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
    });
});

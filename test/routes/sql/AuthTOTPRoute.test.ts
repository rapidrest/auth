///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
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
    isSqlDataSource,
} from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import * as otplib from "otplib";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthTOTPSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/totp";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;

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

    const createSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const obj: SecretSQL = new SecretSQL({
            data: {
                secret: otplib.generateSecret(),
                epochTolerance: [5, 0],
            },
            type: SecretType.TOTP,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

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
            parentUid: "SecretSQL",
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
    });

    it("Can authenticate with valid user id and totp.", async () => {
        const user: UserSQL = await createUserSQL();
        const secret: SecretSQL = await createSecretSQL({
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
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({
            userUid: user.uid,
        });
        const secret: SecretSQL = await createSecretSQL({
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
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `totp ${Buffer.from(user.uid + ":123456").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
    });
});

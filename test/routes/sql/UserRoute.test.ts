///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config";
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
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:UserSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/users";
    let repo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    const admin: any = {
        uid: uuid.v4(),
        roles: ["admin"],
    };
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), admin);
    const user: any = {
        uid: uuid.v4(),
        roles: [],
    };
    const userToken = JWTUtils.createTokenSync(config.get("auth"), user);

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj: UserSQL = new UserSQL({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserSQL = await repo.save(obj);

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

    const createUserSQLs = async function (num: number, data?: any): Promise<UserSQL[]> {
        const results: UserSQL[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createUserSQL(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object. `scopes` has no `@Column()` and is
    // purposefully not persisted for the SQL model (unlike Mongo's schemaless driver, which happens to
    // store it anyway), so it never round-trips here.
    const SERVER_ASSIGNED_FIELDS = ["uid", "dateCreated", "dateModified", "version", "scopes"];

    const expectMatchingFields = function (actual: any, expected: any): void {
        for (const key in expected) {
            if (SERVER_ASSIGNED_FIELDS.includes(key)) {
                continue;
            }
            expect(actual[key]).toEqual(expected[key]);
        }
        expect(actual.uid).toBeDefined();
        expect(new Date(actual.dateCreated).getTime()).not.toBeNaN();
        expect(new Date(actual.dateModified).getTime()).not.toBeNaN();
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
            repo = conn.getRepository(UserSQL);
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
        await repo.clear();
    });

    it("Can make count request (with admin token).", async () => {
        const objs: UserSQL[] = await createUserSQLs(5);

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.headers).toHaveProperty("content-length");
        expect(result.headers["content-length"]).toBe(objs.length.toString());
    });

    it("Can make create request (with admin token).", async () => {
        const obj: UserSQL = new UserSQL({
            roles: ["test"],
            scopes: ["profile"],
            verified: true,
        });

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send(obj);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: UserSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it(
        "A User provisioned by an admin can read and update their own record afterward " +
            "(regression test: `RepoUtils.create()`'s automatic owner grant is skipped for trusted-role " +
            "callers, since a trusted caller creating e.g. an Alias/Secret for themselves doesn't need a " +
            "redundant grant — but an admin provisioning a User on someone else's behalf has no such " +
            "self-service creator, so without this fix nobody ever gets a grant and the new user is locked " +
            "out of their own account).",
        async () => {
            const createResult = await request(server.getApplication())
                .post(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ roles: [], scopes: [], verified: true });

            expect(createResult).toBeDefined();
            expect(createResult.status).toBeGreaterThanOrEqual(200);
            expect(createResult.status).toBeLessThan(300);
            const newUserUid: string = createResult.body.uid;

            const newUserToken = JWTUtils.createTokenSync(config.get("auth"), {
                uid: newUserUid,
                roles: [],
                scopes: [],
            });

            const readResult = await request(server.getApplication())
                .get(`${baseUrl}/${newUserUid}`)
                .set("Authorization", "jwt " + newUserToken);

            expect(readResult).toBeDefined();
            expect(readResult.status).toBeGreaterThanOrEqual(200);
            expect(readResult.status).toBeLessThan(300);
            expect(readResult.body.uid).toBe(newUserUid);

            // `scopes` has no `@Column()` and isn't persisted for the SQL model — the update route can't
            // tolerate an unrecognized `scopes` key in the request body, so it's stripped here.
            const { scopes, ...payload } = readResult.body;
            const updateResult = await request(server.getApplication())
                .put(`${baseUrl}/${newUserUid}`)
                .set("Authorization", "jwt " + newUserToken)
                .send({ ...payload, verified: true });

            expect(updateResult).toBeDefined();
            expect(updateResult.status).toBeGreaterThanOrEqual(200);
            expect(updateResult.status).toBeLessThan(300);
        },
    );

    it("Can make delete request (with admin token).", async () => {
        const obj: UserSQL = await createUserSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        // Validate the contents were removed
        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(0);
    });

    it("Can make findAll request (with admin token).", async () => {
        const objs: UserSQL[] = await createUserSQLs(5);

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveLength(objs.length);
        for (let i = 0; i < objs.length; i++) {
            expectMatchingFields(result.body[i], objs[i]);
        }
    });

    it("Can make findById request (with admin token).", async () => {
        const obj: UserSQL = await createUserSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);
    });

    it("Can make truncate request (with admin token).", async () => {
        const objs: UserSQL[] = await createUserSQLs(5);
        let count: number = await repo.count();
        expect(count).toBe(objs.length);

        const result = await request(server.getApplication())
            .delete(baseUrl)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        count = await repo.count();
        expect(count).toBe(0);
    });

    it("Can make update request (with admin token).", async () => {
        // `scopes` has no `@Column()` and isn't persisted for the SQL model (see SERVER_ASSIGNED_FIELDS),
        // so `roles` — an actually persisted field — is used here to exercise the update itself. The SQL
        // update route can't tolerate an unrecognized `scopes` key in the request body at all (unlike
        // create), so it's stripped from the payload rather than merely left unchanged.
        const obj: UserSQL = await createUserSQL();
        const url = baseUrl + "/" + obj.uid;
        obj.roles = ["test", "another-role"];
        const { scopes, ...payload } = obj;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(payload);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: UserSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make update property request (with admin token).", async () => {
        const obj: UserSQL = await createUserSQL();
        const url = baseUrl + "/" + obj.uid + "/roles";
        obj.roles = ["test", "another-role"];

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj.roles);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: UserSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });
});

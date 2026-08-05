///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import { request } from "@rapidrest/service-core/test";
import {
    ACLRecord,
    MongoConnection,
    MongoRepository,
    RepoUtils,
    Server,
    ObjectFactory,
    ConnectionManager,
    ACLAction,
    isSqlDataSource,
} from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:ProfileSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/profiles";
    let repo: Repository<ProfileSQL>;
    let aclRepo: MongoRepository<any>;
    const admin: any = {
        uid: uuid.v4(),
        roles: ["admin"],
        scopes: ["profile:contacts", "profile:preferences"],
    };
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), admin);
    const user: any = {
        uid: uuid.v4(),
        roles: [],
        scopes: ["profile:contacts", "profile:preferences"],
    };
    const userToken = JWTUtils.createTokenSync(config.get("auth"), user);

    const createProfileSQL = async function (data?: any): Promise<ProfileSQL> {
        const obj: ProfileSQL = new ProfileSQL({
            avatar: "https://gravatar.com/john.smith",
            birthdate: new Date(),
            givenName: "John",
            familyName: "Smith",
            ...data,
        });

        const result: ProfileSQL = await repo.save(obj);

        const records: ACLRecord[] = [];

        // Owner has CRUD access. Unlike Alias/Secret, a Profile has no separate `userUid` field — its own
        // `uid` *is* the owning user's uid — so the ACL record must be keyed by `obj.uid`.
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
            parentUid: "ProfileSQL",
        };
        // Unlike Alias/Secret (whose own uid is always freshly random), some tests pin a Profile's uid to a
        // fixed `user.uid` to represent "the caller's own profile" — since `repo.clear()` in `beforeEach`
        // only clears Profile documents (not ACLs), a leftover ACL from an earlier test with the same uid
        // must be removed first to avoid colliding with the (uid, version) unique index.
        await aclRepo.deleteOne({ uid: result.uid });
        await aclRepo.save(acl);

        return result;
    };

    const createProfileSQLs = async function (num: number, data?: any): Promise<ProfileSQL[]> {
        const results: ProfileSQL[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createProfileSQL(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object.
    const SERVER_ASSIGNED_FIELDS = ["uid", "dateCreated", "dateModified", "version"];

    const expectMatchingFields = function (actual: any, expected: any): void {
        for (const key in expected) {
            if (SERVER_ASSIGNED_FIELDS.includes(key)) {
                continue;
            }
            // Client-controlled Date fields (e.g. birthdate) are real Date instances locally but
            // arrive over JSON as ISO strings, so compare the underlying instant rather than the type.
            if (expected[key] instanceof Date) {
                expect(new Date(actual[key]).getTime()).toEqual(expected[key].getTime());
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
            repo = conn.getRepository(ProfileSQL);
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
        const objs: ProfileSQL[] = await createProfileSQLs(5);

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
        const obj: ProfileSQL = new ProfileSQL({
            avatar: "https://gravatar.com/john.smith",
            birthdate: new Date("10/09/1982"),
            givenName: "John",
            familyName: "Smith",
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
        const existing: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make delete request (with admin token).", async () => {
        const obj: ProfileSQL = await createProfileSQL();
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
        const objs: ProfileSQL[] = await createProfileSQLs(5);

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
        const obj: ProfileSQL = await createProfileSQL();
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

    it("Can retrieve their own profile by id (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);
    });

    it("Can retrieve their own profile via the 'me' alias (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid });

        const result = await request(server.getApplication())
            .get(`${baseUrl}/me`)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);
    });

    it("Cannot retrieve another user's profile by id (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBe(403);
    });

    it("findAll only returns their own profile, not other users' (with user token).", async () => {
        const own: ProfileSQL = await createProfileSQL({ uid: user.uid });
        await createProfileSQLs(3);

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveLength(1);
        expectMatchingFields(result.body[0], own);
    });

    it(
        "A self-registered User (created with no authenticated actor, exactly like " +
            "BaseRegistrationRoute.verify() does) can still create, read and update their own Profile " +
            "afterward, even though the two share the same uid (regression test for the User/Profile ACL " +
            "collision — a Profile's uid is intentionally the same as its owning User's uid, and Profile no " +
            "longer participates in the generic per-record ACL system precisely because of this).",
        async () => {
            const userRepoUtils: RepoUtils<UserSQL> = await objectFactory.newInstance(RepoUtils, {
                name: UserSQL.name,
                args: [UserSQL],
            });
            const newUser: UserSQL = await userRepoUtils.create(new UserSQL({ verified: true }), {
                ignoreACL: true,
            });
            const newUserToken = JWTUtils.createTokenSync(config.get("auth"), {
                uid: newUser.uid,
                roles: [],
                scopes: ["profile:contacts", "profile:preferences"],
            });

            const createResult = await request(server.getApplication())
                .post(baseUrl)
                .set("Authorization", "jwt " + newUserToken)
                .send({ givenName: "New", familyName: "User" });

            expect(createResult).toBeDefined();
            expect(createResult.status).toBeGreaterThanOrEqual(200);
            expect(createResult.status).toBeLessThan(300);
            expect(createResult.body.uid).toBe(newUser.uid);

            const readResult = await request(server.getApplication())
                .get(`${baseUrl}/me`)
                .set("Authorization", "jwt " + newUserToken);

            expect(readResult.status).toBeGreaterThanOrEqual(200);
            expect(readResult.status).toBeLessThan(300);
            expect(readResult.body.uid).toBe(newUser.uid);

            const updateResult = await request(server.getApplication())
                .put(`${baseUrl}/${newUser.uid}`)
                .set("Authorization", "jwt " + newUserToken)
                .send({ ...readResult.body, givenName: "Updated" });

            expect(updateResult).toBeDefined();
            expect(updateResult.status).toBeGreaterThanOrEqual(200);
            expect(updateResult.status).toBeLessThan(300);
            expect(updateResult.body.givenName).toBe("Updated");

            // findAll is the path that actually depended on the (colliding) per-record ACL grant before
            // Profile stopped using it — everything above already goes through `ignoreACL: true`.
            const listResult = await request(server.getApplication())
                .get(baseUrl)
                .set("Authorization", "jwt " + newUserToken);

            expect(listResult.status).toBeGreaterThanOrEqual(200);
            expect(listResult.status).toBeLessThan(300);
            expect(listResult.body).toHaveLength(1);
            expect(listResult.body[0].uid).toBe(newUser.uid);
        },
    );

    it("Can make truncate request (with admin token).", async () => {
        const objs: ProfileSQL[] = await createProfileSQLs(5);
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
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid;
        obj.givenName = uuid.v4();

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make update property request (with admin token).", async () => {
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid + "/avatar";
        obj.avatar = "https://facebook.com/ladeeda";

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj.avatar);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });
});

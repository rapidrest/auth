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
} from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:UserMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/users";
    let repo: MongoRepository<UserMongo>;
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

    const createUserMongo = async function (data?: any): Promise<UserMongo> {
        const obj: UserMongo = new UserMongo({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserMongo = await repo.save(obj);

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

    const createUserMongos = async function (num: number, data?: any): Promise<UserMongo[]> {
        const results: UserMongo[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createUserMongo(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object. _id is MongoDB's internal driver
    // identifier (an ObjectId on the local object vs. its JSON-serialized hex string over HTTP) and isn't
    // part of the User model's public interface.
    const SERVER_ASSIGNED_FIELDS = ["uid", "dateCreated", "dateModified", "version", "_id"];

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
        conn = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            repo = conn.getMongoRepository("UserMongo");
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
            await repo.clear();
        } catch (err: any) {
            // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
            if (err.message !== "ns not found") {
                throw err;
            }
        }
    });

    it("Can make count request (with admin token).", async () => {
        const objs: UserMongo[] = await createUserMongos(5);

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
        const obj: UserMongo = new UserMongo({
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
        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
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

            const updateResult = await request(server.getApplication())
                .put(`${baseUrl}/${newUserUid}`)
                .set("Authorization", "jwt " + newUserToken)
                .send({ ...readResult.body, verified: true });

            expect(updateResult).toBeDefined();
            expect(updateResult.status).toBeGreaterThanOrEqual(200);
            expect(updateResult.status).toBeLessThan(300);
        },
    );

    it("Can make delete request (with admin token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        // Validate the contents were removed
        const count: number = await repo.count({ uid: obj.uid });
        expect(count).toBe(0);
    });

    it("Can make findAll request (with admin token).", async () => {
        const objs: UserMongo[] = await createUserMongos(5);

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
        const obj: UserMongo = await createUserMongo();
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
        const objs: UserMongo[] = await createUserMongos(5);
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
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;
        obj.scopes = ["profile", "profile:contacts"];

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
        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make update property request (with admin token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid + "/scopes";
        obj.scopes = ["profile", "profile:contacts"];

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj.scopes);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expectMatchingFields(result.body, obj);

        // Validate the contents were stored correctly
        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Cannot create a User (with non-admin token).", async () => {
        // UserMongo's class-level ACL grants `.*` no actions at all (unlike Alias/Profile/Secret, which at
        // least grant CREATE) — self-service User creation isn't a thing; accounts come from
        // BaseRegistrationRoute or an admin provisioning them (see the "provisioned by an admin" test above).
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ roles: [], scopes: [], verified: true });

        expect(result.status).toBe(403);
    });

    it("Cannot read another user's record (with user token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Cannot update another user's record (with user token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ ...obj, roles: ["admin"] });

        expect(result.status).toBe(403);

        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing?.roles).not.toContain("admin");
    });

    it("Cannot update a single property of another user's record (with user token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid + "/roles";

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send(["admin"]);

        expect(result.status).toBe(403);
    });

    it("Cannot delete another user's record (with user token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ uid: obj.uid });
        expect(count).toBe(1);
    });

    it("Cannot make count request (with user token).", async () => {
        await createUserMongos(3);

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Truncate (with user token) affects nothing when the caller has no per-record grants.", async () => {
        // Like `doTruncate` elsewhere (see the note in test/routes/mongo/AliasRoute.test.ts), there's no
        // class-level ACL gate here — it defers entirely to per-record grants, and a plain user token with
        // none simply truncates zero records rather than being rejected outright.
        const objs: UserMongo[] = await createUserMongos(3);

        const result = await request(server.getApplication())
            .delete(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const count: number = await repo.count();
        expect(count).toBe(objs.length);
    });

    it("Cannot list Users at all with a user token that has no per-record grants.", async () => {
        // Unlike Alias/Secret/Profile (which override `find()` to self-scope to the caller's own records),
        // User has no such override, so `findAll` falls straight through to CRUDRoute's default class-level
        // LIST check — which UserMongo's ACL denies to `.*` — and 403s outright rather than returning `[]`.
        await createUserMongos(3);

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });
});

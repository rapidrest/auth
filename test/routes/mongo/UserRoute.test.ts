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
        // BaseUserRoute's update/delete/truncate require an elevated token (@RequiresElevation). This
        // file exercises CRUD/ownership/roles behavior, not elevation enforcement itself, so tokens are
        // minted pre-elevated throughout.
        elevated: Date.now(),
    };
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), admin);
    const user: any = {
        uid: uuid.v4(),
        roles: [],
        elevated: Date.now(),
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

    it("Can make create request (with admin token), returning an AuthResult rather than the bare User.", async () => {
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
        // An admin provisioning a User on someone else's behalf doesn't log in as that account, so no
        // token is minted for them (see BaseUserRoute.create()'s trusted-caller branch).
        expect(result.body.token).toBe("");
        expect(result.body.refresh).toBe("");
        expectMatchingFields(result.body.user, obj);

        // Validate the contents were stored correctly
        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Cannot self-register anonymously (no Authorization header) - UserMongo's class-level ACL grants `.*` no CREATE access, same as any non-admin caller.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .send({ roles: [], scopes: [], verified: false });

        expect(result.status).toBe(403);
    });

    it(
        "Does not set a `jwt` `Set-Cookie` header when an already-authenticated (admin) caller creates a User " +
            "on someone else's behalf (regression: the admin's own session must not be silently replaced by a " +
            "session for the account they just provisioned for someone else). The unrelated `rrst.sid` session " +
            "cookie, set by session middleware on every response, is unaffected.",
        async () => {
            const result = await request(server.getApplication())
                .post(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ roles: [], scopes: [], verified: true });

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(typeof result.body.token).toBe("string");
            expect(String(result.headers["set-cookie"])).not.toContain("jwt=");
        },
    );

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
            const newUserUid: string = createResult.body.user.uid;

            const newUserToken = JWTUtils.createTokenSync(config.get("auth"), {
                uid: newUserUid,
                roles: [],
                scopes: [],
                elevated: Date.now(),
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

    it("Can make exists request (with admin token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .head(url)
            .set("Authorization", "jwt " + adminToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.headers["content-length"]).toBe("1");
    });

    it(
        "Cannot make an exists request without authentication (regression: exists() was missing the " +
            "`@Auth([\"jwt\"])` guard applied to every sibling endpoint on this route, so an anonymous " +
            "caller could reach the handler directly instead of being rejected with 401 up front).",
        async () => {
            const obj: UserMongo = await createUserMongo();
            const url = baseUrl + "/" + obj.uid;

            const result = await request(server.getApplication()).head(url);

            expect(result.status).toBe(401);
        },
    );

    it("Cannot check if another user's record exists (with user token).", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .head(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
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

    it("Sets requireMFA on a newly-created User from the request body when the server has no MFA mandate configured (with admin token).", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ roles: [], scopes: [], verified: true, requireMFA: true });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.user.requireMFA).toBe(true);

        const existing: UserMongo | null = await repo.findOne({ uid: result.body.user.uid } as any);
        expect(existing?.requireMFA).toBe(true);
    });

    it("Allows a caller to change their own requireMFA when the server has no MFA mandate configured.", async () => {
        const obj: UserMongo = await createUserMongo({ requireMFA: false, roles: [] });
        const selfToken = JWTUtils.createTokenSync(config.get("auth"), { uid: obj.uid, roles: [], elevated: Date.now() });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + selfToken)
            .send({ ...obj, requireMFA: true });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.requireMFA).toBe(true);

        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing?.requireMFA).toBe(true);
    });

    it(
        "updateProperty is disabled, even for an admin token (regression: CRUDRoute.updateProperty " +
            "calls validateUpdate() with a throwaway wrapper object, not the object that actually gets " +
            "persisted, so the roles-reconciliation guard below cannot protect PUT /:id/roles - it's " +
            "disabled outright instead, the same way BaseAliasRoute disables it).",
        async () => {
            const obj: UserMongo = await createUserMongo();
            const url = baseUrl + "/" + obj.uid + "/scopes";

            const result = await request(server.getApplication())
                .put(url)
                .set("Authorization", "jwt " + adminToken)
                .send(["profile", "profile:contacts"]);

            expect(result.status).toBe(404);

            // Validate nothing was stored
            const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
            expect(existing?.scopes).toEqual(obj.scopes);
        },
    );

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

    it(
        "Cannot self-escalate roles via update on their own record (regression: `roles` had no `@ReadOnly` " +
            "protection and every self-registered user is automatically granted UPDATE on their own record, " +
            "so a plain PUT with an elevated roles array used to persist unmodified - a full account " +
            "takeover, since roles:[\"admin\"] bypasses every ACL check system-wide). The attempted roles " +
            "change is now silently discarded rather than rejecting the whole request.",
        async () => {
            const obj: UserMongo = await createUserMongo({ roles: [] });
            const selfToken = JWTUtils.createTokenSync(config.get("auth"), { uid: obj.uid, roles: [], elevated: Date.now() });
            const url = baseUrl + "/" + obj.uid;

            const result = await request(server.getApplication())
                .put(url)
                .set("Authorization", "jwt " + selfToken)
                .send({ ...obj, roles: ["admin"] });

            expect(result).toBeDefined();
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.roles).not.toContain("admin");

            const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
            expect(existing?.roles).not.toContain("admin");
        },
    );

    it("Allows a caller to update their own record when roles are unchanged (no false-positive block).", async () => {
        const obj: UserMongo = await createUserMongo({ roles: [] });
        const selfToken = JWTUtils.createTokenSync(config.get("auth"), { uid: obj.uid, roles: [], elevated: Date.now() });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + selfToken)
            .send({ ...obj, roles: [], verified: false });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.verified).toBe(false);
    });

    it("Admin can still change another user's roles via update (legitimate role management is preserved).", async () => {
        const obj: UserMongo = await createUserMongo({ roles: [] });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send({ ...obj, roles: ["admin"] });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.roles).toContain("admin");

        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing?.roles).toContain("admin");
    });

    it("Cannot update a single property of another user's record (with user token) - updateProperty is disabled.", async () => {
        const obj: UserMongo = await createUserMongo();
        const url = baseUrl + "/" + obj.uid + "/roles";

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send(["admin"]);

        expect(result.status).toBe(404);

        const existing: UserMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing?.roles).not.toContain("admin");
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

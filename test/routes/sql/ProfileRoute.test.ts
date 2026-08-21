///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
import { agent, request } from "@rapidrest/service-core/test";
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
import { ContactType } from "../../../src/models/types.js";

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

    it(
        "updateProperty is disabled, even for an admin token (regression: CRUDRoute.updateProperty " +
            "calls validateUpdate() with a throwaway wrapper object, not the object that actually gets " +
            "persisted, so the contacts[].verified reconciliation guard cannot protect PUT " +
            "/:id/contacts - it's disabled outright instead, the same way BaseAliasRoute disables it).",
        async () => {
            const obj: ProfileSQL = await createProfileSQL();
            const url = baseUrl + "/" + obj.uid + "/avatar";

            const result = await request(server.getApplication())
                .put(url)
                .set("Authorization", "jwt " + adminToken)
                .send("https://facebook.com/ladeeda");

            expect(result.status).toBe(404);

            // Validate nothing was stored
            const existing: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
            expect(existing?.avatar).toEqual(obj.avatar);
        },
    );

    it("Cannot create a profile for another user (with user token).", async () => {
        const obj = { uid: uuid.v4(), givenName: "Victim" };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send(obj);

        // See the identical note in test/routes/mongo/ProfileRoute.test.ts: the real error here is 403
        // AUTH_PERMISSION_FAILURE from validateCreate(), but CRUDRoute.validateCreateBulk (an upstream bug
        // in @rapidrest/service-core) flattens every create-time validation failure to a generic 400.
        expect(result.status).toBe(400);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(0);
    });

    it("Can update their own profile (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ ...obj, givenName: "Updated" });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.givenName).toBe("Updated");
    });

    it("Cannot update another user's profile (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ ...obj, givenName: "Hijacked" });

        expect(result.status).toBe(403);

        const existing: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.givenName).not.toBe("Hijacked");
    });

    it("Cannot update a single property of their own profile either - updateProperty is disabled entirely.", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid });
        const url = baseUrl + "/" + obj.uid + "/avatar";

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send("https://gravatar.com/updated");

        expect(result.status).toBe(404);
    });

    it("Cannot update a single property of another user's profile (with user token) - updateProperty is disabled.", async () => {
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid + "/avatar";

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send("https://gravatar.com/hijacked");

        expect(result.status).toBe(404);
    });

    it("Can delete their own profile (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(0);
    });

    it("Cannot delete another user's profile (with user token).", async () => {
        const obj: ProfileSQL = await createProfileSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(1);
    });

    it("Cannot make count request (with user token).", async () => {
        await createProfileSQL({ uid: user.uid });

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Can request and complete verification for a newly-added contact on their own profile (with user token, end-to-end).", async () => {
        const obj: ProfileSQL = await createProfileSQL({ uid: user.uid, contacts: [] });
        const client = agent(server.getApplication());
        const debugSpy = vi.spyOn(logger, "debug");
        const contactValue = `${uuid.v4()}@example.com`;

        const updateResult = await client
            .put(`${baseUrl}/${obj.uid}`)
            .set("Authorization", "jwt " + userToken)
            .send({
                ...obj,
                contacts: [{ contact: contactValue, type: ContactType.EMAIL, verified: false }],
            });
        expect(updateResult.status).toBeGreaterThanOrEqual(200);
        expect(updateResult.status).toBeLessThan(300);

        const debugCall = debugSpy.mock.calls
            .map((args) => args[0])
            .find((msg) => typeof msg === "string" && msg.includes("[BaseProfileRoute] verification code for"));
        expect(debugCall).toBeDefined();
        const match = (debugCall as string).match(/verification code for .*: (\S+)$/);
        expect(match).toBeDefined();
        const token = match![1];

        const verifyResult = await client
            .post(`${baseUrl}/${obj.uid}/contacts/verify`)
            .set("Authorization", "jwt " + userToken)
            .send({ contact: contactValue, token });

        expect(verifyResult.status).toBeGreaterThanOrEqual(200);
        expect(verifyResult.status).toBeLessThan(300);
        const verifiedContact = verifyResult.body.contacts.find((c: any) => c.contact === contactValue);
        expect(verifiedContact?.verified).toBe(true);

        const stored: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(stored?.contacts.find((c) => c.contact === contactValue)?.verified).toBe(true);

        debugSpy.mockRestore();
    });

    it("Rejects contact verification with an incorrect code, leaving the contact unverified.", async () => {
        const contactValue = `${uuid.v4()}@example.com`;
        const obj: ProfileSQL = await createProfileSQL({
            uid: user.uid,
            contacts: [{ contact: contactValue, type: ContactType.EMAIL, verified: false }],
        });
        const client = agent(server.getApplication());

        const sendResult = await client
            .get(`${baseUrl}/${obj.uid}/contacts/sendCode?contact=${encodeURIComponent(contactValue)}`)
            .set("Authorization", "jwt " + userToken);
        expect(sendResult.status).toBeGreaterThanOrEqual(200);
        expect(sendResult.status).toBeLessThan(300);

        const verifyResult = await client
            .post(`${baseUrl}/${obj.uid}/contacts/verify`)
            .set("Authorization", "jwt " + userToken)
            .send({ contact: contactValue, token: "000000" });

        expect(verifyResult.status).toBe(400);

        const stored: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(stored?.contacts.find((c) => c.contact === contactValue)?.verified).toBe(false);
    });

    it(
        "Cannot self-verify a contact by PUTting verified:true directly, bypassing OTP entirely " +
            "(regression: update() forwarded obj.contacts to repoUtils.update() unsanitized, so a client " +
            "could fabricate a verified contact with no OTP round-trip at all - and since " +
            "BaseAliasRoute.isVerifiedContact() trusts Profile.contacts blindly, that could then be used " +
            "to auto-verify an Alias for an email/phone the caller doesn't own, pre-empting its real owner).",
        async () => {
            const contactValue = `${uuid.v4()}@example.com`;
            const obj: ProfileSQL = await createProfileSQL({ uid: user.uid, contacts: [] });

            const result = await request(server.getApplication())
                .put(`${baseUrl}/${obj.uid}`)
                .set("Authorization", "jwt " + userToken)
                .send({
                    ...obj,
                    contacts: [{ contact: contactValue, type: ContactType.EMAIL, verified: true }],
                });

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            const contact = result.body.contacts.find((c: any) => c.contact === contactValue);
            expect(contact?.verified).toBe(false);

            const stored: ProfileSQL | null = await repo.findOne({ where: { uid: obj.uid } });
            expect(stored?.contacts.find((c) => c.contact === contactValue)?.verified).toBe(false);
        },
    );

    it("Cannot request a verification code for another user's profile contact (with user token).", async () => {
        const contactValue = `${uuid.v4()}@example.com`;
        const obj: ProfileSQL = await createProfileSQL({
            contacts: [{ contact: contactValue, type: ContactType.EMAIL, verified: false }],
        });

        const result = await request(server.getApplication())
            .get(`${baseUrl}/${obj.uid}/contacts/sendCode?contact=${encodeURIComponent(contactValue)}`)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Cannot verify a contact on another user's profile (with user token).", async () => {
        const contactValue = `${uuid.v4()}@example.com`;
        const obj: ProfileSQL = await createProfileSQL({
            contacts: [{ contact: contactValue, type: ContactType.EMAIL, verified: false }],
        });

        const result = await request(server.getApplication())
            .post(`${baseUrl}/${obj.uid}/contacts/verify`)
            .set("Authorization", "jwt " + userToken)
            .send({ contact: contactValue, token: "000000" });

        expect(result.status).toBe(403);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config";
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
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AliasMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/aliases";
    let repo: MongoRepository<AliasMongo>;
    let aclRepo: MongoRepository<any>;
    const admin: any = {
        uid: uuid.v4(),
        roles: ["admin"],
        // BaseAliasRoute's create()/delete() require an elevated token (@RequiresElevation). This file
        // exercises CRUD/ownership/verification behavior, not elevation enforcement itself (see
        // BaseAuthElevationRoute's own tests for that), so tokens are minted pre-elevated throughout.
        elevated: Date.now(),
    };
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), admin);
    const user: any = {
        uid: uuid.v4(),
        roles: [],
        elevated: Date.now(),
    };
    const userToken = JWTUtils.createTokenSync(config.get("auth"), user);

    const createAliasMongo = async function (data?: any): Promise<AliasMongo> {
        const obj: AliasMongo = new AliasMongo({
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasMongo = await repo.save(obj);

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
            parentUid: "AliasMongo",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createAliasMongos = async function (num: number, data?: any): Promise<AliasMongo[]> {
        const results: AliasMongo[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createAliasMongo(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object. _id is MongoDB's internal driver
    // identifier (an ObjectId on the local object vs. its JSON-serialized hex string over HTTP) and isn't
    // part of the Alias model's public interface.
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
            repo = conn.getMongoRepository("AliasMongo");
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
        const objs: AliasMongo[] = await createAliasMongos(5);

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
        const obj: AliasMongo = new AliasMongo({
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: uuid.v4(),
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
        const existing: AliasMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make delete request (with admin token).", async () => {
        const obj: AliasMongo = await createAliasMongo();
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

    // Regression guard: create()/delete() are @RequiresElevation(60)-gated. A plain, non-elevated access
    // token — the kind issued by a normal login — must not be able to satisfy them; only a token minted by
    // BaseAuthElevationRoute (see AuthElevationRoute.test.ts) can.
    it("Cannot make create request with a non-elevated token.", async () => {
        const nonElevated: any = { uid: uuid.v4(), roles: [] };
        const nonElevatedToken = JWTUtils.createTokenSync(config.get("auth"), nonElevated);
        const obj: Partial<AliasMongo> = {
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: nonElevated.uid,
        };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + nonElevatedToken)
            .send(obj);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ alias: obj.alias });
        expect(count).toBe(0);
    });

    it("Cannot make delete request with a non-elevated token.", async () => {
        const nonElevated: any = { uid: uuid.v4(), roles: [] };
        const nonElevatedToken = JWTUtils.createTokenSync(config.get("auth"), nonElevated);
        const obj: AliasMongo = await createAliasMongo({ userUid: nonElevated.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + nonElevatedToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ uid: obj.uid });
        expect(count).toBe(1);
    });

    it("Can make findAll request (with admin token).", async () => {
        const objs: AliasMongo[] = await createAliasMongos(5);

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
        const obj: AliasMongo = await createAliasMongo();
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

    it("Can retrieve only their own aliases via findAll (with user token).", async () => {
        const ownAliases: AliasMongo[] = await createAliasMongos(3, { userUid: user.uid });
        await createAliasMongos(2);

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveLength(ownAliases.length);
        for (const alias of result.body) {
            expect(alias.userUid).toBe(user.uid);
        }
    });

    it("Can retrieve their own alias by id (with user token).", async () => {
        const obj: AliasMongo = await createAliasMongo({ userUid: user.uid });
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

    it("Cannot retrieve another user's alias by id (with user token).", async () => {
        const obj: AliasMongo = await createAliasMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBe(403);
    });

    it("Can make truncate request (with admin token).", async () => {
        const objs: AliasMongo[] = await createAliasMongos(5);
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

    it("Cannot make update request (with admin token).", async () => {
        const obj: AliasMongo = await createAliasMongo();
        const url = baseUrl + "/" + obj.uid;
        obj.alias = uuid.v4();

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj);

        expect(result).toBeDefined();
        expect(result.status).toBe(404);
    });

    it("Cannot make update property request (with admin token).", async () => {
        const obj: AliasMongo = await createAliasMongo();
        const url = baseUrl + "/" + obj.uid + "/alias";
        obj.alias = uuid.v4();

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send(obj.alias);

        expect(result).toBeDefined();
        expect(result.status).toBe(404);
    });

    it("Can create their own alias (with user token).", async () => {
        const obj: Partial<AliasMongo> = {
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: user.uid,
        };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send(obj);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.userUid).toBe(user.uid);

        const existing: AliasMongo | null = await repo.findOne({ uid: result.body.uid } as any);
        expect(existing).toBeDefined();
    });

    it("Defaults a newly-created alias's userUid to the caller when omitted (with user token).", async () => {
        const obj: Partial<AliasMongo> = { alias: uuid.v4(), type: AliasType.NAME };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send(obj);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.userUid).toBe(user.uid);
    });

    it("Cannot create an alias on behalf of another user (with user token).", async () => {
        const obj: Partial<AliasMongo> = {
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: uuid.v4(),
        };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send(obj);

        // Expected 400, not 403: POST / is validated via CRUDRoute's `validateCreateBulk`, which wraps any
        // rejection from `validateCreate()` (here, the 403 AUTH_PERMISSION_FAILURE this ownership check
        // throws) into a generic `ApiError(ApiErrorMessages.BULK_UPDATE_FAILURE, 400, ...)` — discarding the
        // original status/message entirely. This is an upstream bug in
        // `@rapidrest/service-core`'s `CRUDRoute.validateCreateBulk` (it also misuses the *update*-bulk
        // failure constants for the *create* path), not something this route controls; it flattens every
        // create-time validation failure (permission, uniqueness, etc.) to the same 400 across every model.
        expect(result.status).toBe(400);

        const count: number = await repo.count({ userUid: obj.userUid });
        expect(count).toBe(0);
    });

    it("Cannot create a second 'name' alias with a value that's already taken (with user token).", async () => {
        const existing: AliasMongo = await createAliasMongo({ type: AliasType.NAME });

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ alias: existing.alias, type: AliasType.NAME, userUid: user.uid });

        // See the comment above: the real error here is 403 IDENTIFIER_EXISTS from validateCreate(), but
        // CRUDRoute.validateCreateBulk flattens it to a generic 400.
        expect(result.status).toBe(400);

        const count: number = await repo.count({ alias: existing.alias });
        expect(count).toBe(1);
    });

    // Regression (anti-squatting): a `name` alias is free-form and instantly self-verified, and the
    // uniqueness index on `alias` spans all types — without this restriction, an attacker could squat a
    // victim's future e-mail/phone as a `name` alias before the victim ever registers it, permanently
    // blocking their registration (see the dedicated orphan-prevention test in RegistrationRoute.test.ts).
    it("Cannot create a 'name' alias that resembles an e-mail address (with user token).", async () => {
        const email = `${uuid.v4()}@example.com`;

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ alias: email, type: AliasType.NAME, userUid: user.uid });

        // The real error is 400 INVALID_REQUEST from validateCreate() — already the expected flattened code
        // here (see the CRUDRoute.validateCreateBulk comment above), so nothing extra is being masked.
        expect(result.status).toBe(400);

        const count: number = await repo.count({ alias: email });
        expect(count).toBe(0);
    });

    it("Cannot create a 'name' alias that resembles a phone number (with user token).", async () => {
        const phone = "+14155552671";

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ alias: phone, type: AliasType.NAME, userUid: user.uid });

        expect(result.status).toBe(400);

        const count: number = await repo.count({ alias: phone });
        expect(count).toBe(0);
    });

    it("Can delete their own alias (with user token).", async () => {
        const obj: AliasMongo = await createAliasMongo({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const count: number = await repo.count({ uid: obj.uid });
        expect(count).toBe(0);
    });

    it("Cannot delete another user's alias (with user token).", async () => {
        const obj: AliasMongo = await createAliasMongo();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ uid: obj.uid });
        expect(count).toBe(1);
    });

    it("Cannot make count request (with user token).", async () => {
        await createAliasMongos(3, { userUid: user.uid });

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Truncate (with user token) only removes aliases the caller owns, leaving others' intact.", async () => {
        // `doTruncate` has no class-level ACL gate of its own (unlike `doCreate`) — it defers entirely to
        // `RepoUtils.truncate()`'s per-record ACL enforcement, so a non-admin caller isn't blocked outright;
        // they can only ever affect records they hold a DELETE/TRUNCATE grant on (their own, per the
        // `createAliasMongo` helper's owner grant), same scoping idiom as `find()` above.
        await createAliasMongos(3, { userUid: user.uid });
        const others: AliasMongo[] = await createAliasMongos(2);

        const result = await request(server.getApplication())
            .delete(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const ownCount: number = await repo.count({ userUid: user.uid });
        expect(ownCount).toBe(0);
        for (const other of others) {
            const stillExists: number = await repo.count({ uid: other.uid });
            expect(stillExists).toBe(1);
        }
    });

    it("Can request and complete verification for their own alias (with user token, end-to-end).", async () => {
        const obj: AliasMongo = await createAliasMongo({
            userUid: user.uid,
            type: AliasType.EMAIL,
            alias: `${uuid.v4()}@example.com`,
            verified: false,
        });
        const client = agent(server.getApplication());
        const debugSpy = vi.spyOn(logger, "debug");

        const sendResult = await client
            .get(`${baseUrl}/${obj.uid}/sendCode`)
            .set("Authorization", "jwt " + userToken);
        expect(sendResult.status).toBeGreaterThanOrEqual(200);
        expect(sendResult.status).toBeLessThan(300);

        const debugCall = debugSpy.mock.calls
            .map((args) => args[0])
            .find((msg) => typeof msg === "string" && msg.includes("[BaseAliasRoute] verification code for"));
        expect(debugCall).toBeDefined();
        const match = (debugCall as string).match(/verification code for .*: (\S+)$/);
        expect(match).toBeDefined();
        const token = match![1];

        const verifyResult = await client
            .post(`${baseUrl}/${obj.uid}/verify`)
            .set("Authorization", "jwt " + userToken)
            .send({ token });

        expect(verifyResult.status).toBeGreaterThanOrEqual(200);
        expect(verifyResult.status).toBeLessThan(300);
        expect(verifyResult.body.verified).toBe(true);

        const stored: AliasMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(stored?.verified).toBe(true);

        debugSpy.mockRestore();
    });

    it("Rejects verification with an incorrect code, leaving the alias unverified.", async () => {
        const obj: AliasMongo = await createAliasMongo({
            userUid: user.uid,
            type: AliasType.EMAIL,
            alias: `${uuid.v4()}@example.com`,
            verified: false,
        });
        const client = agent(server.getApplication());

        const sendResult = await client
            .get(`${baseUrl}/${obj.uid}/sendCode`)
            .set("Authorization", "jwt " + userToken);
        expect(sendResult.status).toBeGreaterThanOrEqual(200);
        expect(sendResult.status).toBeLessThan(300);

        const verifyResult = await client
            .post(`${baseUrl}/${obj.uid}/verify`)
            .set("Authorization", "jwt " + userToken)
            .send({ token: "000000" });

        expect(verifyResult.status).toBe(400);

        const stored: AliasMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(stored?.verified).toBe(false);
    });

    it("Cannot request a verification code for another user's alias (with user token).", async () => {
        const obj: AliasMongo = await createAliasMongo({
            type: AliasType.EMAIL,
            alias: `${uuid.v4()}@example.com`,
            verified: false,
        });

        const result = await request(server.getApplication())
            .get(`${baseUrl}/${obj.uid}/sendCode`)
            .set("Authorization", "jwt " + userToken);

        // Passing `user` scopes `repoUtils.findOne()` to the caller's ACL grants (same as `findById`) —
        // for a record that exists but the caller doesn't own, that's a 403, not a silent no-op.
        expect(result.status).toBe(403);

        const stored: AliasMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(stored?.verified).toBe(false);
    });
});

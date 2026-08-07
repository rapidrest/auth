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
    isSqlDataSource,
} from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AliasSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/aliases";
    let repo: Repository<AliasSQL>;
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

    const createAliasSQL = async function (data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasSQL = await repo.save(obj);

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

    const createAliasSQLs = async function (num: number, data?: any): Promise<AliasSQL[]> {
        const results: AliasSQL[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createAliasSQL(data));
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
            repo = conn.getRepository(AliasSQL);
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
        const objs: AliasSQL[] = await createAliasSQLs(5);

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
        const obj: AliasSQL = new AliasSQL({
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
        const existing: AliasSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make delete request (with admin token).", async () => {
        const obj: AliasSQL = await createAliasSQL();
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
        const objs: AliasSQL[] = await createAliasSQLs(5);

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
        const obj: AliasSQL = await createAliasSQL();
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
        const ownAliases: AliasSQL[] = await createAliasSQLs(3, { userUid: user.uid });
        await createAliasSQLs(2);

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
        const obj: AliasSQL = await createAliasSQL({ userUid: user.uid });
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
        const obj: AliasSQL = await createAliasSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBe(403);
    });

    it("Can make truncate request (with admin token).", async () => {
        const objs: AliasSQL[] = await createAliasSQLs(5);
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
        const obj: AliasSQL = await createAliasSQL();
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
        const obj: AliasSQL = await createAliasSQL();
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
        const obj: Partial<AliasSQL> = {
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

        const existing: AliasSQL | null = await repo.findOne({ where: { uid: result.body.uid } });
        expect(existing).toBeDefined();
    });

    it("Defaults a newly-created alias's userUid to the caller when omitted (with user token).", async () => {
        const obj: Partial<AliasSQL> = { alias: uuid.v4(), type: AliasType.NAME };

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send(obj);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.userUid).toBe(user.uid);
    });

    it("Cannot create an alias on behalf of another user (with user token).", async () => {
        const obj: Partial<AliasSQL> = {
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

        const count: number = await repo.count({ where: { userUid: obj.userUid } });
        expect(count).toBe(0);
    });

    it("Cannot create a second 'name' alias with a value that's already taken (with user token).", async () => {
        const existing: AliasSQL = await createAliasSQL({ type: AliasType.NAME });

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ alias: existing.alias, type: AliasType.NAME, userUid: user.uid });

        // See the comment above: the real error here is 403 IDENTIFIER_EXISTS from validateCreate(), but
        // CRUDRoute.validateCreateBulk flattens it to a generic 400.
        expect(result.status).toBe(400);

        const count: number = await repo.count({ where: { alias: existing.alias } });
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

        const count: number = await repo.count({ where: { alias: email } });
        expect(count).toBe(0);
    });

    it("Cannot create a 'name' alias that resembles a phone number (with user token).", async () => {
        const phone = "+14155552671";

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ alias: phone, type: AliasType.NAME, userUid: user.uid });

        expect(result.status).toBe(400);

        const count: number = await repo.count({ where: { alias: phone } });
        expect(count).toBe(0);
    });

    it("Can delete their own alias (with user token).", async () => {
        const obj: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(0);
    });

    it("Cannot delete another user's alias (with user token).", async () => {
        const obj: AliasSQL = await createAliasSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(1);
    });

    it("Cannot make count request (with user token).", async () => {
        await createAliasSQLs(3, { userUid: user.uid });

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Truncate (with user token) only removes aliases the caller owns, leaving others' intact.", async () => {
        await createAliasSQLs(3, { userUid: user.uid });
        const others: AliasSQL[] = await createAliasSQLs(2);

        const result = await request(server.getApplication())
            .delete(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const ownCount: number = await repo.count({ where: { userUid: user.uid } });
        expect(ownCount).toBe(0);
        for (const other of others) {
            const stillExists: number = await repo.count({ where: { uid: other.uid } });
            expect(stillExists).toBe(1);
        }
    });

    it("Can request and complete verification for their own alias (with user token, end-to-end).", async () => {
        const obj: AliasSQL = await createAliasSQL({
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

        const stored: AliasSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(stored?.verified).toBe(true);

        debugSpy.mockRestore();
    });

    it("Rejects verification with an incorrect code, leaving the alias unverified.", async () => {
        const obj: AliasSQL = await createAliasSQL({
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

        const stored: AliasSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(stored?.verified).toBe(false);
    });

    it("Cannot request a verification code for another user's alias (with user token).", async () => {
        const obj: AliasSQL = await createAliasSQL({
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

        const stored: AliasSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(stored?.verified).toBe(false);
    });
});

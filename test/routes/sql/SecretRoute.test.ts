///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// The real cryptographic verification is SimpleWebAuthn's own tested responsibility. Here we mock its two
// registration ceremony functions so we can exercise the full HTTP route (session handling, credential
// storage) end to end without a real authenticator.
vi.mock("@simplewebauthn/server", () => ({
    generateRegistrationOptions: vi.fn(),
    verifyRegistrationResponse: vi.fn(),
}));

import config from "../../config";
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
import { JWTUtils, Logger } from "@rapidrest/core";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { generateSecret as generateTOTPSecret } from "otplib";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretType } from "../../../src/models/types.js";
import { StoredPasskeyCredential, TOTPSecret } from "../../../src/auth/types.js";

const mockGenerateRegistrationOptions = generateRegistrationOptions as any;
const mockVerifyRegistrationResponse = verifyRegistrationResponse as any;

function makeRegistrationBody(credentialId: string, overrides: any = {}) {
    return {
        id: credentialId,
        rawId: credentialId,
        response: {
            clientDataJSON: "clientDataJSON-base64",
            attestationObject: "attestationObject-base64",
        },
        type: "public-key",
        clientExtensionResults: {},
        ...overrides,
    };
}

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:SecretSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/secrets";
    let repo: Repository<SecretSQL>;
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

    const createSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretSQL = await repo.save(obj);

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

    const createSecretSQLs = async function (num: number, data?: any): Promise<SecretSQL[]> {
        const results: SecretSQL[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createSecretSQL(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object. `data` (the hashed secret) is
    // withheld from API responses for security, so it isn't compared either.
    const SERVER_ASSIGNED_FIELDS = ["uid", "dateCreated", "dateModified", "version", "data"];

    const expectMatchingFields = function (actual: any, expected: any): void {
        for (const key in expected) {
            if (SERVER_ASSIGNED_FIELDS.includes(key)) {
                continue;
            }
            // A nullable column left unset (e.g. `hint`) round-trips through SQL as `null`, even though
            // the client-side object never assigned it anything but `undefined`.
            if (expected[key] === undefined && actual[key] === null) {
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
            repo = conn.getRepository(SecretSQL);
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
        mockGenerateRegistrationOptions.mockReset();
        mockVerifyRegistrationResponse.mockReset();
    });

    it("Can make count request (with admin token).", async () => {
        const objs: SecretSQL[] = await createSecretSQLs(5);

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
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("my-password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
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
        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Persists and returns the optional hint field (with admin token).", async () => {
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("my-password"),
            hint: "My favorite pet's name",
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
        });

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send(obj);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.hint).toBe("My favorite pet's name");

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.hint).toBe("My favorite pet's name");
    });

    it("Can make delete request (with admin token).", async () => {
        const obj: SecretSQL = await createSecretSQL();
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
        const objs: SecretSQL[] = await createSecretSQLs(5);

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
        const obj: SecretSQL = await createSecretSQL();
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

    it("Can retrieve only their own secrets via findAll, with data stripped (with user token).", async () => {
        const ownSecrets: SecretSQL[] = await createSecretSQLs(3, { userUid: user.uid });
        await createSecretSQLs(2);

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveLength(ownSecrets.length);
        for (const secret of result.body) {
            expect(secret.userUid).toBe(user.uid);
            expect(secret.data).toBeUndefined();
        }
    });

    it("Can retrieve their own secret by id, with data stripped (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body.data).toBeUndefined();
        expectMatchingFields(result.body, obj);
    });

    it("Cannot retrieve another user's secret by id (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .get(url)
            .set("Authorization", "jwt " + userToken);

        expect(result).toBeDefined();
        expect(result.status).toBe(403);
    });

    it("Can make truncate request (with admin token).", async () => {
        const objs: SecretSQL[] = await createSecretSQLs(5);
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

    it("Cannot begin passkey registration without authentication.", async () => {
        const result = await request(server.getApplication()).get(baseUrl + "/passkey/register");

        expect(result.status).toBe(401);
        expect(mockGenerateRegistrationOptions).not.toHaveBeenCalled();
    });

    it("Can begin passkey registration and receive creation options (with admin token).", async () => {
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });

        const result = await request(server.getApplication())
            .get(baseUrl + "/passkey/register")
            .set("Authorization", "jwt " + adminToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual({ challenge: "test-challenge", rp: { id: "rapidrest" } });
    });

    it("Cannot create a passkey secret without a prior registration ceremony.", async () => {
        const credentialId = uuid.v4();

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({
                data: makeRegistrationBody(credentialId),
                type: SecretType.PASSKEY,
                userUid: uuid.v4(),
            });

        expect(result.status).toBe(400);
        expect(mockVerifyRegistrationResponse).not.toHaveBeenCalled();
    });

    it("Can create a passkey secret with a valid registration response (with admin token).", async () => {
        const credentialId = uuid.v4();
        const userUid = uuid.v4();
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });

        const client = agent(server.getApplication());
        const beginResult = await client
            .get(baseUrl + "/passkey/register")
            .set("Authorization", "jwt " + adminToken);
        expect(beginResult.status).toBeGreaterThanOrEqual(200);
        expect(beginResult.status).toBeLessThan(300);

        mockVerifyRegistrationResponse.mockResolvedValue({
            verified: true,
            registrationInfo: {
                credential: {
                    id: credentialId,
                    publicKey: new Uint8Array([1, 2, 3, 4]),
                    counter: 0,
                    transports: ["internal"],
                },
            },
        });

        const finishResult = await client
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({
                data: makeRegistrationBody(credentialId),
                type: SecretType.PASSKEY,
                userUid,
            });

        expect(finishResult.status).toBeGreaterThanOrEqual(200);
        expect(finishResult.status).toBeLessThan(300);
        expect(finishResult.body).toBeDefined();
        expect(finishResult.body).not.toHaveProperty("data");
        expect(mockVerifyRegistrationResponse).toHaveBeenCalledWith(
            expect.objectContaining({
                expectedChallenge: "test-challenge",
                expectedOrigin: "http://localhost:3000",
                expectedRPID: "rapidrest",
            }),
        );

        // The credential's own `uid` should double as its WebAuthn credential ID, so that a login
        // ceremony (which only has the credential ID to go on) can look the secret up directly.
        const stored: SecretSQL | null = await repo.findOne({ where: { uid: credentialId } });
        expect(stored).toBeDefined();
        expect((stored?.data as StoredPasskeyCredential)?.uid).toBe(userUid);
        expect((stored?.data as StoredPasskeyCredential)?.counter).toBe(0);
    });

    it("Cannot register the same passkey credential twice.", async () => {
        const credentialId = uuid.v4();
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });
        mockVerifyRegistrationResponse.mockResolvedValue({
            verified: true,
            registrationInfo: {
                credential: {
                    id: credentialId,
                    publicKey: new Uint8Array([1, 2, 3, 4]),
                    counter: 0,
                    transports: ["internal"],
                },
            },
        });

        const firstClient = agent(server.getApplication());
        await firstClient.get(baseUrl + "/passkey/register").set("Authorization", "jwt " + adminToken);
        const firstResult = await firstClient
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: makeRegistrationBody(credentialId), type: SecretType.PASSKEY, userUid: uuid.v4() });
        expect(firstResult.status).toBeGreaterThanOrEqual(200);
        expect(firstResult.status).toBeLessThan(300);

        const secondClient = agent(server.getApplication());
        await secondClient.get(baseUrl + "/passkey/register").set("Authorization", "jwt " + adminToken);
        const secondResult = await secondClient
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: makeRegistrationBody(credentialId), type: SecretType.PASSKEY, userUid: uuid.v4() });

        expect(secondResult.status).toBe(400);
    });

    it("Cannot begin FIDO2 registration without authentication.", async () => {
        const result = await request(server.getApplication()).get(baseUrl + "/fido2/register");

        expect(result.status).toBe(401);
        expect(mockGenerateRegistrationOptions).not.toHaveBeenCalled();
    });

    it("Can begin FIDO2 registration and receive creation options (with admin token).", async () => {
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });

        const result = await request(server.getApplication())
            .get(baseUrl + "/fido2/register")
            .set("Authorization", "jwt " + adminToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual({ challenge: "test-challenge", rp: { id: "rapidrest" } });
    });

    it("Cannot create a FIDO2 secret without a prior registration ceremony.", async () => {
        const credentialId = uuid.v4();

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({
                data: makeRegistrationBody(credentialId),
                type: SecretType.FIDO2,
                userUid: uuid.v4(),
            });

        expect(result.status).toBe(400);
        expect(mockVerifyRegistrationResponse).not.toHaveBeenCalled();
    });

    it("Can create a FIDO2 secret with a valid registration response (with admin token).", async () => {
        const credentialId = uuid.v4();
        const userUid = uuid.v4();
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });

        const client = agent(server.getApplication());
        const beginResult = await client
            .get(baseUrl + "/fido2/register")
            .set("Authorization", "jwt " + adminToken);
        expect(beginResult.status).toBeGreaterThanOrEqual(200);
        expect(beginResult.status).toBeLessThan(300);

        mockVerifyRegistrationResponse.mockResolvedValue({
            verified: true,
            registrationInfo: {
                credential: {
                    id: credentialId,
                    publicKey: new Uint8Array([1, 2, 3, 4]),
                    counter: 0,
                    transports: ["usb"],
                },
            },
        });

        const finishResult = await client
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({
                data: makeRegistrationBody(credentialId),
                type: SecretType.FIDO2,
                userUid,
            });

        expect(finishResult.status).toBeGreaterThanOrEqual(200);
        expect(finishResult.status).toBeLessThan(300);
        expect(finishResult.body).toBeDefined();
        expect(finishResult.body).not.toHaveProperty("data");
        expect(mockVerifyRegistrationResponse).toHaveBeenCalledWith(
            expect.objectContaining({
                expectedChallenge: "test-challenge",
                expectedOrigin: "http://localhost:3000",
                expectedRPID: "rapidrest",
            }),
        );

        // The credential's own `uid` should double as its WebAuthn credential ID, so that a login
        // ceremony (which only has the credential ID to go on) can look the secret up directly.
        const stored: SecretSQL | null = await repo.findOne({ where: { uid: credentialId } });
        expect(stored).toBeDefined();
        expect((stored?.data as StoredPasskeyCredential)?.uid).toBe(userUid);
        expect((stored?.data as StoredPasskeyCredential)?.counter).toBe(0);
    });

    it("Cannot register the same FIDO2 credential twice.", async () => {
        const credentialId = uuid.v4();
        mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "test-challenge", rp: { id: "rapidrest" } });
        mockVerifyRegistrationResponse.mockResolvedValue({
            verified: true,
            registrationInfo: {
                credential: {
                    id: credentialId,
                    publicKey: new Uint8Array([1, 2, 3, 4]),
                    counter: 0,
                    transports: ["usb"],
                },
            },
        });

        const firstClient = agent(server.getApplication());
        await firstClient.get(baseUrl + "/fido2/register").set("Authorization", "jwt " + adminToken);
        const firstResult = await firstClient
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: makeRegistrationBody(credentialId), type: SecretType.FIDO2, userUid: uuid.v4() });
        expect(firstResult.status).toBeGreaterThanOrEqual(200);
        expect(firstResult.status).toBeLessThan(300);

        const secondClient = agent(server.getApplication());
        await secondClient.get(baseUrl + "/fido2/register").set("Authorization", "jwt " + adminToken);
        const secondResult = await secondClient
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: makeRegistrationBody(credentialId), type: SecretType.FIDO2, userUid: uuid.v4() });

        expect(secondResult.status).toBe(400);
    });

    it("Can create a TOTP secret with a server-generated secret (with admin token).", async () => {
        const userUid = uuid.v4();

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ type: SecretType.TOTP, userUid });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.data).toBeDefined();
        expect(result.body.data.secret).toEqual(expect.any(String));
        expect(result.body.data.digits).toBe(6);
        expect(result.body.data.period).toBe(30);
        expect(result.body.data.algorithm).toBe("sha1");
        // The `otpauth://` provisioning URI is only computed for the response, never persisted.
        expect(result.body.data.uri).toMatch(/^otpauth:\/\/totp\//);

        const stored: SecretSQL | null = await repo.findOne({ where: { uid: result.body.uid } });
        expect(stored).toBeDefined();
        expect((stored?.data as TOTPSecret).secret).toBe(result.body.data.secret);
        expect(stored?.data.uri).toBeUndefined();
    });

    it("Can create a TOTP secret with a caller-supplied secret (with admin token).", async () => {
        const secret = generateTOTPSecret();

        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: secret, type: SecretType.TOTP, userUid: uuid.v4() });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.data.secret).toBe(secret);
    });

    it("Cannot create a TOTP secret with a secret that is too short.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: "JBSWY3DP", type: SecretType.TOTP, userUid: uuid.v4() });

        expect(result.status).toBe(400);
    });

    it("Cannot create a TOTP secret with a secret that isn't valid Base32.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + adminToken)
            .send({ data: "not-valid-base32-!!!", type: SecretType.TOTP, userUid: uuid.v4() });

        expect(result.status).toBe(400);
    });

    it("Can create their own password secret (with user token).", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ data: "MyValidPassw0rd!", type: SecretType.PASSWORD, userUid: user.uid });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.userUid).toBe(user.uid);
        expect(result.body.data).toBeUndefined();

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: result.body.uid } });
        expect(existing).toBeDefined();
    });

    it("Defaults a newly-created secret's userUid to the caller when omitted (with user token).", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ data: "MyValidPassw0rd!", type: SecretType.PASSWORD });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.userUid).toBe(user.uid);
    });

    it("Cannot create a secret on behalf of another user (with user token).", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .set("Authorization", "jwt " + userToken)
            .send({ data: "MyValidPassw0rd!", type: SecretType.PASSWORD, userUid: uuid.v4() });

        // Unlike Alias/Profile/User (which rely on CRUDRoute's default `create()` and its buggy
        // `validateCreateBulk` wrapper — see the note in test/routes/mongo/AliasRoute.test.ts), Secret
        // defines its own `create()` wired directly to `@Validate("validateCreate")`, so the real 403
        // AUTH_PERMISSION_FAILURE from `enforceOwnership()` propagates unmangled.
        expect(result.status).toBe(403);
    });

    it("Can update their own secret's hint (with user token), with data stripped from the response.", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid, hint: "old hint" });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, hint: "new hint" });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.hint).toBe("new hint");
        expect(result.body.data).toBeUndefined();

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.hint).toBe("new hint");
    });

    it("Rotates a PASSWORD secret's data, hashing the new plaintext value (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, data: "NewValidPassw0rd!", type: SecretType.PASSWORD });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body.data).toBeUndefined();

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.data).not.toBe("NewValidPassw0rd!");
        expect(await argon2.verify(existing!.data, "NewValidPassw0rd!")).toBe(true);
    });

    it("Regression: rotates a PASSWORD secret's data and enforces complexity even when `type` is omitted from the request body (previously fell through validateUpdate()'s switch unvalidated since it keyed off obj.type instead of existing.type).", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, data: "NewValidPassw0rd!" });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.data).not.toBe("NewValidPassw0rd!");
        expect(await argon2.verify(existing!.data, "NewValidPassw0rd!")).toBe(true);
    });

    it("Rejects an updated PASSWORD secret that doesn't meet complexity requirements.", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, data: "weak" });

        expect(result.status).toBe(400);
    });

    it("Cannot modify a FIDO2 secret's data, even when `type` is omitted from the request body.", async () => {
        const obj: SecretSQL = await createSecretSQL({
            userUid: user.uid,
            type: SecretType.FIDO2,
            data: { id: "cred-1", uid: user.uid, publicKey: new Uint8Array([1, 2, 3]), counter: 0 },
        });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, data: { tampered: true } });

        expect(result.status).toBe(400);

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect((existing?.data as StoredPasskeyCredential)?.id).toBe("cred-1");
    });

    it("Cannot change the `type` of a secret.", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, type: SecretType.TOTP });

        expect(result.status).toBe(400);
    });

    it("Cannot re-assign a secret to a different owner.", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, userUid: uuid.v4() });

        expect(result.status).toBe(400);

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.userUid).toBe(user.uid);
    });

    it("Cannot update another user's secret (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + userToken)
            .send({ uid: obj.uid, version: obj.version, hint: "hijacked" });

        expect(result.status).toBe(403);
    });

    it("Regression: a trusted (admin) caller can update another user's secret without the omitted userUid being treated as a re-assignment attempt, and ownership is not silently transferred to the admin.", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid, hint: "old hint" });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send({ uid: obj.uid, version: obj.version, hint: "updated by admin" });

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const existing: SecretSQL | null = await repo.findOne({ where: { uid: obj.uid } });
        expect(existing?.hint).toBe("updated by admin");
        expect(existing?.userUid).toBe(user.uid);
    });

    it("Returns 404 when updating a secret that does not exist.", async () => {
        const url = baseUrl + "/" + uuid.v4();

        const result = await request(server.getApplication())
            .put(url)
            .set("Authorization", "jwt " + adminToken)
            .send({ uid: uuid.v4(), hint: "nope" });

        expect(result.status).toBe(404);
    });

    it("Can delete their own secret (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL({ userUid: user.uid });
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(0);
    });

    it("Cannot delete another user's secret (with user token).", async () => {
        const obj: SecretSQL = await createSecretSQL();
        const url = baseUrl + "/" + obj.uid;

        const result = await request(server.getApplication())
            .delete(url)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);

        const count: number = await repo.count({ where: { uid: obj.uid } });
        expect(count).toBe(1);
    });

    it("Cannot make count request (with user token).", async () => {
        await createSecretSQLs(3, { userUid: user.uid });

        const result = await request(server.getApplication())
            .head(baseUrl)
            .set("Authorization", "jwt " + userToken);

        expect(result.status).toBe(403);
    });

    it("Truncate (with user token) only removes secrets the caller owns, leaving others' intact.", async () => {
        await createSecretSQLs(3, { userUid: user.uid });
        const others: SecretSQL[] = await createSecretSQLs(2);

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
});

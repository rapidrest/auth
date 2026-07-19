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
} from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import * as uuid from "uuid";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretType } from "../../../src/models/types.js";
import { StoredPasskeyCredential } from "../../../src/auth/types.js";

const mockGenerateRegistrationOptions = generateRegistrationOptions as unknown as ReturnType<typeof vi.fn>;
const mockVerifyRegistrationResponse = verifyRegistrationResponse as unknown as ReturnType<typeof vi.fn>;

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

describe("Route:SecretMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/secrets";
    let repo: MongoRepository<SecretMongo>;
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

    const createSecretMongo = async function (data?: any): Promise<SecretMongo> {
        const obj: SecretMongo = new SecretMongo({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretMongo = await repo.save(obj);

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
            parentUid: "SecretMongo",
        };
        await aclRepo.save(acl);

        return result;
    };

    const createSecretMongos = async function (num: number, data?: any): Promise<SecretMongo[]> {
        const results: SecretMongo[] = [];

        for (let i = 0; i < num; i++) {
            results.push(await createSecretMongo(data));
        }

        return results;
    };

    // dateCreated, dateModified, uid and version are assigned by the server and cannot be known by the
    // client ahead of time (e.g. before a create request completes), so they're checked for validity
    // rather than compared for equality against a client-side object. _id is MongoDB's internal driver
    // identifier (an ObjectId on the local object vs. its JSON-serialized hex string over HTTP) and isn't
    // part of the Secret model's public interface.
    const SERVER_ASSIGNED_FIELDS = ["uid", "dateCreated", "dateModified", "version", "_id", "data"];

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
            repo = conn.getMongoRepository("SecretMongo");
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
        mockGenerateRegistrationOptions.mockReset();
        mockVerifyRegistrationResponse.mockReset();
    });

    it("Can make count request (with admin token).", async () => {
        const objs: SecretMongo[] = await createSecretMongos(5);

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
        const obj: SecretMongo = new SecretMongo({
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
        const existing: SecretMongo | null = await repo.findOne({ uid: obj.uid } as any);
        expect(existing).toBeDefined();
        if (existing) {
            expectMatchingFields(existing, obj);
        }
    });

    it("Can make delete request (with admin token).", async () => {
        const obj: SecretMongo = await createSecretMongo();
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
        const objs: SecretMongo[] = await createSecretMongos(5);

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
        const obj: SecretMongo = await createSecretMongo();
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
        const objs: SecretMongo[] = await createSecretMongos(5);
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
        const stored: SecretMongo | null = await repo.findOne({ uid: credentialId } as any);
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
});

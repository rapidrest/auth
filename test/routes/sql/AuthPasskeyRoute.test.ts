///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// The real cryptographic verification is SimpleWebAuthn's own tested responsibility (see
// test/auth/PasskeyStrategy.test.ts for isolated strategy-orchestration tests against a mocked
// SimpleWebAuthn). Here we mock the same two ceremony functions so we can exercise the full HTTP
// route (session handling, credential storage/lookup, counter persistence, JWT issuance) end to end.
vi.mock("@simplewebauthn/server", () => ({
    generateAuthenticationOptions: vi.fn(),
    verifyAuthenticationResponse: vi.fn(),
}));

import config from "../../config.js";
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
import { Logger } from "@rapidrest/core";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { SecretType } from "../../../src/models/types.js";
import { StoredPasskeyCredential } from "../../../src/auth/types.js";

const mockGenerateAuthenticationOptions = generateAuthenticationOptions as unknown as ReturnType<typeof vi.fn>;
const mockVerifyAuthenticationResponse = verifyAuthenticationResponse as unknown as ReturnType<typeof vi.fn>;

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

function makeAssertionBody(credentialId: string, overrides: any = {}) {
    return {
        id: credentialId,
        rawId: credentialId,
        response: {
            clientDataJSON: "clientDataJSON-base64",
            authenticatorData: "authenticatorData-base64",
            signature: "signature-base64",
        },
        type: "public-key",
        clientExtensionResults: {},
        ...overrides,
    };
}

describe("Route:AuthPasskeySQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/passkey";
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

    // The credential's own `uid` doubles as its WebAuthn credential ID here, since
    // `BaseAuthPasskeyRoute.getCredentialById()` looks secrets up by their own `uid`.
    const createPasskeySecretSQL = async function (data?: Partial<StoredPasskeyCredential> & { userUid?: string }) {
        const credentialId: string = data?.id ?? uuid.v4();
        const userUid: string = data?.userUid ?? uuid.v4();
        const credential: StoredPasskeyCredential = {
            id: credentialId,
            uid: userUid,
            publicKey: new Uint8Array([1, 2, 3, 4]),
            counter: 0,
            transports: ["internal"],
            ...data,
        };

        const obj: SecretSQL = new SecretSQL({
            uid: credentialId,
            data: credential,
            type: SecretType.PASSKEY,
            userUid,
        });

        const result: SecretSQL = await secretRepo.save(obj);

        const records: ACLRecord[] = [];

        // Owner has CRUD access
        records.push({
            userOrRoleId: userUid,
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

        mockGenerateAuthenticationOptions.mockReset();
        mockVerifyAuthenticationResponse.mockReset();
    });

    it("Can begin a passkey ceremony and receive challenge options.", async () => {
        mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "test-challenge", rpId: "rapidrest" });

        const result = await request(server.getApplication()).get(baseUrl);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual({ challenge: "test-challenge", rpId: "rapidrest" });
    });

    it("Can complete a passkey ceremony with a valid assertion and authenticate.", async () => {
        const user: UserSQL = await createUserSQL();
        const credentialId = uuid.v4();
        await createPasskeySecretSQL({ id: credentialId, userUid: user.uid, counter: 5 });

        mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "test-challenge", rpId: "rapidrest" });
        const client = agent(server.getApplication());

        const beginResult = await client.get(baseUrl);
        expect(beginResult.status).toBeGreaterThanOrEqual(200);
        expect(beginResult.status).toBeLessThan(300);

        mockVerifyAuthenticationResponse.mockResolvedValue({
            verified: true,
            authenticationInfo: { newCounter: 6, credentialID: credentialId },
        });

        const finishResult = await client.post(baseUrl).send(makeAssertionBody(credentialId));

        expect(finishResult).toBeDefined();
        expect(finishResult.status).toBeGreaterThanOrEqual(200);
        expect(finishResult.status).toBeLessThan(300);
        expect(finishResult.body).toBeDefined();
        expect(finishResult.body).toHaveProperty("token");
        expect(finishResult.body).toHaveProperty("user");
        expect(String(finishResult.headers["set-cookie"])).toContain(`jwt=${finishResult.body.token}`);
        expect(mockVerifyAuthenticationResponse).toHaveBeenCalledWith(
            expect.objectContaining({
                expectedChallenge: "test-challenge",
                expectedOrigin: "http://localhost:3000",
                expectedRPID: "rapidrest",
            }),
        );

        // The signature counter should have been persisted for clone detection on the next login.
        const updated: SecretSQL | null = await secretRepo.findOne({ where: { uid: credentialId } });
        expect((updated?.data as StoredPasskeyCredential).counter).toBe(6);
    });

    it("Cannot authenticate with an unknown credential id.", async () => {
        mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "test-challenge", rpId: "rapidrest" });
        const client = agent(server.getApplication());

        await client.get(baseUrl);

        const result = await client.post(baseUrl).send(makeAssertionBody(uuid.v4()));

        expect(result.status).toBe(401);
        expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    });

    it("Cannot authenticate when SimpleWebAuthn fails to verify the assertion.", async () => {
        const user: UserSQL = await createUserSQL();
        const credentialId = uuid.v4();
        await createPasskeySecretSQL({ id: credentialId, userUid: user.uid, counter: 5 });

        mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "test-challenge", rpId: "rapidrest" });
        const client = agent(server.getApplication());
        await client.get(baseUrl);

        mockVerifyAuthenticationResponse.mockResolvedValue({ verified: false, authenticationInfo: undefined });

        const result = await client.post(baseUrl).send(makeAssertionBody(credentialId));

        expect(result.status).toBe(401);
    });

    it("Cannot authenticate with a malformed assertion response.", async () => {
        const result = await request(server.getApplication())
            .post(baseUrl)
            .send({ id: "some-id", response: { clientDataJSON: "x" } });

        expect(result.status).toBe(401);
        expect(mockVerifyAuthenticationResponse).not.toHaveBeenCalled();
    });
});

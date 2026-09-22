///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "../../config";
import * as argon2 from "argon2";
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
import { Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { SecretType } from "../../../src/models/types.js";
import { normalizePasswordSubmission } from "../../../src/auth/shared.js";
import { PasswordConfig } from "../../../src/auth/types.js";

// An app password is checked with a plain argon2 comparison - never normalizePasswordSubmission() - since
// it's always pasted as literal plaintext by a legacy Basic-auth client. See BaseSecretRoute's own
// app-password tests for the real create-time hashing path this mirrors.
const hashAppPasswordForLogin = async function (plaintext: string): Promise<string> {
    return argon2.hash(plaintext);
};

// Stored hashes must be of the canonical (would-be client-hashed) form of a plaintext password, not
// the plaintext itself — see normalizePasswordSubmission() in shared.ts, which
// BaseSecretRoute.processPasswordSecret() applies to every password created/changed through the real
// route. A raw `argon2.hash(password)` here (the pre-client-hashing-support shape) would no longer be
// verifiable via Basic auth, since login normalizes a plaintext submission the same way before comparing.
const hashPasswordForLogin = async function (password: string, userUid: string): Promise<string> {
    const canonical = await normalizePasswordSubmission(password, userUid, new PasswordConfig());
    return argon2.hash(canonical);
};

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthBasicSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/password";
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

    const createSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const userUid: string = data?.userUid ?? uuid.v4();
        const obj: SecretSQL = new SecretSQL({
            data: await hashPasswordForLogin("password", userUid),
            type: SecretType.PASSWORD,
            userUid,
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

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

    const createAppPasswordSQL = async function (plaintext: string, data?: any): Promise<SecretSQL> {
        const userUid: string = data?.userUid ?? uuid.v4();
        const obj: SecretSQL = new SecretSQL({
            data: await hashAppPasswordForLogin(plaintext),
            hint: "My mail client",
            type: SecretType.APP_PASSWORD,
            userUid,
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

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
    });

    it("Can authenticate with valid user id and password.", async () => {
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
        expect(String(result.headers["set-cookie"])).toContain(`jwt=${result.body.token}`);
    });

    it("Can authenticate with valid user id and password when multiple passwords exist.", async () => {
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({
            userUid: user.uid,
        });
        await createSecretSQL({
            data: await hashPasswordForLogin("another-password", user.uid),
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":another-password").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toBeDefined();
        expect(result.body).toHaveProperty("token");
        expect(result.body).toHaveProperty("user");
    });

    it("Cannot authenticate with invalid user id and password.", async () => {
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":bogus").toString("base64")}`);

        expect(result).toBeDefined();
        expect(result.status).toBe(401);
    });

    it("Cannot authenticate via basic auth when the account requires MFA, even with the correct password.", async () => {
        const user: UserSQL = await createUserSQL({ requireMFA: true });
        await createSecretSQL({
            userUid: user.uid,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

        expect(result.status).toBe(401);
    });

    // End-to-end proof of the dual-mode client-side password hashing support: a capable client
    // computes its own Argon2id hash locally (using the documented salt derivation/parameters — see
    // deriveClientSalt()/CLIENT_ARGON2_PARAMS in shared.ts) and submits that instead of the plaintext.
    it("Can authenticate submitting an already client-side-hashed password instead of plaintext.", async () => {
        const shared = await import("../../../src/auth/shared.js");
        const user: UserSQL = await createUserSQL();
        await createSecretSQL({ userUid: user.uid });
        const clientHash = await argon2.hash("password", {
            salt: shared.deriveClientSalt(user.uid),
            ...shared.CLIENT_ARGON2_PARAMS,
        });

        const result = await request(server.getApplication())
            .get(baseUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":" + clientHash).toString("base64")}`);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveProperty("token");
    });

    describe("app passwords", () => {
        // Core feature proof: an app password authenticates via Basic auth even when requireMFA is set,
        // intentionally bypassing the gate a real password remains subject to (see the test above).
        it("Can authenticate with a valid app password when the account requires MFA.", async () => {
            const user: UserSQL = await createUserSQL({ requireMFA: true });
            await createAppPasswordSQL("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            const result = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body).toHaveProperty("token");
        });

        it("Can authenticate with a valid app password when the account does not require MFA.", async () => {
            const user: UserSQL = await createUserSQL({ requireMFA: false });
            await createAppPasswordSQL("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            const result = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body).toHaveProperty("token");
        });

        it("Cannot authenticate with a wrong app password value - falls through and is rejected.", async () => {
            const user: UserSQL = await createUserSQL({ requireMFA: true });
            await createAppPasswordSQL("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            const result = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":WRONG-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );

            expect(result.status).toBe(401);
        });

        // Regression: a real password must still honor requireMFA exactly as before - app-password support
        // must not accidentally loosen that gate for a genuine password submission.
        it("A real password is still rejected via basic auth when the account requires MFA, unaffected by app-password support.", async () => {
            const user: UserSQL = await createUserSQL({ requireMFA: true });
            await createSecretSQL({ userUid: user.uid });
            await createAppPasswordSQL("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            const result = await request(server.getApplication())
                .get(baseUrl)
                .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);

            expect(result.status).toBe(401);
        });

        it("Can authenticate with any of multiple app passwords on the same account, each independently.", async () => {
            const user: UserSQL = await createUserSQL();
            await createAppPasswordSQL("FIRST-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });
            await createAppPasswordSQL("SECND-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            for (const plaintext of ["FIRST-FGHJK-MNPQR-STVWX-YZ012-34567", "SECND-FGHJK-MNPQR-STVWX-YZ012-34567"]) {
                const result = await request(server.getApplication())
                    .get(baseUrl)
                    .set("Authorization", `basic ${Buffer.from(user.uid + ":" + plaintext).toString("base64")}`);

                expect(result.status).toBeGreaterThanOrEqual(200);
                expect(result.status).toBeLessThan(300);
            }
        });

        // Each app password is independently revocable: deleting one must not affect the others.
        it("Revoking (deleting) one app password does not affect another app password on the same account.", async () => {
            const user: UserSQL = await createUserSQL();
            const revoked: SecretSQL = await createAppPasswordSQL("REVKD-FGHJK-MNPQR-STVWX-YZ012-34567", {
                userUid: user.uid,
            });
            await createAppPasswordSQL("KEPTX-FGHJK-MNPQR-STVWX-YZ012-34567", { userUid: user.uid });

            await secretRepo.delete({ uid: revoked.uid });

            const revokedResult = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":REVKD-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );
            expect(revokedResult.status).toBe(401);

            const keptResult = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":KEPTX-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );
            expect(keptResult.status).toBeGreaterThanOrEqual(200);
            expect(keptResult.status).toBeLessThan(300);
        });

        // lastUsedAt persistence is best-effort/fire-and-forget (see touchSecretLastUsedAt() in shared.ts) -
        // it isn't guaranteed to have landed by the time the HTTP response comes back, so this polls briefly
        // rather than asserting immediately after the request resolves.
        it("Persists lastUsedAt on only the matched app password after a successful login, leaving an unused one untouched.", async () => {
            const user: UserSQL = await createUserSQL();
            const used: SecretSQL = await createAppPasswordSQL("USEDX-FGHJK-MNPQR-STVWX-YZ012-34567", {
                userUid: user.uid,
            });
            const unused: SecretSQL = await createAppPasswordSQL("OTHER-FGHJK-MNPQR-STVWX-YZ012-34567", {
                userUid: user.uid,
            });
            // A never-set nullable column round-trips through TypeORM as `null`, not `undefined` - same as
            // every other optional Secret field (e.g. `hint`) already behaves in this tier.
            expect(used.lastUsedAt).toBeNull();

            const result = await request(server.getApplication())
                .get(baseUrl)
                .set(
                    "Authorization",
                    `basic ${Buffer.from(user.uid + ":USEDX-FGHJK-MNPQR-STVWX-YZ012-34567").toString("base64")}`,
                );
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            let updated: SecretSQL | null = null;
            for (let i = 0; i < 20 && !updated?.lastUsedAt; i++) {
                updated = await secretRepo.findOne({ where: { uid: used.uid } });
                if (!updated?.lastUsedAt) {
                    await new Promise((resolve) => setTimeout(resolve, 25));
                }
            }

            expect(updated?.lastUsedAt).toEqual(expect.any(String));
            const stillUnused: SecretSQL | null = await secretRepo.findOne({ where: { uid: unused.uid } });
            expect(stillUnused?.lastUsedAt).toBeNull();
        });
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import config from "../../config.js";
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
import { Logger, MessagingUtils } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { AliasType, SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AuthElevationSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/auth/elevate";
    const loginUrl = "/sql/auth/password";
    const secretsUrl = "/sql/secrets";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;
    let aliasRepo: Repository<AliasSQL>;
    let messagingUtils: MessagingUtils;

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj: UserSQL = new UserSQL({
            roles: ["admin"],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserSQL = await userRepo.save(obj);

        const records: ACLRecord[] = [
            {
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
            },
        ];

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

    const createPasswordSecretSQL = async function (data?: any): Promise<SecretSQL> {
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid: uuid.v4(),
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);

        const records: ACLRecord[] = [
            {
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
            },
        ];

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

    const createAliasSQL = async function (data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.EMAIL,
            userUid: uuid.v4(),
            verified: true,
            ...data,
        });

        const result: AliasSQL = await aliasRepo.save(obj);

        const records: ACLRecord[] = [
            {
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
            },
        ];

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

    // Logs in via the normal password flow to obtain a real, non-elevated access token — this route
    // requires the caller to already hold one (see BaseAuthElevationRoute's doc comment: this is a
    // "prove you're still you" check, not a full re-authentication).
    const login = async function (client: any, uid: string): Promise<string> {
        const result = await client
            .get(loginUrl)
            .set("Authorization", `basic ${Buffer.from(uid + ":password").toString("base64")}`);
        return result.body.token;
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
            aliasRepo = conn.getRepository(AliasSQL);
        } else {
            throw new Error("Could not find sql connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        await userRepo.clear();
        await secretRepo.clear();
        await aliasRepo.clear();

        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
    });

    it("Cannot list methods or elevate without an existing valid access token.", async () => {
        const result = await request(server.getApplication()).get(baseUrl);
        expect(result.status).toBe(401);
    });

    it("Lists no methods for a user with only a password secret.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client.get(baseUrl).set("Authorization", "jwt " + token);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual([]);
    });

    it(
        "A user with no enrolled secondary method elevates by resubmitting their password (prevents lockout " +
            "of a freshly bootstrapped admin account that has no 2FA configured yet).",
        async () => {
            const user: UserSQL = await createUserSQL();
            await createPasswordSecretSQL({ userUid: user.uid });
            const client = agent(server.getApplication());
            const token = await login(client, user.uid);

            const result = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ password: "password" });

            expect(result).toBeDefined();
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body).toHaveProperty("token");
            expect(result.body.user.uid).toBe(user.uid);
            expect(result.body.user.roles).toContain("admin");
            expect(result.body.user.elevated).toEqual(expect.any(Number));
        },
    );

    it("Cannot elevate by password with an invalid password.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ password: "bogus" });

        expect(result.status).toBe(401);
    });

    it(
        "A user with an enrolled OTP method cannot elevate via password alone — resubmitting the same " +
            "password used to obtain the current token proves nothing new once a real second factor exists.",
        async () => {
            const user: UserSQL = await createUserSQL();
            await createPasswordSecretSQL({ userUid: user.uid });
            await createAliasSQL({ userUid: user.uid });
            const client = agent(server.getApplication());
            const token = await login(client, user.uid);

            const result = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ password: "password" });

            expect(result.status).toBe(400);
        },
    );

    it("Lists the user's enrolled OTP method.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client.get(baseUrl).set("Authorization", "jwt " + token);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toHaveLength(1);
        expect(result.body[0]).toMatchObject({ id: alias.uid, type: "otp" });
    });

    it("Completes a single-factor OTP challenge and mints a usable elevated token.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const begin = await client
            .post(baseUrl)
            .set("Authorization", "jwt " + token)
            .send({ methodId: alias.uid });
        expect(begin.status).toBeGreaterThanOrEqual(200);
        expect(begin.status).toBeLessThan(300);

        const sendEmailMock = messagingUtils.sendEmail as any;
        expect(sendEmailMock).toHaveBeenCalledTimes(1);
        const otp: string = sendEmailMock.mock.calls[0][1].totp;
        expect(otp).toBeDefined();

        const verify = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ token: otp });
        expect(verify.status).toBeGreaterThanOrEqual(200);
        expect(verify.status).toBeLessThan(300);
        expect(verify.body.user.uid).toBe(user.uid);
        expect(verify.body.user.elevated).toEqual(expect.any(Number));

        // The minted token actually satisfies a @RequiresElevation-gated endpoint (BaseSecretRoute.create()).
        const createResult = await request(server.getApplication())
            .post(secretsUrl)
            .set("Authorization", "jwt " + verify.body.token)
            .send({ data: "MyValidPassw0rd!", type: SecretType.PASSWORD, userUid: user.uid });
        expect(createResult.status).toBeGreaterThanOrEqual(200);
        expect(createResult.status).toBeLessThan(300);
    });

    it("Cannot complete an OTP challenge with an invalid token.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        await client.post(baseUrl).set("Authorization", "jwt " + token).send({ methodId: alias.uid });

        const result = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ token: "000000" });
        expect(result.status).toBe(401);
    });

    // Regression/exploit-closing test: an unverified, self-added alias must never be usable to satisfy
    // elevation — see BaseAuthElevationRoute's convertAliasToMethod/getMethod for the fix. Without it, a
    // caller holding only a non-elevated access token could add an attacker-controlled, unverified alias
    // via BaseAliasRoute.create() (no elevation required there) and use it to receive and submit a real
    // OTP code, minting a fully elevated token without proving anything beyond holding that access token.
    it("Excludes an unverified alias from the listed elevation methods.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        await createAliasSQL({ userUid: user.uid, verified: false });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client.get(baseUrl).set("Authorization", "jwt " + token);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual([]);
    });

    it("Cannot begin a challenge using an unverified alias's id, even though the caller owns it.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const unverifiedAlias: AliasSQL = await createAliasSQL({ userUid: user.uid, verified: false });
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client
            .post(baseUrl)
            .set("Authorization", "jwt " + token)
            .send({ methodId: unverifiedAlias.uid });

        expect(result.status).toBe(400);
        expect(messagingUtils.sendEmail).not.toHaveBeenCalled();
    });

    // Regression: a failed elevation attempt used to unconditionally clear the shared `session.userUid`
    // field that BaseAuthRefreshRoute depends on, permanently stranding the caller's still-otherwise-valid
    // refresh token. Elevation state now lives in a dedicated session field instead, so refresh must keep
    // working after a failed attempt.
    it("Does not break the caller's ability to refresh their session after a failed OTP elevation attempt.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const alias: AliasSQL = await createAliasSQL({ userUid: user.uid });
        const client = agent(server.getApplication());
        const loginResult = await client
            .get(loginUrl)
            .set("Authorization", `basic ${Buffer.from(user.uid + ":password").toString("base64")}`);
        const token: string = loginResult.body.token;
        const refresh: string = loginResult.body.refresh;

        await client.post(baseUrl).set("Authorization", "jwt " + token).send({ methodId: alias.uid });
        const failedElevate = await client.post(baseUrl).set("Authorization", "jwt " + token).send({ token: "000000" });
        expect(failedElevate.status).toBe(401);

        const refreshResult = await client.post("/sql/auth/refresh").send({ token: refresh });

        expect(refreshResult.status).toBeGreaterThanOrEqual(200);
        expect(refreshResult.status).toBeLessThan(300);
        expect(refreshResult.body.user.uid).toBe(user.uid);
    });

    it("Cannot begin a challenge for a method id that does not belong to the caller.", async () => {
        const user: UserSQL = await createUserSQL();
        await createPasswordSecretSQL({ userUid: user.uid });
        const otherUsersAlias: AliasSQL = await createAliasSQL();
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client
            .post(baseUrl)
            .set("Authorization", "jwt " + token)
            .send({ methodId: otherUsersAlias.uid });

        expect(result.status).toBe(400);
    });

    it(
        "A plain (non-elevated) access token is rejected by a @RequiresElevation-gated endpoint " +
            "(regression guard for the elevate route's entire reason for existing).",
        async () => {
            const user: UserSQL = await createUserSQL();
            await createPasswordSecretSQL({ userUid: user.uid });
            const client = agent(server.getApplication());
            const token = await login(client, user.uid);

            const createResult = await request(server.getApplication())
                .post(secretsUrl)
                .set("Authorization", "jwt " + token)
                .send({ data: "MyValidPassw0rd!", type: SecretType.PASSWORD, userUid: user.uid });

            expect(createResult.status).toBe(403);
        },
    );
});

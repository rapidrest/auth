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
    isSqlDataSource,
} from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as argon2 from "argon2";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasType, SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AccountSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/account";
    let userRepo: Repository<UserSQL>;
    let aliasRepo: Repository<AliasSQL>;
    let profileRepo: Repository<ProfileSQL>;
    let secretRepo: Repository<SecretSQL>;
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

    const grantOwnerAcl = async function (uid: string, ownerUid: string, parentUid: string): Promise<void> {
        const records: ACLRecord[] = [
            {
                userOrRoleId: ownerUid,
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
            uid,
            dateCreated: new Date(),
            dateModified: new Date(),
            version: 0,
            records,
            parentUid,
        };
        await aclRepo.deleteOne({ uid });
        await aclRepo.save(acl);
    };

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj: UserSQL = new UserSQL({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserSQL = await userRepo.save(obj);
        await grantOwnerAcl(result.uid, result.uid, "UserSQL");

        return result;
    };

    const createAliasSQL = async function (userUid: string, data?: any): Promise<AliasSQL> {
        const obj: AliasSQL = new AliasSQL({
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid,
            verified: true,
            ...data,
        });

        const result: AliasSQL = await aliasRepo.save(obj);
        await grantOwnerAcl(result.uid, userUid, "AliasSQL");

        return result;
    };

    const createProfileSQL = async function (uid: string, data?: any): Promise<ProfileSQL> {
        const obj: ProfileSQL = new ProfileSQL({
            uid,
            avatar: "https://gravatar.com/john.smith",
            givenName: "John",
            familyName: "Smith",
            ...data,
        });

        const result: ProfileSQL = await profileRepo.save(obj);
        await grantOwnerAcl(result.uid, uid, "ProfileSQL");

        return result;
    };

    const createSecretSQL = async function (userUid: string, data?: any): Promise<SecretSQL> {
        const obj: SecretSQL = new SecretSQL({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid,
            ...data,
        });

        const result: SecretSQL = await secretRepo.save(obj);
        await grantOwnerAcl(result.uid, userUid, "SecretSQL");

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
            aliasRepo = conn.getRepository(AliasSQL);
            profileRepo = conn.getRepository(ProfileSQL);
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
        await secretRepo.clear();
        await aliasRepo.clear();
        await profileRepo.clear();
        await userRepo.clear();
    });

    describe("GET /account/:id", () => {
        it("Can retrieve the caller's own account data (with user token, using 'me').", async () => {
            const owner: UserSQL = await createUserSQL({ uid: user.uid });
            const alias: AliasSQL = await createAliasSQL(owner.uid);
            const profile: ProfileSQL = await createProfileSQL(owner.uid);
            const secret: SecretSQL = await createSecretSQL(owner.uid);

            const result = await request(server.getApplication())
                .get(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result).toBeDefined();
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.user.uid).toBe(owner.uid);
            expect(result.body.aliases).toHaveLength(1);
            expect(result.body.aliases[0].uid).toBe(alias.uid);
            expect(result.body.profile.uid).toBe(profile.uid);
            expect(result.body.secrets).toHaveLength(1);
            expect(result.body.secrets[0].uid).toBe(secret.uid);
        });

        it("Can retrieve the caller's own account data (with user token, using their own uid).", async () => {
            const owner: UserSQL = await createUserSQL({ uid: user.uid });

            const result = await request(server.getApplication())
                .get(`${baseUrl}/${owner.uid}`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.user.uid).toBe(owner.uid);
        });

        it("Only aggregates the target user's own aliases/secrets, not another user's.", async () => {
            const owner: UserSQL = await createUserSQL({ uid: user.uid });
            await createAliasSQL(owner.uid);
            await createSecretSQL(owner.uid);
            const otherUser: UserSQL = await createUserSQL();
            await createAliasSQL(otherUser.uid);
            await createSecretSQL(otherUser.uid);

            const result = await request(server.getApplication())
                .get(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.aliases).toHaveLength(1);
            expect(result.body.aliases[0].userUid).toBe(owner.uid);
            expect(result.body.secrets).toHaveLength(1);
            expect(result.body.secrets[0].userUid).toBe(owner.uid);
        });

        it("Cannot retrieve another user's account data (with user token).", async () => {
            const other: UserSQL = await createUserSQL();

            const result = await request(server.getApplication())
                .get(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);
        });

        it("Returns 403 for a nonexistent account (with user token, own uid coincidentally requested).", async () => {
            const result = await request(server.getApplication())
                .get(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);
        });

        it("Can retrieve another user's account data (with a trusted/admin token).", async () => {
            const other: UserSQL = await createUserSQL();
            const alias: AliasSQL = await createAliasSQL(other.uid);
            const profile: ProfileSQL = await createProfileSQL(other.uid);
            const secret: SecretSQL = await createSecretSQL(other.uid);

            const result = await request(server.getApplication())
                .get(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + adminToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.user.uid).toBe(other.uid);
            expect(result.body.aliases[0].uid).toBe(alias.uid);
            expect(result.body.profile.uid).toBe(profile.uid);
            expect(result.body.secrets[0].uid).toBe(secret.uid);
        });

        it("Returns 403 when a trusted/admin token targets a nonexistent account.", async () => {
            const result = await request(server.getApplication())
                .get(`${baseUrl}/${uuid.v4()}`)
                .set("Authorization", "jwt " + adminToken);

            expect(result.status).toBe(403);
        });

        it("Requires authentication.", async () => {
            const result = await request(server.getApplication()).get(`${baseUrl}/me`);

            expect(result.status).toBe(401);
        });
    });

    describe("DELETE /account/:id", () => {
        it("Can delete the caller's own account data (with user token, using 'me').", async () => {
            const owner: UserSQL = await createUserSQL({ uid: user.uid });
            const alias: AliasSQL = await createAliasSQL(owner.uid);
            const profile: ProfileSQL = await createProfileSQL(owner.uid);
            const secret: SecretSQL = await createSecretSQL(owner.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result).toBeDefined();
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ where: { uid: owner.uid } })).toBe(0);
            expect(await aliasRepo.count({ where: { uid: alias.uid } })).toBe(0);
            expect(await profileRepo.count({ where: { uid: profile.uid } })).toBe(0);
            expect(await secretRepo.count({ where: { uid: secret.uid } })).toBe(0);
        });

        it("Does not delete another user's aliases/secrets when deleting the caller's own account.", async () => {
            const owner: UserSQL = await createUserSQL({ uid: user.uid });
            const otherUser: UserSQL = await createUserSQL();
            const otherAlias: AliasSQL = await createAliasSQL(otherUser.uid);
            const otherSecret: SecretSQL = await createSecretSQL(otherUser.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ where: { uid: otherUser.uid } })).toBe(1);
            expect(await aliasRepo.count({ where: { uid: otherAlias.uid } })).toBe(1);
            expect(await secretRepo.count({ where: { uid: otherSecret.uid } })).toBe(1);
        });

        it("Cannot delete another user's account data (with user token).", async () => {
            const other: UserSQL = await createUserSQL();
            const alias: AliasSQL = await createAliasSQL(other.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);

            expect(await userRepo.count({ where: { uid: other.uid } })).toBe(1);
            expect(await aliasRepo.count({ where: { uid: alias.uid } })).toBe(1);
        });

        it("Returns 403 when deleting a nonexistent account (with user token).", async () => {
            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);
        });

        it("Can delete another user's account data (with a trusted/admin token).", async () => {
            const other: UserSQL = await createUserSQL();
            const alias: AliasSQL = await createAliasSQL(other.uid);
            const profile: ProfileSQL = await createProfileSQL(other.uid);
            const secret: SecretSQL = await createSecretSQL(other.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + adminToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ where: { uid: other.uid } })).toBe(0);
            expect(await aliasRepo.count({ where: { uid: alias.uid } })).toBe(0);
            expect(await profileRepo.count({ where: { uid: profile.uid } })).toBe(0);
            expect(await secretRepo.count({ where: { uid: secret.uid } })).toBe(0);
        });

        it("Returns 403 when a trusted/admin token targets a nonexistent account.", async () => {
            const result = await request(server.getApplication())
                .delete(`${baseUrl}/${uuid.v4()}`)
                .set("Authorization", "jwt " + adminToken);

            expect(result.status).toBe(403);
        });

        it("Requires authentication.", async () => {
            const result = await request(server.getApplication()).delete(`${baseUrl}/me`);

            expect(result.status).toBe(401);
        });
    });
});

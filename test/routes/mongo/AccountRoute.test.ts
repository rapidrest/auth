///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
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
import * as argon2 from "argon2";
import * as uuid from "uuid";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { ProfileMongo } from "../../../src/models/mongo/ProfileMongo.js";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasType, SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:AccountMongo Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-mongo", logger, objectFactory });
    const baseUrl = "/mongo/account";
    let userRepo: MongoRepository<UserMongo>;
    let aliasRepo: MongoRepository<AliasMongo>;
    let profileRepo: MongoRepository<ProfileMongo>;
    let secretRepo: MongoRepository<SecretMongo>;
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

    const createUserMongo = async function (data?: any): Promise<UserMongo> {
        const obj: UserMongo = new UserMongo({
            roles: [],
            scopes: [],
            verified: true,
            ...data,
        });

        const result: UserMongo = await userRepo.save(obj);
        await grantOwnerAcl(result.uid, result.uid, "UserMongo");

        return result;
    };

    const createAliasMongo = async function (userUid: string, data?: any): Promise<AliasMongo> {
        const obj: AliasMongo = new AliasMongo({
            alias: uuid.v4(),
            type: AliasType.NAME,
            userUid,
            verified: true,
            ...data,
        });

        const result: AliasMongo = await aliasRepo.save(obj);
        await grantOwnerAcl(result.uid, userUid, "AliasMongo");

        return result;
    };

    const createProfileMongo = async function (uid: string, data?: any): Promise<ProfileMongo> {
        const obj: ProfileMongo = new ProfileMongo({
            uid,
            avatar: "https://gravatar.com/john.smith",
            givenName: "John",
            familyName: "Smith",
            ...data,
        });

        const result: ProfileMongo = await profileRepo.save(obj);
        await grantOwnerAcl(result.uid, uid, "ProfileMongo");

        return result;
    };

    const createSecretMongo = async function (userUid: string, data?: any): Promise<SecretMongo> {
        const obj: SecretMongo = new SecretMongo({
            data: await argon2.hash("password"),
            type: SecretType.PASSWORD,
            userUid,
            ...data,
        });

        const result: SecretMongo = await secretRepo.save(obj);
        await grantOwnerAcl(result.uid, userUid, "SecretMongo");

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
        conn = connMgr?.connections.get("mongo");
        if (conn instanceof MongoConnection) {
            userRepo = conn.getMongoRepository("UserMongo");
            aliasRepo = conn.getMongoRepository("AliasMongo");
            profileRepo = conn.getMongoRepository("ProfileMongo");
            secretRepo = conn.getMongoRepository("SecretMongo");
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
        for (const repo of [userRepo, aliasRepo, profileRepo, secretRepo]) {
            try {
                await repo.clear();
            } catch (err: any) {
                // The error "ns not found" occurs when the collection doesn't exist yet. We can ignore this error.
                if (err.message !== "ns not found") {
                    throw err;
                }
            }
        }
    });

    describe("GET /account/:id", () => {
        it("Can retrieve the caller's own account data (with user token, using 'me').", async () => {
            const owner: UserMongo = await createUserMongo({ uid: user.uid });
            const alias: AliasMongo = await createAliasMongo(owner.uid);
            const profile: ProfileMongo = await createProfileMongo(owner.uid);
            const secret: SecretMongo = await createSecretMongo(owner.uid);

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
            const owner: UserMongo = await createUserMongo({ uid: user.uid });

            const result = await request(server.getApplication())
                .get(`${baseUrl}/${owner.uid}`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(result.body.user.uid).toBe(owner.uid);
        });

        it("Only aggregates the target user's own aliases/secrets, not another user's.", async () => {
            const owner: UserMongo = await createUserMongo({ uid: user.uid });
            await createAliasMongo(owner.uid);
            await createSecretMongo(owner.uid);
            const otherUser: UserMongo = await createUserMongo();
            await createAliasMongo(otherUser.uid);
            await createSecretMongo(otherUser.uid);

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
            const other: UserMongo = await createUserMongo();

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
            const other: UserMongo = await createUserMongo();
            const alias: AliasMongo = await createAliasMongo(other.uid);
            const profile: ProfileMongo = await createProfileMongo(other.uid);
            const secret: SecretMongo = await createSecretMongo(other.uid);

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
            const owner: UserMongo = await createUserMongo({ uid: user.uid });
            const alias: AliasMongo = await createAliasMongo(owner.uid);
            const profile: ProfileMongo = await createProfileMongo(owner.uid);
            const secret: SecretMongo = await createSecretMongo(owner.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result).toBeDefined();
            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ uid: owner.uid })).toBe(0);
            expect(await aliasRepo.count({ uid: alias.uid })).toBe(0);
            expect(await profileRepo.count({ uid: profile.uid })).toBe(0);
            expect(await secretRepo.count({ uid: secret.uid })).toBe(0);
        });

        it("Does not delete another user's aliases/secrets when deleting the caller's own account.", async () => {
            const owner: UserMongo = await createUserMongo({ uid: user.uid });
            const otherUser: UserMongo = await createUserMongo();
            const otherAlias: AliasMongo = await createAliasMongo(otherUser.uid);
            const otherSecret: SecretMongo = await createSecretMongo(otherUser.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ uid: otherUser.uid })).toBe(1);
            expect(await aliasRepo.count({ uid: otherAlias.uid })).toBe(1);
            expect(await secretRepo.count({ uid: otherSecret.uid })).toBe(1);
        });

        it("Cannot delete another user's account data (with user token).", async () => {
            const other: UserMongo = await createUserMongo();
            const alias: AliasMongo = await createAliasMongo(other.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);

            expect(await userRepo.count({ uid: other.uid })).toBe(1);
            expect(await aliasRepo.count({ uid: alias.uid })).toBe(1);
        });

        it("Returns 403 when deleting a nonexistent account (with user token).", async () => {
            const result = await request(server.getApplication())
                .delete(`${baseUrl}/me`)
                .set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(403);
        });

        it("Can delete another user's account data (with a trusted/admin token).", async () => {
            const other: UserMongo = await createUserMongo();
            const alias: AliasMongo = await createAliasMongo(other.uid);
            const profile: ProfileMongo = await createProfileMongo(other.uid);
            const secret: SecretMongo = await createSecretMongo(other.uid);

            const result = await request(server.getApplication())
                .delete(`${baseUrl}/${other.uid}`)
                .set("Authorization", "jwt " + adminToken);

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);

            expect(await userRepo.count({ uid: other.uid })).toBe(0);
            expect(await aliasRepo.count({ uid: alias.uid })).toBe(0);
            expect(await profileRepo.count({ uid: profile.uid })).toBe(0);
            expect(await secretRepo.count({ uid: secret.uid })).toBe(0);
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

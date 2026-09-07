///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Real-database integration coverage for BaseImpersonationRoute: exercises the actual cookie-based
// login -> elevate -> impersonate -> stop flow against a real running server, since the isolated unit
// tests in test/routes/BaseImpersonationRoute.test.ts mock tokenUtils/userRepo entirely and never prove
// that a real elevated session cookie is genuinely stashed/restored, or that a non-trusted caller is
// actually rejected by the framework's own @RequiresTrustedRole() middleware.
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
import { Repository } from "typeorm";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { SecretType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:ImpersonationSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const loginUrl = "/sql/auth/password";
    const elevateUrl = "/sql/auth/elevate";
    const impersonateUrl = "/sql/admin/impersonate";
    const stopUrl = "/sql/admin/impersonate/stop";
    let userRepo: Repository<UserSQL>;
    let aclRepo: MongoRepository<any>;
    let secretRepo: Repository<SecretSQL>;

    const withOwnerACL = async function (uid: string, parentUid: string, ownerId: string): Promise<void> {
        const records: ACLRecord[] = [
            {
                userOrRoleId: ownerId,
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
        await aclRepo.save({ uid, dateCreated: new Date(), dateModified: new Date(), version: 0, records, parentUid });
    };

    const createUserSQL = async function (data?: any): Promise<UserSQL> {
        const obj = new UserSQL({ roles: [], scopes: [], verified: true, ...data });
        const result = await userRepo.save(obj);
        await withOwnerACL(result.uid, "UserSQL", result.uid);
        return result;
    };

    const createSecretSQL = async function (userUid: string): Promise<SecretSQL> {
        const obj = new SecretSQL({ data: await argon2.hash("password"), type: SecretType.PASSWORD, userUid });
        const result = await secretRepo.save(obj);
        await withOwnerACL(result.uid, "SecretSQL", userUid);
        return result;
    };

    // Logs in via the normal password flow. The resulting token/cookie never carries trusted roles -
    // only an elevation step does (see TokenUtils.resolveTokenUser()) - so this alone is never
    // sufficient to pass @RequiresTrustedRole().
    const login = async function (client: any, uid: string): Promise<string> {
        const result = await client
            .get(loginUrl)
            .set("Authorization", `basic ${Buffer.from(uid + ":password").toString("base64")}`);
        return result.body.token;
    };

    // Elevates by resubmitting the password (no 2FA enrolled) - the same shortcut
    // test/routes/sql/AuthElevationRoute.test.ts uses. Overwrites the agent's `jwt` cookie with a new,
    // elevated one that carries trusted roles.
    const elevate = async function (client: any, token: string): Promise<string> {
        const result = await client.post(elevateUrl).set("Authorization", "jwt " + token).send({ password: "password" });
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

    it("Cannot impersonate without authentication.", async () => {
        const result = await request(server.getApplication())
            .post(impersonateUrl)
            .send({ userUid: "does-not-matter" });

        expect(result.status).toBe(401);
    });

    it("Cannot impersonate without a trusted role, even when authenticated.", async () => {
        const user = await createUserSQL();
        await createSecretSQL(user.uid);
        const target = await createUserSQL();
        const client = agent(server.getApplication());
        const token = await login(client, user.uid);

        const result = await client.post(impersonateUrl).set("Authorization", "jwt " + token).send({ userUid: target.uid });

        expect(result.status).toBe(403);
    });

    it("Fails with a 400 when userUid is missing from the body.", async () => {
        const admin = await createUserSQL({ roles: ["admin"] });
        await createSecretSQL(admin.uid);
        const client = agent(server.getApplication());
        const token = await login(client, admin.uid);
        const elevatedToken = await elevate(client, token);

        const result = await client.post(impersonateUrl).set("Authorization", "jwt " + elevatedToken).send({});

        expect(result.status).toBe(400);
    });

    it("Fails with a 404 when the target user does not exist.", async () => {
        const admin = await createUserSQL({ roles: ["admin"] });
        await createSecretSQL(admin.uid);
        const client = agent(server.getApplication());
        const token = await login(client, admin.uid);
        const elevatedToken = await elevate(client, token);

        const result = await client
            .post(impersonateUrl)
            .set("Authorization", "jwt " + elevatedToken)
            .send({ userUid: "does-not-exist" });

        expect(result.status).toBe(404);
    });

    it("Returns restored:false and sets no cookies when there is no active impersonation to stop.", async () => {
        const admin = await createUserSQL({ roles: ["admin"] });
        await createSecretSQL(admin.uid);
        const client = agent(server.getApplication());
        const token = await login(client, admin.uid);
        const elevatedToken = await elevate(client, token);

        const result = await client.get(stopUrl).set("Authorization", "jwt " + elevatedToken);

        expect(result.status).toBeGreaterThanOrEqual(200);
        expect(result.status).toBeLessThan(300);
        expect(result.body).toEqual({ restored: false });
        expect(result.headers["set-cookie"]).toBeUndefined();
    });

    it(
        "An elevated, trusted-role caller can impersonate another user via the jwt cookie alone, receiving " +
            "that user's own token with no refresh token, and can later restore their original session.",
        async () => {
            const admin = await createUserSQL({ roles: ["admin"] });
            await createSecretSQL(admin.uid);
            const target = await createUserSQL();
            const client = agent(server.getApplication());
            const loginToken = await login(client, admin.uid);
            const elevatedToken = await elevate(client, loginToken);

            // Purely cookie-based: no Authorization header at all, proving the whole flow works the way a
            // real browser session (no JS-visible token) would use it.
            const impersonateResult = await client.post(impersonateUrl).send({ userUid: target.uid });

            expect(impersonateResult.status).toBeGreaterThanOrEqual(200);
            expect(impersonateResult.status).toBeLessThan(300);
            expect(impersonateResult.body.refresh).toBe("");
            expect(impersonateResult.body.user.uid).toBe(target.uid);
            expect(String(impersonateResult.headers["set-cookie"])).toContain(`jwt_impersonator=${elevatedToken}`);
            expect(String(impersonateResult.headers["set-cookie"])).toContain(`jwt=${impersonateResult.body.token}`);

            const impersonatedClaims: any = await JWTUtils.decodeToken(config.get("auth"), impersonateResult.body.token);
            expect(impersonatedClaims.profile.uid).toBe(target.uid);
            // The impersonated session never inherits the caller's own trusted role.
            expect(impersonatedClaims.profile.roles).not.toContain("admin");

            const stopResult = await client.get(stopUrl);

            expect(stopResult.status).toBeGreaterThanOrEqual(200);
            expect(stopResult.status).toBeLessThan(300);
            expect(stopResult.body).toEqual({ restored: true });
            expect(String(stopResult.headers["set-cookie"])).toContain(`jwt=${elevatedToken}`);
            expect(String(stopResult.headers["set-cookie"])).toContain("jwt_impersonator=;");

            // A second stop call, now that the stash has been cleared, is a no-op.
            const secondStopResult = await client.get(stopUrl).set("Authorization", "jwt " + elevatedToken);
            expect(secondStopResult.body).toEqual({ restored: false });
        },
    );
});

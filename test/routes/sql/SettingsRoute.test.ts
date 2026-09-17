///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// End-to-end HTTP coverage for the new dedicated `/settings` route (`BaseSettingsRouteSQL`), mounted at
// `/sql/settings` by `test/server-sql/routes/SettingsRoute.ts` — separate from (and replacing, for
// registration/MFA policy) the site-branding settings previously exercised under `/settings` by the
// consuming app. See `BaseSettingsRoute.test.ts` for isolated unit coverage of its own logic.
import config from "../../config.js";
import { request } from "@rapidrest/service-core/test";
import { Server, ObjectFactory, ConnectionManager, isSqlDataSource } from "@rapidrest/service-core";
import { JWTUtils, Logger } from "@rapidrest/core";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { MongoMemoryServer } from "mongodb-memory-server";
import { SystemSettingsSQL } from "../../../src/models/sql/SystemSettingsSQL.js";
import { SYSTEM_SETTINGS_UID } from "../../../src/routes/SystemSettingsUtils.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Route:SettingsSQL Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const baseUrl = "/sql/settings";
    let settingsRepo: Repository<SystemSettingsSQL>;

    // Tokens are minted pre-elevated directly (as `UserRoute.test.ts` does) since this file exercises the
    // route's own settings/scope logic, not the elevation flow itself.
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), {
        uid: uuid.v4(),
        roles: ["admin"],
        elevated: Date.now(),
    });
    const userToken = JWTUtils.createTokenSync(config.get("auth"), { uid: uuid.v4(), roles: [], scopes: [] });
    const systemScopedToken = JWTUtils.createTokenSync(config.get("auth"), {
        uid: uuid.v4(),
        roles: [],
        scopes: ["system"],
    });

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            settingsRepo = conn.getRepository(SystemSettingsSQL);
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
        await settingsRepo.clear();
    });

    describe("GET /", () => {
        it("Is public, creates the default row on first access, and never includes requireMFA for an anonymous caller.", async () => {
            const result = await request(server.getApplication()).get(baseUrl);

            expect(result.status).toBe(200);
            expect(result.body.allowRegistration).toBe(true);
            expect("requireMFA" in result.body).toBe(false);
            expect(await settingsRepo.count()).toBe(1);
        });

        it("Still omits requireMFA for an authenticated, non-trusted, non-scoped caller.", async () => {
            const result = await request(server.getApplication()).get(baseUrl).set("Authorization", "jwt " + userToken);

            expect(result.status).toBe(200);
            expect("requireMFA" in result.body).toBe(false);
        });

        it("Includes requireMFA for a trusted-role caller.", async () => {
            const result = await request(server.getApplication()).get(baseUrl).set("Authorization", "jwt " + adminToken);

            expect(result.status).toBe(200);
            expect(result.body.requireMFA).toBe(false);
        });

        it("Includes requireMFA for a caller whose token carries the 'system' scope, even without a trusted role.", async () => {
            const result = await request(server.getApplication())
                .get(baseUrl)
                .set("Authorization", "jwt " + systemScopedToken);

            expect(result.status).toBe(200);
            expect(result.body.requireMFA).toBe(false);
        });

        it("Reflects a value persisted by a prior PUT.", async () => {
            await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: false });

            const result = await request(server.getApplication()).get(baseUrl);

            expect(result.body.allowRegistration).toBe(false);
        });
    });

    describe("PUT /", () => {
        it("Rejects an anonymous caller.", async () => {
            const result = await request(server.getApplication()).put(baseUrl).send({ allowRegistration: false });

            expect(result.status).toBe(401);
        });

        it("Rejects an authenticated caller without the trusted role.", async () => {
            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + userToken)
                .send({ allowRegistration: false });

            expect(result.status).toBe(403);
        });

        it("Rejects even a caller whose token carries the 'system' scope but no trusted role — reading and writing are gated independently.", async () => {
            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + systemScopedToken)
                .send({ allowRegistration: false });

            expect(result.status).toBe(403);
        });

        it("Lets a trusted admin update allowRegistration and requireMFA together.", async () => {
            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: false, requireMFA: true });

            expect(result.status).toBe(200);
            expect(result.body).toMatchObject({ allowRegistration: false, requireMFA: true });

            const stored = await settingsRepo.findOne({ where: { uid: SYSTEM_SETTINGS_UID } });
            expect(stored).toMatchObject({ allowRegistration: false, requireMFA: true });
        });

        it("Leaves a field untouched when omitted from the body.", async () => {
            await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: false, requireMFA: true });

            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: true });

            expect(result.status).toBe(200);
            expect(result.body).toMatchObject({ allowRegistration: true, requireMFA: true });
        });

        it("Rejects null for allowRegistration, leaving the stored value unchanged.", async () => {
            await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: false });

            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ allowRegistration: null });

            expect(result.status).toBe(400);
            const stored = await settingsRepo.findOne({ where: { uid: SYSTEM_SETTINGS_UID } });
            expect(stored?.allowRegistration).toBe(false);
        });

        it("Rejects a non-boolean requireMFA.", async () => {
            const result = await request(server.getApplication())
                .put(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ requireMFA: "yes" });

            expect(result.status).toBe(400);
        });
    });
});

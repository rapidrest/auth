///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// End-to-end coverage of closing new account registration at runtime (`SystemSettings.allowRegistration`)
// across every path that can create a `User`: direct creation (`BaseUserRoute`), the OTP registration
// flow (`BaseRegistrationRoute`) and a first-time OIDC sign-in (`BaseAuthOIDCRoute`). The OIDC provider
// is mocked via axios, the same way `AuthOIDCRoute.test.ts` does.
vi.mock("axios", async (importOriginal) => {
    const actual = await importOriginal<typeof import("axios")>();
    return {
        ...actual,
        default: {
            ...actual.default,
            get: vi.fn(),
            post: vi.fn(),
        },
    };
});

import config from "../../config.js";
import { agent, request } from "@rapidrest/service-core/test";
import { Server, ObjectFactory, ConnectionManager, isSqlDataSource } from "@rapidrest/service-core";
import { JWTUtils, Logger, MessagingUtils } from "@rapidrest/core";
import axios from "axios";
import * as uuid from "uuid";
import { Repository } from "typeorm";
import { MongoMemoryServer } from "mongodb-memory-server";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { SystemSettingsSQL } from "../../../src/models/sql/SystemSettingsSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { AliasType } from "../../../src/models/types.js";
import { SYSTEM_SETTINGS_UID, SystemSettingsUtils } from "../../../src/routes/SystemSettingsUtils.js";

const mockPost = axios.post as any;
const mockGet = axios.get as any;

const mongod: MongoMemoryServer = new MongoMemoryServer({
    instance: {
        port: 9999,
        dbName: "rrst-test",
    },
});

describe("Registration Disabled (SQL) Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    const adminToken = JWTUtils.createTokenSync(config.get("auth"), { uid: uuid.v4(), roles: ["admin"] });
    const userToken = JWTUtils.createTokenSync(config.get("auth"), { uid: uuid.v4(), roles: [] });
    let aliasRepo: Repository<AliasSQL>;
    let profileRepo: Repository<ProfileSQL>;
    let settingsRepo: Repository<SystemSettingsSQL>;
    let userRepo: Repository<UserSQL>;
    let messagingUtils: MessagingUtils;
    let settings: SystemSettingsUtils<SystemSettingsSQL>;

    beforeAll(async () => {
        await mongod.start();
        await server.start();

        const connMgr: ConnectionManager | undefined = objectFactory.getInstance(ConnectionManager);
        const conn: any = connMgr?.connections.get("sql");
        if (isSqlDataSource(conn)) {
            aliasRepo = conn.getRepository(AliasSQL);
            profileRepo = conn.getRepository(ProfileSQL);
            settingsRepo = conn.getRepository(SystemSettingsSQL);
            userRepo = conn.getRepository(UserSQL);
        } else {
            throw new Error("Could not find sql connection");
        }

        messagingUtils = objectFactory.getInstance(MessagingUtils) as MessagingUtils;
        // Every route shares the one instance keyed by the settings class, which is what lets a change made
        // through it (e.g. by an admin console) take effect for all of them without a restart.
        settings = objectFactory.getInstance(`${SystemSettingsUtils.name}:${SystemSettingsSQL.name}`);
        expect(settings).toBeInstanceOf(SystemSettingsUtils);
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        await aliasRepo.clear();
        await profileRepo.clear();
        await settingsRepo.clear();
        await userRepo.clear();

        mockPost.mockReset();
        mockGet.mockReset();
        vi.spyOn(messagingUtils, "sendEmail").mockResolvedValue(undefined as any);
        vi.spyOn(messagingUtils, "sendSMS").mockResolvedValue(undefined as any);

        await settings.update({ allowRegistration: false });
    });

    describe("SystemSettings", () => {
        it("Seeds the stored settings from @Config on first read.", async () => {
            await settingsRepo.clear();

            const effective = await settings.get();

            expect(effective.allowRegistration).toBe(config.get("auth:allowRegistration") ?? true);
            const stored = await settingsRepo.findOne({ where: { uid: SYSTEM_SETTINGS_UID } });
            expect(stored?.allowRegistration).toBe(effective.allowRegistration);
        });

        it("Keeps the stored value over @Config once seeded.", async () => {
            const stored = await settingsRepo.findOne({ where: { uid: SYSTEM_SETTINGS_UID } });
            expect(stored?.allowRegistration).toBe(false);
            expect((await settings.get()).allowRegistration).toBe(false);
        });

        // Unlike the branding settings this replaced, SystemSettings has no "revert to @Config" sentinel: once
        // seeded, the stored value is always authoritative, so `null` is rejected outright rather than clearing it.
        it("Rejects clearing the stored value with null, leaving it unchanged.", async () => {
            await expect(settings.update({ allowRegistration: null as any })).rejects.toMatchObject({ status: 400 });

            const stored = await settingsRepo.findOne({ where: { uid: SYSTEM_SETTINGS_UID } });
            expect(stored?.allowRegistration).toBe(false);
        });
    });

    describe("BaseUserRoute", () => {
        const baseUrl = "/sql/users";

        it("Rejects an anonymous create and creates no user.", async () => {
            const result = await request(server.getApplication())
                .post(baseUrl)
                .send({ roles: [], scopes: [], verified: false });

            expect(result.status).toBe(403);
            expect(await userRepo.count()).toBe(0);
        });

        it("Rejects a create by an authenticated non-admin and creates no user.", async () => {
            const result = await request(server.getApplication())
                .post(baseUrl)
                .set("Authorization", "jwt " + userToken)
                .send({ roles: [], scopes: [], verified: false });

            expect(result.status).toBe(403);
            expect(await userRepo.count()).toBe(0);
        });

        it("Still allows an admin to create a user.", async () => {
            const result = await request(server.getApplication())
                .post(baseUrl)
                .set("Authorization", "jwt " + adminToken)
                .send({ roles: [], scopes: [], verified: true });

            expect(result.status).toBeGreaterThanOrEqual(200);
            expect(result.status).toBeLessThan(300);
            expect(await userRepo.count()).toBe(1);
        });
    });

    describe("BaseRegistrationRoute", () => {
        const baseUrl = "/sql/registration";

        it.each([{ email: "closed@example.com" }, { phone: "+14155552671" }])(
            "Rejects starting registration for %o without sending a code.",
            async (body) => {
                const result = await request(server.getApplication()).post(`${baseUrl}/start`).send(body);

                expect(result.status).toBe(403);
                expect(messagingUtils.sendEmail).not.toHaveBeenCalled();
                expect(messagingUtils.sendSMS).not.toHaveBeenCalled();
            },
        );

        it("Rejects completing a registration that was started before registration was closed.", async () => {
            const client = agent(server.getApplication());
            const email = `${uuid.v4()}@example.com`;

            await settings.update({ allowRegistration: true });
            const startResult = await client.post(`${baseUrl}/start`).send({ email });
            expect(startResult.status).toBe(200);
            const token: string = (messagingUtils.sendEmail as any).mock.calls[0][1].totp;

            await settings.update({ allowRegistration: false });
            const verifyResult = await client.post(`${baseUrl}/verify`).send({ email, token });

            expect(verifyResult.status).toBe(403);
            expect(await userRepo.count()).toBe(0);
            expect(await aliasRepo.count()).toBe(0);

            // Re-opening registration at runtime lets the same, still unused, code complete it.
            await settings.update({ allowRegistration: true });
            const retryResult = await client.post(`${baseUrl}/verify`).send({ email, token });

            expect(retryResult.status).toBe(200);
            expect(await userRepo.count()).toBe(1);
        });
    });

    describe("BaseAuthOIDCRoute", () => {
        const baseUrl = "/sql/auth/oidc";

        const signIn = async function (profile: any) {
            const client = agent(server.getApplication());
            const beginResult = await client.get(baseUrl);
            const state = new URL(beginResult.headers["location"]).searchParams.get("state") as string;
            mockPost.mockResolvedValue({
                status: 200,
                data: { access_token: "test-access-token", token_type: "Bearer", expires_in: 3600 },
            });
            mockGet.mockResolvedValue({ status: 200, data: profile });
            return await client.get(`${baseUrl}?code=auth-code&state=${encodeURIComponent(state)}`);
        };

        // The route rejects with a 403, but `AuthMiddleware` reports any strategy failure as a 401.
        it("Rejects a first-time sign-in and provisions no user, profile or alias.", async () => {
            const result = await signIn({ id: "ext-new", username: "new", email: "new@example.com", verified: true });

            expect(result.status).toBe(401);
            expect(await userRepo.count()).toBe(0);
            expect(await profileRepo.count()).toBe(0);
            expect(await aliasRepo.count()).toBe(0);
        });

        it("Still signs in a returning user.", async () => {
            const existing = await userRepo.save(new UserSQL({ roles: [], scopes: [], verified: true }));
            await aliasRepo.save(
                new AliasSQL({
                    alias: "test:ext-returning",
                    type: AliasType.OAUTH,
                    userUid: existing.uid,
                    verified: true,
                }),
            );

            const result = await signIn({ id: "ext-returning", username: "returning" });

            expect(result.status).toBe(200);
            expect(result.body.user.uid).toBe(existing.uid);
            expect(await userRepo.count()).toBe(1);
        });

        it("Provisions the user once registration is re-opened at runtime.", async () => {
            const profile = { id: "ext-later", username: "later", email: "later@example.com", verified: true };
            expect((await signIn(profile)).status).toBe(401);

            await settings.update({ allowRegistration: true });
            const result = await signIn(profile);

            expect(result.status).toBe(200);
            expect(await userRepo.count()).toBe(1);
        });
    });
});

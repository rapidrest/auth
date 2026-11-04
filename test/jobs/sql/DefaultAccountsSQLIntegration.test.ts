///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Runs the real `DefaultAccountsSQL` job against an in-memory SQLite database, covering what the mocked unit
// tests in DefaultAccounts.test.ts can't: that `RepoUtils` strips `@RequiresScope` fields (`Profile.contacts`)
// from what it returns, and that re-running the job never duplicates an account.
import config from "../../config.js";
import { ConnectionManager, ObjectFactory, Server, isSqlDataSource } from "@rapidrest/service-core";
import { Logger } from "@rapidrest/core";
import { Repository } from "typeorm";
import { MongoMemoryServer } from "mongodb-memory-server";
import * as path from "path";
import * as fs from "fs";
import { DefaultAccountsSQL } from "../../../src/jobs/sql/DefaultAccountsSQL.js";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";
import { AliasType, ContactType } from "../../../src/models/types.js";

const mongod: MongoMemoryServer = new MongoMemoryServer({ instance: { port: 9999, dbName: "rrst-test" } });

describe("DefaultAccountsSQL Integration Tests", () => {
    const logger = Logger();
    const objectFactory: ObjectFactory = new ObjectFactory(config, logger);
    const server: Server = new Server({ config, basePath: "./test/server-sql", logger, objectFactory });
    let job: any;
    let aliasRepo: Repository<any>;
    let profileRepo: Repository<any>;
    let secretRepo: Repository<any>;
    let userRepo: Repository<any>;

    const withEmail = () => ({
        name: "admin",
        email: "Admin@Example.local",
        password: "Some-Password-1!",
        roles: ["admin"],
    });

    beforeAll(async () => {
        await mongod.start();
        await server.start();
        const conn: any = objectFactory.getInstance(ConnectionManager)?.connections.get("sql");
        if (!isSqlDataSource(conn)) {
            throw new Error("Could not find sql connection");
        }
        aliasRepo = conn.getRepository(AliasSQL);
        profileRepo = conn.getRepository(ProfileSQL);
        secretRepo = conn.getRepository(SecretSQL);
        userRepo = conn.getRepository(UserSQL);
    });

    afterAll(async () => {
        await server.stop();
        await mongod.stop();
        await objectFactory.destroy();
    });

    beforeEach(async () => {
        for (const repo of [aliasRepo, profileRepo, secretRepo, userRepo]) {
            await repo.clear();
        }
        job = await objectFactory.newInstance(DefaultAccountsSQL, { name: `DefaultAccountsSQLTest-${Date.now()}` });
        job.passwordFile = undefined;
    });

    afterEach(() => {
        vi.restoreAllMocks();
        const passwordFile: string = path.resolve("passwords");
        if (fs.existsSync(passwordFile)) {
            fs.unlinkSync(passwordFile);
        }
    });

    it("Seeds an account that has an email.", async () => {
        job.defaultAccounts = [withEmail()];

        await job.start();

        const users = await userRepo.find();
        expect(users).toHaveLength(1);
        expect(users[0].roles).toEqual(["admin"]);
        const aliases = await aliasRepo.find({ where: { userUid: users[0].uid } });
        expect(aliases.map((a: any) => [a.type, a.alias]).sort()).toEqual([
            [AliasType.EMAIL, "admin@example.local"],
            [AliasType.NAME, "admin"],
        ]);
        expect(await secretRepo.count({ where: { userUid: users[0].uid } })).toBe(1);
        const profile = await profileRepo.findOne({ where: { uid: users[0].uid } });
        expect(profile.contacts).toEqual([{ contact: "admin@example.local", type: ContactType.EMAIL, verified: true }]);
    });

    it("Seeds an account that has no email.", async () => {
        job.defaultAccounts = [{ name: "admin", password: "Some-Password-1!" }];

        await job.start();

        const users = await userRepo.find();
        expect(users).toHaveLength(1);
        const aliases = await aliasRepo.find({ where: { userUid: users[0].uid } });
        expect(aliases.map((a: any) => a.alias)).toEqual(["admin"]);
        expect(await secretRepo.count({ where: { userUid: users[0].uid } })).toBe(1);
        expect((await profileRepo.findOne({ where: { uid: users[0].uid } })).contacts).toEqual([]);
    });

    it("Creates no duplicates when the job runs again, and keeps existing contacts.", async () => {
        job.defaultAccounts = [withEmail(), { name: "Second", phone: "+15555550100", password: "Some-Password-1!" }];
        await job.start();
        // A contact added by the account holder after the first run must survive the restart
        const first = await aliasRepo.findOne({ where: { alias: "admin" } });
        const profile = await profileRepo.findOne({ where: { uid: first.userUid } });
        profile.contacts.push({ contact: "me@example.com", type: ContactType.EMAIL, verified: false });
        await profileRepo.save(profile);
        const counts = async () => [
            await userRepo.count(),
            await aliasRepo.count(),
            await secretRepo.count(),
            await profileRepo.count(),
        ];
        const before = await counts();
        expect(before).toEqual([2, 4, 2, 2]);

        job.defaultAccounts = [withEmail(), { name: "Second", phone: "+15555550100", password: "Some-Password-1!" }];
        await job.start();
        await job.start();

        expect(await counts()).toEqual(before);
        const after = await profileRepo.findOne({ where: { uid: first.userUid } });
        expect(after.contacts.map((c: any) => c.contact).sort()).toEqual(["admin@example.local", "me@example.com"]);
    });

    it("Resumes an account whose provisioning failed part way, without creating another user.", async () => {
        job.defaultAccounts = [withEmail()];
        const create = vi.spyOn(job.secretRepo, "create").mockRejectedValueOnce(new Error("secret store down"));

        await expect(job.start()).rejects.toThrow("secret store down");
        expect(create).toHaveBeenCalledTimes(1);
        expect(await userRepo.count()).toBe(1);
        expect(await secretRepo.count()).toBe(0);

        await job.start();

        expect(await userRepo.count()).toBe(1);
        expect(await secretRepo.count()).toBe(1);
        expect(await aliasRepo.count()).toBe(2);
    });

    it("Removes the new user when its name alias can't be created, so the next run starts clean.", async () => {
        job.defaultAccounts = [withEmail()];
        vi.spyOn(job.aliasRepo, "create").mockRejectedValueOnce(new Error("alias store down"));

        await expect(job.start()).rejects.toThrow("alias store down");
        expect(await userRepo.count()).toBe(0);

        await job.start();

        expect(await userRepo.count()).toBe(1);
        expect(await aliasRepo.count()).toBe(2);
    });
});

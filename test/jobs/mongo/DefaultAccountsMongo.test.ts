///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test — no HTTP server, no database. `DefaultAccountsMongo` is a thin subclass that
// only wires the Mongo model classes onto the base `DefaultAccounts` job; its behavior is already
// covered by DefaultAccounts.test.ts.
import { DefaultAccounts } from "../../../src/jobs/DefaultAccounts.js";
import { DefaultAccountsMongo } from "../../../src/jobs/mongo/DefaultAccountsMongo.js";
import { AliasMongo } from "../../../src/models/mongo/AliasMongo.js";
import { ProfileMongo } from "../../../src/models/mongo/ProfileMongo.js";
import { SecretMongo } from "../../../src/models/mongo/SecretMongo.js";
import { UserMongo } from "../../../src/models/mongo/UserMongo.js";

describe("DefaultAccountsMongo Tests", () => {
    it("Wires the Mongo alias/profile/secret/user model classes onto the base DefaultAccounts job.", () => {
        const job = new DefaultAccountsMongo();

        expect(job).toBeInstanceOf(DefaultAccounts);
        expect((job as any).aliasClass).toBe(AliasMongo);
        expect((job as any).profileClass).toBe(ProfileMongo);
        expect((job as any).secretClass).toBe(SecretMongo);
        expect((job as any).userClass).toBe(UserMongo);
    });
});

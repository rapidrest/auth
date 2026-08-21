///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit test — no HTTP server, no database. `DefaultAccountsSQL` is a thin subclass that only
// wires the SQL model classes onto the base `DefaultAccounts` job; its behavior is already covered by
// DefaultAccounts.test.ts.
import { DefaultAccounts } from "../../../src/jobs/DefaultAccounts.js";
import { DefaultAccountsSQL } from "../../../src/jobs/sql/DefaultAccountsSQL.js";
import { AliasSQL } from "../../../src/models/sql/AliasSQL.js";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL.js";
import { SecretSQL } from "../../../src/models/sql/SecretSQL.js";
import { UserSQL } from "../../../src/models/sql/UserSQL.js";

describe("DefaultAccountsSQL Tests", () => {
    it("Wires the SQL alias/profile/secret/user model classes onto the base DefaultAccounts job.", () => {
        const job = new DefaultAccountsSQL();

        expect(job).toBeInstanceOf(DefaultAccounts);
        expect((job as any).aliasClass).toBe(AliasSQL);
        expect((job as any).profileClass).toBe(ProfileSQL);
        expect((job as any).secretClass).toBe(SecretSQL);
        expect((job as any).userClass).toBe(UserSQL);
    });
});

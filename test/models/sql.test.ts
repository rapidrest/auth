///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasType, SecretType } from "../../src/models/types.js";
import { AliasSQL } from "../../src/models/sql/AliasSQL.js";
import { ProfileSQL } from "../../src/models/sql/ProfileSQL.js";
import { SecretSQL } from "../../src/models/sql/SecretSQL.js";
import { UserSQL } from "../../src/models/sql/UserSQL.js";

describe("SQL model default construction", () => {
    it("AliasSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new AliasSQL();

        expect(obj.alias).toBe("");
        expect(obj.type).toBe(AliasType.NAME);
        expect(obj.userUid).toBe("");
        expect(obj.verified).toBe(false);
    });

    it("ProfileSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new ProfileSQL();

        expect(obj.avatar).toBeUndefined();
        expect(obj.birthdate).toBeUndefined();
        expect(obj.contacts).toEqual([]);
        expect(obj.givenName).toBeUndefined();
        expect(obj.familyName).toBeUndefined();
        expect(obj.preferences).toEqual({ contact: ["all"] });
    });

    it("SecretSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new SecretSQL();

        expect(obj.data).toBeUndefined();
        expect(obj.hint).toBeUndefined();
        expect(obj.type).toBe(SecretType.PASSWORD);
        expect(obj.userUid).toBe("");
    });

    it("SecretSQL applies a provided hint when constructed with data.", () => {
        const obj = new SecretSQL({ hint: "My favorite pet's name" });

        expect(obj.hint).toBe("My favorite pet's name");
    });

    it("UserSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new UserSQL();

        expect(obj.roles).toEqual([]);
        expect(obj.scopes).toEqual([]);
        expect(obj.verified).toBe(false);
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { AliasType, SecretType } from "../../src/models/types.js";
import { AliasMongo } from "../../src/models/mongo/AliasMongo.js";
import { ProfileMongo } from "../../src/models/mongo/ProfileMongo.js";
import { SecretMongo } from "../../src/models/mongo/SecretMongo.js";
import { UserMongo } from "../../src/models/mongo/UserMongo.js";

describe("Mongo model default construction", () => {
    it("AliasMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new AliasMongo();

        expect(obj.alias).toBe("");
        expect(obj.type).toBe(AliasType.NAME);
        expect(obj.userUid).toBe("");
        expect(obj.verified).toBe(false);
    });

    it("ProfileMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new ProfileMongo();

        expect(obj.avatar).toBeUndefined();
        expect(obj.birthdate).toBeUndefined();
        expect(obj.contacts).toEqual([]);
        expect(obj.givenName).toBeUndefined();
        expect(obj.familyName).toBeUndefined();
        expect(obj.preferences).toEqual({ contact: ["all"] });
    });

    it("SecretMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new SecretMongo();

        expect(obj.data).toBeUndefined();
        expect(obj.hint).toBeUndefined();
        expect(obj.type).toBe(SecretType.PASSWORD);
        expect(obj.userUid).toBe("");
    });

    it("SecretMongo applies a provided hint when constructed with data.", () => {
        const obj = new SecretMongo({ hint: "My favorite pet's name" });

        expect(obj.hint).toBe("My favorite pet's name");
    });

    it("UserMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new UserMongo();

        expect(obj.roles).toEqual([]);
        expect(obj.scopes).toEqual([]);
        expect(obj.verified).toBe(false);
    });
});

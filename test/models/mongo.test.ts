///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasType, ClientType, SecretType, SigningKeyStatus, TokenEndpointAuthMethod } from "../../src/models/types.js";
import { AliasMongo } from "../../src/models/mongo/AliasMongo.js";
import { AuthorizationCodeMongo } from "../../src/models/mongo/AuthorizationCodeMongo.js";
import { ClientMongo } from "../../src/models/mongo/ClientMongo.js";
import { ConsentGrantMongo } from "../../src/models/mongo/ConsentGrantMongo.js";
import { OAuthRefreshTokenMongo } from "../../src/models/mongo/OAuthRefreshTokenMongo.js";
import { ProfileMongo } from "../../src/models/mongo/ProfileMongo.js";
import { SecretMongo } from "../../src/models/mongo/SecretMongo.js";
import { SigningKeyMongo } from "../../src/models/mongo/SigningKeyMongo.js";
import { UserMongo } from "../../src/models/mongo/UserMongo.js";

describe("Mongo model default construction", () => {
    it("AliasMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new AliasMongo();

        expect(obj.alias).toBe("");
        expect(obj.type).toBe(AliasType.NAME);
        expect(obj.userUid).toBe("");
        expect(obj.verified).toBe(false);
    });

    it("AuthorizationCodeMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new AuthorizationCodeMongo();

        expect(obj.codeHash).toBe("");
        expect(obj.clientId).toBe("");
        expect(obj.userUid).toBe("");
        expect(obj.redirectUri).toBe("");
        expect(obj.scope).toBe("");
        expect(obj.codeChallenge).toBeUndefined();
        expect(obj.codeChallengeMethod).toBeUndefined();
        expect(obj.nonce).toBeUndefined();
        expect(obj.used).toBe(false);
    });

    it("AuthorizationCodeMongo applies provided data when constructed with data.", () => {
        const obj = new AuthorizationCodeMongo({ codeHash: "hash-1", used: true });

        expect(obj.codeHash).toBe("hash-1");
        expect(obj.used).toBe(true);
    });

    it("ConsentGrantMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new ConsentGrantMongo();

        expect(obj.userUid).toBe("");
        expect(obj.clientId).toBe("");
        expect(obj.scope).toBe("");
        expect(obj.lastUsedAt).toBeUndefined();
    });

    it("ConsentGrantMongo applies provided data when constructed with data.", () => {
        const obj = new ConsentGrantMongo({ userUid: "user-1", clientId: "client-1", scope: "openid profile" });

        expect(obj.userUid).toBe("user-1");
        expect(obj.clientId).toBe("client-1");
        expect(obj.scope).toBe("openid profile");
    });

    it("OAuthRefreshTokenMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new OAuthRefreshTokenMongo();

        expect(obj.tokenHash).toBe("");
        expect(obj.clientId).toBe("");
        expect(obj.userUid).toBeUndefined();
        expect(obj.scope).toBe("");
        expect(obj.familyId).toBe("");
        expect(obj.revoked).toBe(false);
        expect(obj.revokedAt).toBeUndefined();
        expect(obj.replacedByHash).toBeUndefined();
    });

    it("OAuthRefreshTokenMongo applies provided data when constructed with data.", () => {
        const obj = new OAuthRefreshTokenMongo({ tokenHash: "hash-1", clientId: "client-1", revoked: true });

        expect(obj.tokenHash).toBe("hash-1");
        expect(obj.clientId).toBe("client-1");
        expect(obj.revoked).toBe(true);
    });

    it("ClientMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new ClientMongo();

        expect(obj.clientSecretHash).toBeUndefined();
        expect(obj.clientType).toBe(ClientType.CONFIDENTIAL);
        expect(obj.clientName).toBe("");
        expect(obj.redirectUris).toEqual([]);
        expect(obj.grantTypes).toEqual([]);
        expect(obj.responseTypes).toEqual([]);
        expect(obj.scope).toBe("");
        expect(obj.tokenEndpointAuthMethod).toBe(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        expect(obj.requirePkce).toBe(false);
        expect(obj.firstParty).toBe(false);
        expect(obj.disabled).toBeUndefined();
    });

    it("ClientMongo applies provided data when constructed with data.", () => {
        const obj = new ClientMongo({ clientName: "My App", firstParty: true });

        expect(obj.clientName).toBe("My App");
        expect(obj.firstParty).toBe(true);
    });

    it("SigningKeyMongo falls back to class defaults when constructed with no data.", () => {
        const obj = new SigningKeyMongo();

        expect(obj.kid).toBe("");
        expect(obj.alg).toBe("RS256");
        expect(obj.publicKeyJwk).toEqual({});
        expect(obj.privateKeyEncrypted).toBe("");
        expect(obj.status).toBe(SigningKeyStatus.ACTIVE);
        expect(obj.retiredAt).toBeUndefined();
    });

    it("SigningKeyMongo applies provided data when constructed with data.", () => {
        const retiredAt = new Date();
        const obj = new SigningKeyMongo({ kid: "key-1", status: SigningKeyStatus.RETIRED, retiredAt });

        expect(obj.kid).toBe("key-1");
        expect(obj.status).toBe(SigningKeyStatus.RETIRED);
        expect(obj.retiredAt).toBe(retiredAt);
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

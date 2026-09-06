///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasType, ClientType, SecretType, SigningKeyStatus, TokenEndpointAuthMethod } from "../../src/models/types.js";
import { AliasSQL } from "../../src/models/sql/AliasSQL.js";
import { AuthorizationCodeSQL } from "../../src/models/sql/AuthorizationCodeSQL.js";
import { ClientSQL } from "../../src/models/sql/ClientSQL.js";
import { ConsentGrantSQL } from "../../src/models/sql/ConsentGrantSQL.js";
import { OAuthRefreshTokenSQL } from "../../src/models/sql/OAuthRefreshTokenSQL.js";
import { ProfileSQL } from "../../src/models/sql/ProfileSQL.js";
import { SecretSQL } from "../../src/models/sql/SecretSQL.js";
import { SigningKeySQL } from "../../src/models/sql/SigningKeySQL.js";
import { UserSQL } from "../../src/models/sql/UserSQL.js";

describe("SQL model default construction", () => {
    it("AliasSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new AliasSQL();

        expect(obj.alias).toBe("");
        expect(obj.type).toBe(AliasType.NAME);
        expect(obj.userUid).toBe("");
        expect(obj.verified).toBe(false);
    });

    it("AuthorizationCodeSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new AuthorizationCodeSQL();

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

    it("AuthorizationCodeSQL applies provided data when constructed with data.", () => {
        const obj = new AuthorizationCodeSQL({ codeHash: "hash-1", used: true });

        expect(obj.codeHash).toBe("hash-1");
        expect(obj.used).toBe(true);
    });

    it("ConsentGrantSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new ConsentGrantSQL();

        expect(obj.userUid).toBe("");
        expect(obj.clientId).toBe("");
        expect(obj.scope).toBe("");
        expect(obj.lastUsedAt).toBeUndefined();
    });

    it("ConsentGrantSQL applies provided data when constructed with data.", () => {
        const obj = new ConsentGrantSQL({ userUid: "user-1", clientId: "client-1", scope: "openid profile" });

        expect(obj.userUid).toBe("user-1");
        expect(obj.clientId).toBe("client-1");
        expect(obj.scope).toBe("openid profile");
    });

    it("OAuthRefreshTokenSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new OAuthRefreshTokenSQL();

        expect(obj.tokenHash).toBe("");
        expect(obj.clientId).toBe("");
        expect(obj.userUid).toBeUndefined();
        expect(obj.scope).toBe("");
        expect(obj.familyId).toBe("");
        expect(obj.revoked).toBe(false);
        expect(obj.revokedAt).toBeUndefined();
        expect(obj.replacedByHash).toBeUndefined();
    });

    it("OAuthRefreshTokenSQL applies provided data when constructed with data.", () => {
        const obj = new OAuthRefreshTokenSQL({ tokenHash: "hash-1", clientId: "client-1", revoked: true });

        expect(obj.tokenHash).toBe("hash-1");
        expect(obj.clientId).toBe("client-1");
        expect(obj.revoked).toBe(true);
    });

    it("ClientSQL falls back to class defaults when constructed with no data.", () => {
        const obj = new ClientSQL();

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

    it("ClientSQL applies provided data when constructed with data.", () => {
        const obj = new ClientSQL({ clientName: "My App", firstParty: true });

        expect(obj.clientName).toBe("My App");
        expect(obj.firstParty).toBe(true);
    });

    it("SigningKeySQL falls back to class defaults when constructed with no data.", () => {
        const obj = new SigningKeySQL();

        expect(obj.kid).toBe("");
        expect(obj.alg).toBe("RS256");
        expect(obj.publicKeyJwk).toEqual({});
        expect(obj.privateKeyEncrypted).toBe("");
        expect(obj.status).toBe(SigningKeyStatus.ACTIVE);
        expect(obj.retiredAt).toBeUndefined();
    });

    it("SigningKeySQL applies provided data when constructed with data.", () => {
        const retiredAt = new Date();
        const obj = new SigningKeySQL({ kid: "key-1", status: SigningKeyStatus.RETIRED, retiredAt });

        expect(obj.kid).toBe("key-1");
        expect(obj.status).toBe(SigningKeyStatus.RETIRED);
        expect(obj.retiredAt).toBe(retiredAt);
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

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for OAuthTokenUtils — no HTTP server, no database. Uses a real SigningKeyUtils
// (backed by an in-memory mock repo) so tokens are genuinely RS256-signed, and verifies them with the real
// `jsonwebtoken` package rather than mocking it, since the whole point of these tests is confirming the
// issued tokens are actually well-formed, correctly-signed, and carry the right claims.
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import { JWTUser } from "@rapidrest/core";
import { OAuthTokenUtils } from "../../src/auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { Client, ClientType, SigningKey, TokenEndpointAuthMethod } from "../../src/models/types.js";

const ENCRYPTION_KEY = "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718";

function makeMockSigningKeyRepo() {
    const store = new Map<string, SigningKey>();
    return {
        create: vi.fn(async (obj: Partial<SigningKey>) => {
            const key = { uid: obj.kid!, dateCreated: new Date(), dateModified: new Date(), version: 0, ...obj } as SigningKey;
            store.set(key.kid, key);
            return key;
        }),
        find: vi.fn(async (query: any) => {
            const all = Array.from(store.values());
            if (Object.keys(query).length === 0) {
                return all;
            }
            return all.filter((key) => Object.entries(query).every(([k, v]) => (key as any)[k] === v));
        }),
        findOne: vi.fn(async (kid: string) => store.get(kid)),
        update: vi.fn(async (obj: Partial<SigningKey>, existing: SigningKey) => {
            const updated = { ...existing, ...obj };
            store.set(existing.kid, updated);
            return updated;
        }),
    };
}

function makeOAuthTokenUtils(config: any = {}) {
    const signingKeyUtils = new SigningKeyUtils(makeMockSigningKeyRepo() as any);
    (signingKeyUtils as any).config = { encryption_key: ENCRYPTION_KEY };
    const utils = new OAuthTokenUtils(signingKeyUtils);
    (utils as any).config = config;
    return utils;
}

const client: Client = {
    uid: "client-record-1",
    dateCreated: new Date(),
    dateModified: new Date(),
    version: 0,
    clientId: "abc123",
    clientType: ClientType.CONFIDENTIAL,
    clientName: "Test App",
    redirectUris: ["https://app.example.com/callback"],
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    scope: "openid profile",
    tokenEndpointAuthMethod: TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    requirePkce: false,
    firstParty: false,
};

const user: JWTUser = { uid: "user-1", roles: ["member"], scopes: [] };

describe("OAuthTokenUtils Tests", () => {
    describe("createAccessToken", () => {
        it("Issues an RS256-signed access token with the expected flat OAuth claims.", async () => {
            const utils = makeOAuthTokenUtils({ issuer: "https://auth.example.com" });

            const { token, jti, expiresIn } = await utils.createAccessToken(client, user, ["openid", "profile"]);

            expect(expiresIn).toBe(900);
            const decoded = jwt.decode(token, { complete: true }) as any;
            expect(decoded.header.alg).toBe("RS256");
            expect(decoded.header.kid).toBeDefined();
            expect(decoded.payload.sub).toBe("user-1");
            expect(decoded.payload.aud).toBe("abc123");
            expect(decoded.payload.azp).toBe("abc123");
            expect(decoded.payload.client_id).toBe("abc123");
            expect(decoded.payload.scope).toBe("openid profile");
            expect(decoded.payload.jti).toBe(jti);
            expect(decoded.payload.iss).toBe("https://auth.example.com");
        });

        it("Uses the client's clientId as sub when no user is provided (client_credentials).", async () => {
            const utils = makeOAuthTokenUtils();

            const { token } = await utils.createAccessToken(client, undefined, ["profile"]);

            const decoded = jwt.decode(token) as any;
            expect(decoded.sub).toBe("abc123");
            expect(decoded.aud).toBe("abc123");
            expect(decoded.scope).toBe("profile");
        });

        it("Honors a configured accessTokenTTL.", async () => {
            const utils = makeOAuthTokenUtils({ accessTokenTTL: "5m" });

            const { expiresIn } = await utils.createAccessToken(client, user, []);

            expect(expiresIn).toBe(300);
        });

        it("Signs with a key verifiable via the same SigningKeyUtils' public JWK.", async () => {
            const signingKeyUtils = new SigningKeyUtils(makeMockSigningKeyRepo() as any);
            (signingKeyUtils as any).config = { encryption_key: ENCRYPTION_KEY };
            const utils = new OAuthTokenUtils(signingKeyUtils);
            (utils as any).config = {};

            const { token } = await utils.createAccessToken(client, user, ["openid"]);
            const jwks = await signingKeyUtils.getPublicJwks();
            const decodedHeader = jwt.decode(token, { complete: true }) as any;
            const matchingJwk = jwks.keys.find((k) => k.kid === decodedHeader.header.kid);

            expect(matchingJwk).toBeDefined();

            // Verifying against the *decrypted PEM* the signing key actually used confirms end-to-end
            // correctness (the public JWK matching by kid alone wouldn't catch a signature mismatch).
            const material = await signingKeyUtils.getSigningMaterial(decodedHeader.header.kid);
            const publicKey = crypto.createPublicKey(material.privateKeyPem);
            expect(() => jwt.verify(token, publicKey, { algorithms: ["RS256"] })).not.toThrow();
        });
    });

    describe("createIdToken", () => {
        it("Issues an RS256-signed id_token with core OIDC claims and the echoed nonce.", async () => {
            const utils = makeOAuthTokenUtils({ issuer: "https://auth.example.com" });

            const token = await utils.createIdToken(client, user, "nonce-abc");

            const decoded = jwt.decode(token) as any;
            expect(decoded.sub).toBe("user-1");
            expect(decoded.aud).toBe("abc123");
            expect(decoded.azp).toBe("abc123");
            expect(decoded.nonce).toBe("nonce-abc");
            expect(decoded.auth_time).toBeTypeOf("number");
            expect(decoded.iss).toBe("https://auth.example.com");
        });

        it("Omits the nonce claim entirely when none was requested.", async () => {
            const utils = makeOAuthTokenUtils();

            const token = await utils.createIdToken(client, user, undefined);

            const decoded = jwt.decode(token) as any;
            expect("nonce" in decoded).toBe(false);
        });

        it("Honors a configured idTokenTTL.", async () => {
            const utils = makeOAuthTokenUtils({ idTokenTTL: "2m" });

            const token = await utils.createIdToken(client, user, undefined);

            const decoded = jwt.decode(token) as any;
            expect(decoded.exp - decoded.iat).toBe(120);
        });
    });
});

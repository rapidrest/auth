///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for SigningKeyUtils — no HTTP server, no database.
// Node's built-in `crypto` module can't be `vi.spyOn()`-ed directly (its ESM namespace object is not
// configurable), so a full `vi.mock()` is used instead - defaulting every function to the real
// implementation via `importOriginal()`, and overriding only `generateKeyPair` for the one test that
// needs to simulate a failure.
vi.mock("crypto", async (importOriginal) => {
    const actual = await importOriginal<typeof import("crypto")>();
    return { ...actual, generateKeyPair: vi.fn(actual.generateKeyPair) };
});

import * as crypto from "crypto";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { SigningKey, SigningKeyStatus } from "../../src/models/types.js";

const mockGenerateKeyPair = crypto.generateKeyPair as unknown as ReturnType<typeof vi.fn>;

const ENCRYPTION_KEY = "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718";

function makeMockRepo() {
    const store = new Map<string, SigningKey>();
    return {
        create: vi.fn(async (obj: Partial<SigningKey>) => {
            const key: SigningKey = { uid: obj.kid!, dateCreated: new Date(), dateModified: new Date(), version: 0, ...obj } as SigningKey;
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
            // Mirrors RepoUtils.update()'s real optimistic-locking contract: `obj` must carry the same
            // `uid`/`version` as `existing`, not just the fields being changed — a bare partial like
            // `{status: ...}` would fail this check in production even on a first, uncontested call.
            if ((obj as any).uid !== existing.uid || obj.version !== existing.version) {
                throw new Error("Invalid object version. Do you have the latest version?");
            }
            const updated = { ...existing, ...obj, version: existing.version + 1 };
            store.set(existing.kid, updated);
            return updated;
        }),
    };
}

function makeUtils(config: any = { encryption_key: ENCRYPTION_KEY }) {
    const repo = makeMockRepo();
    const utils = new SigningKeyUtils(repo as any);
    (utils as any).config = config;
    return { utils, repo };
}

describe("SigningKeyUtils Tests", () => {
    it("getActiveSigningKey() generates and persists a new key when none exists.", async () => {
        const { utils, repo } = makeUtils();

        const key = await utils.getActiveSigningKey();

        expect(key.kid).toBeTruthy();
        expect(key.alg).toBe("RS256");
        expect(key.status).toBe(SigningKeyStatus.ACTIVE);
        expect(key.publicKeyJwk.kty).toBe("RSA");
        expect(key.publicKeyJwk.kid).toBe(key.kid);
        expect(key.privateKeyEncrypted.startsWith("enc:v1:")).toBe(true);
        expect(repo.create).toHaveBeenCalledTimes(1);
    });

    it("getActiveSigningKey() returns the existing active key without generating a new one.", async () => {
        const { utils, repo } = makeUtils();

        const first = await utils.getActiveSigningKey();
        const second = await utils.getActiveSigningKey();

        expect(second.kid).toBe(first.kid);
        expect(repo.create).toHaveBeenCalledTimes(1);
    });

    it("getActiveSigningKey() throws a clear error when no encryption key is configured.", async () => {
        const { utils } = makeUtils({});

        await expect(utils.getActiveSigningKey()).rejects.toThrow(/encryption_key/);
    });

    it("getActiveSigningKey() throws a clear error when the configured encryption key has the wrong length.", async () => {
        const { utils } = makeUtils({ encryption_key: "tooshort" });

        await expect(utils.getActiveSigningKey()).rejects.toThrow(/64-character hex string/);
    });

    it("rotateKey() retires the previously active key and generates a new active one.", async () => {
        const { utils, repo } = makeUtils();

        const original = await utils.getActiveSigningKey();
        const rotated = await utils.rotateKey();

        expect(rotated.kid).not.toBe(original.kid);
        expect(rotated.status).toBe(SigningKeyStatus.ACTIVE);

        const retired = await repo.findOne(original.kid);
        expect(retired!.status).toBe(SigningKeyStatus.RETIRED);
        expect(retired!.retiredAt).toBeInstanceOf(Date);
    });

    it("getPublicJwks() includes the active key and excludes a retired key past its grace period.", async () => {
        const { utils, repo } = makeUtils({ encryption_key: ENCRYPTION_KEY, retirementGraceDays: 7 });

        const active = await utils.getActiveSigningKey();
        await repo.create({
            kid: "expired-retired-key",
            alg: "RS256",
            publicKeyJwk: { kty: "RSA", kid: "expired-retired-key" },
            privateKeyEncrypted: "enc:v1:unused",
            status: SigningKeyStatus.RETIRED,
            activatedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            retiredAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
        });
        await repo.create({
            kid: "recently-retired-key",
            alg: "RS256",
            publicKeyJwk: { kty: "RSA", kid: "recently-retired-key" },
            privateKeyEncrypted: "enc:v1:unused",
            status: SigningKeyStatus.RETIRED,
            activatedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
            retiredAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
        });

        const jwks = await utils.getPublicJwks();
        const kids = jwks.keys.map((k) => k.kid);

        expect(kids).toContain(active.kid);
        expect(kids).toContain("recently-retired-key");
        expect(kids).not.toContain("expired-retired-key");
    });

    it("getPublicJwks() falls back to a 7 day retirement grace period by default.", async () => {
        const { utils, repo } = makeUtils({ encryption_key: ENCRYPTION_KEY });

        const active = await utils.getActiveSigningKey();
        await repo.create({
            kid: "expired-retired-key",
            alg: "RS256",
            publicKeyJwk: { kty: "RSA", kid: "expired-retired-key" },
            privateKeyEncrypted: "enc:v1:unused",
            status: SigningKeyStatus.RETIRED,
            activatedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
            retiredAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
        });

        const jwks = await utils.getPublicJwks();
        const kids = jwks.keys.map((k) => k.kid);

        expect(kids).toContain(active.kid);
        expect(kids).not.toContain("expired-retired-key");
    });

    it("getJwksCacheMaxAgeSeconds() returns half of the configured rotation interval, in seconds.", () => {
        const { utils } = makeUtils({ encryption_key: ENCRYPTION_KEY, rotationIntervalDays: 10 });

        expect(utils.getJwksCacheMaxAgeSeconds()).toBe((10 * 24 * 60 * 60) / 2);
    });

    it("getJwksCacheMaxAgeSeconds() falls back to a 30 day rotation interval by default.", () => {
        const { utils } = makeUtils({ encryption_key: ENCRYPTION_KEY });

        expect(utils.getJwksCacheMaxAgeSeconds()).toBe((30 * 24 * 60 * 60) / 2);
    });

    it("getSigningMaterial() decrypts the active key's private material by default.", async () => {
        const { utils } = makeUtils();

        const active = await utils.getActiveSigningKey();
        const material = await utils.getSigningMaterial();

        expect(material.kid).toBe(active.kid);
        expect(material.privateKeyPem).toContain("PRIVATE KEY");
    });

    it("getSigningMaterial() decrypts the private material for a specific kid.", async () => {
        const { utils } = makeUtils();

        const active = await utils.getActiveSigningKey();
        const material = await utils.getSigningMaterial(active.kid);

        expect(material.kid).toBe(active.kid);
        expect(material.privateKeyPem).toContain("PRIVATE KEY");
    });

    it("getSigningMaterial() throws when no key exists for the given kid.", async () => {
        const { utils } = makeUtils();

        await expect(utils.getSigningMaterial("does-not-exist")).rejects.toThrow(/No signing key found/);
    });

    it("getSigningMaterial() throws when no active key exists and none was requested by kid.", async () => {
        const { utils } = makeUtils();
        vi.spyOn(utils, "getActiveSigningKey").mockResolvedValue(undefined);

        await expect(utils.getSigningMaterial()).rejects.toThrow(/No signing key found/);
    });

    it("Propagates the error when RSA key pair generation fails.", async () => {
        const { utils } = makeUtils();
        mockGenerateKeyPair.mockImplementationOnce((..._args: any[]) => {
            const callback = _args[_args.length - 1];
            callback(new Error("boom"));
        });

        await expect(utils.getActiveSigningKey()).rejects.toThrow(/boom/);
    });

    it("getSigningMaterial() throws when the stored private material uses an unrecognized format.", async () => {
        const { utils, repo } = makeUtils();

        await repo.create({
            kid: "bad-format-key",
            alg: "RS256",
            publicKeyJwk: { kty: "RSA", kid: "bad-format-key" },
            privateKeyEncrypted: "not-encrypted-at-all",
            status: SigningKeyStatus.RETIRED,
            activatedAt: new Date(),
        });

        await expect(utils.getSigningMaterial("bad-format-key")).rejects.toThrow(/unrecognized format/);
    });
});

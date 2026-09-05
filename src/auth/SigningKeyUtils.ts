///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as crypto from "crypto";
import { ApiError, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors, RepoUtils } from "@rapidrest/service-core";
import { SigningKey, SigningKeyStatus } from "../models/types.js";

const { Config } = ObjectDecorators;

/**
 * Configuration options for `SigningKeyUtils`.
 */
export interface SigningKeyConfig {
    /**
     * The 64-character hex AES-256 key used to encrypt signing key private material at rest. Required before
     * any signing key can be generated or used — there is no plaintext fallback, since this material (unlike
     * e.g. a TOTP secret) is the entire trust root for every token this authorization server issues.
     */
    encryption_key?: string;
    /** How often, in days, a new active signing key should be generated. Default `30`. Informational only —
     * actually rotating on this schedule is the responsibility of a caller invoking `rotateKey()` periodically. */
    rotationIntervalDays?: number;
    /** How many days a retired key remains servable from `getPublicJwks()` before being excluded. Default `7`. */
    retirementGraceDays?: number;
}

const ENCRYPTION_PREFIX = "enc:v1:";
const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const ENCRYPTION_IV_LENGTH = 12;
const ENCRYPTION_AUTH_TAG_LENGTH = 16;

/**
 * Decodes `key` (a 64-character hex string) into the 32-byte buffer `aes-256-gcm` requires, throwing a
 * deployment-misconfiguration error rather than silently encrypting/decrypting with the wrong key length.
 */
function parseEncryptionKey(key: string): Buffer {
    const buf = Buffer.from(key, "hex");
    if (buf.length !== 32) {
        throw new ApiError(
            ApiErrors.INTERNAL_ERROR,
            500,
            "`auth:oauth_server:keys:encryption_key` must be a 64-character hex string (32 bytes) for AES-256-GCM.",
        );
    }
    return buf;
}

/**
 * A freshly generated RSA signing key pair, ready to be persisted as a `SigningKey`.
 */
export interface GeneratedKeyPair {
    kid: string;
    publicKeyJwk: any;
    privateKeyPem: string;
}

/**
 * Manages the RSA key pairs this authorization server uses to sign the tokens it issues, backing the
 * `/jwks.json` endpoint and every OAuth/OIDC token-issuance/verification path. Not exported from
 * `src/auth/index.ts` — like `TokenUtils`, this is an internal service constructed by a route's `@Init`
 * hook (`this._objectFactory.newInstance(SigningKeyUtils, {name, args: [signingKeyRepo]})`), since the
 * concrete `SigningKey` model class differs between the Mongo and SQL datastores.
 *
 * @author Jean-Philippe Steinmetz
 */
export class SigningKeyUtils {
    @Config("auth:oauth_server:keys", {})
    protected config: SigningKeyConfig = {};

    private readonly repo: RepoUtils<SigningKey>;

    constructor(repo: RepoUtils<SigningKey>) {
        this.repo = repo;
    }

    private encryptionKey(): string {
        if (!this.config.encryption_key) {
            throw new ApiError(
                ApiErrors.INTERNAL_ERROR,
                500,
                "`auth:oauth_server:keys:encryption_key` must be configured (a 64-character hex string) before " +
                    "the authorization server can generate or use signing keys.",
            );
        }
        return this.config.encryption_key;
    }

    /**
     * Encrypts `pem` for storage, using AES-256-GCM with a fresh random IV per call. Stores the result as
     * `"enc:v1:" + base64(iv[12] + authTag[16] + ciphertext)` — the same versioned envelope shape used
     * elsewhere in this library (see `shared.ts`'s `encryptTOTPSecret`), applied here to a private key
     * instead of a TOTP secret.
     */
    private encryptPrivateKey(pem: string): string {
        const keyBuf = parseEncryptionKey(this.encryptionKey());
        const iv = crypto.randomBytes(ENCRYPTION_IV_LENGTH);
        const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, keyBuf, iv);
        const ciphertext = Buffer.concat([cipher.update(pem, "utf8"), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return ENCRYPTION_PREFIX + Buffer.concat([iv, authTag, ciphertext]).toString("base64");
    }

    /** Decrypts private key material previously encrypted by `encryptPrivateKey()`. */
    private decryptPrivateKey(encrypted: string): string {
        if (!encrypted.startsWith(ENCRYPTION_PREFIX)) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Signing key private material uses an unrecognized format.");
        }

        const keyBuf = parseEncryptionKey(this.encryptionKey());
        const raw = Buffer.from(encrypted.slice(ENCRYPTION_PREFIX.length), "base64");
        const iv = raw.subarray(0, ENCRYPTION_IV_LENGTH);
        const authTag = raw.subarray(ENCRYPTION_IV_LENGTH, ENCRYPTION_IV_LENGTH + ENCRYPTION_AUTH_TAG_LENGTH);
        const ciphertext = raw.subarray(ENCRYPTION_IV_LENGTH + ENCRYPTION_AUTH_TAG_LENGTH);

        const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, keyBuf, iv);
        decipher.setAuthTag(authTag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return plaintext.toString("utf8");
    }

    /** Generates a new RSA-2048 key pair and its JWK/`kid`, without persisting anything. */
    private async generateKeyPair(): Promise<GeneratedKeyPair> {
        const { publicKey, privateKey } = await new Promise<{ publicKey: string; privateKey: string }>(
            (resolve, reject) => {
                crypto.generateKeyPair(
                    "rsa",
                    {
                        modulusLength: 2048,
                        publicKeyEncoding: { type: "spki", format: "pem" },
                        privateKeyEncoding: { type: "pkcs8", format: "pem" },
                    },
                    (err, publicKeyPem, privateKeyPem) =>
                        err ? reject(err) : resolve({ publicKey: publicKeyPem, privateKey: privateKeyPem }),
                );
            },
        );

        // A random, non-sequential kid - not derived from the key material itself - so a verifier can select
        // the right key without that identifier leaking any information about the key content.
        const kid = crypto.randomBytes(16).toString("base64url");
        const publicKeyJwk = {
            ...crypto.createPublicKey(publicKey).export({ format: "jwk" }),
            kid,
            use: "sig",
            alg: "RS256",
        };

        return { kid, publicKeyJwk, privateKeyPem: privateKey };
    }

    private async createKey(): Promise<SigningKey> {
        const { kid, publicKeyJwk, privateKeyPem } = await this.generateKeyPair();
        const key: Partial<SigningKey> = {
            kid,
            alg: "RS256",
            publicKeyJwk,
            privateKeyEncrypted: this.encryptPrivateKey(privateKeyPem),
            status: SigningKeyStatus.ACTIVE,
            activatedAt: new Date(),
        };
        return this.repo.create(key, { ignoreACL: true });
    }

    /**
     * Returns the currently active signing key, lazily generating and persisting one if none exists yet — no
     * separate provisioning step is required before the authorization server can start issuing tokens.
     */
    public async getActiveSigningKey(): Promise<SigningKey> {
        const existing = await this.repo.find({ status: SigningKeyStatus.ACTIVE }, { ignoreACL: true, limit: 1 });
        if (existing.length > 0) {
            return existing[0];
        }
        return this.createKey();
    }

    /**
     * Generates a new active signing key, retiring whichever key(s) were previously active. A retired key
     * remains servable from `getPublicJwks()` for `retirementGraceDays` so tokens signed with it before
     * rotation can still be verified until they naturally expire.
     */
    public async rotateKey(): Promise<SigningKey> {
        const active = await this.repo.find({ status: SigningKeyStatus.ACTIVE }, { ignoreACL: true });
        for (const key of active) {
            await this.repo.update(
                { uid: key.uid, version: key.version, status: SigningKeyStatus.RETIRED, retiredAt: new Date() },
                key,
                { ignoreACL: true },
            );
        }
        return this.createKey();
    }

    /**
     * Returns the public JWK set: the active key plus any retired key still within its retirement grace
     * period. Never includes private key material. Ensures an active key exists first (see
     * `getActiveSigningKey()`), so a fresh deployment's very first call returns a real key instead of an
     * empty set.
     */
    public async getPublicJwks(): Promise<{ keys: any[] }> {
        await this.getActiveSigningKey();
        const all = await this.repo.find({}, { ignoreACL: true });
        const graceMs = (this.config.retirementGraceDays ?? 7) * 24 * 60 * 60 * 1000;
        const now = Date.now();

        const keys = all
            .filter((key) => key.status === SigningKeyStatus.ACTIVE || now - new Date(key.retiredAt!).getTime() < graceMs)
            .map((key) => key.publicKeyJwk);

        return { keys };
    }

    /**
     * Returns how long, in seconds, a `/jwks.json` response may be cached for — half of
     * `rotationIntervalDays`, so a cached response can never outlive a key rotation by more than that margin.
     */
    public getJwksCacheMaxAgeSeconds(): number {
        const rotationIntervalDays = this.config.rotationIntervalDays ?? 30;
        return Math.floor((rotationIntervalDays * 24 * 60 * 60) / 2);
    }

    /**
     * Decrypts and returns the PEM-encoded private key material for the given `kid`, or the currently active
     * key if `kid` is omitted. Never caches the decrypted result — decryption happens fresh on every call.
     */
    public async getSigningMaterial(kid?: string): Promise<{ kid: string; privateKeyPem: string }> {
        const key = kid ? await this.repo.findOne(kid, { ignoreACL: true }) : await this.getActiveSigningKey();
        if (!key) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, `No signing key found for kid "${kid}".`);
        }
        return { kid: key.kid, privateKeyPem: this.decryptPrivateKey(key.privateKeyEncrypted) };
    }
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUser, JWTUtils, JWTUtilsConfig, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors } from "@rapidrest/service-core";
import * as crypto from "crypto";
import jwt from "jsonwebtoken";
import parseDuration from "parse-duration";
import * as uuid from "uuid";
import { Client } from "../models/types.js";
import { SigningKeyUtils } from "./SigningKeyUtils.js";

const { Config } = ObjectDecorators;

/**
 * Configuration options for `OAuthTokenUtils`.
 */
export interface OAuthServerConfig {
    /**
     * This authorization server's issuer identifier, stamped into every token's `iss` claim and required
     * on verification. Required before any token can be issued or verified (OIDC Core §2) — there is no
     * plaintext/no-issuer fallback, unlike this config block's other, genuinely optional settings.
     */
    issuer?: string;
    /** How long an issued access token is valid for. Default `"15m"`. */
    accessTokenTTL?: string;
    /** How long an issued `id_token` is valid for. Default `"15m"`. */
    idTokenTTL?: string;
    /** How long an issued refresh token is valid for. Default `"30d"`. */
    refreshTokenTTL?: string;
}

/**
 * Issues the access/ID tokens this authorization server hands out to registered `Client`s. Unlike
 * `TokenUtils` (which signs this library's own relying-party-oriented tokens with a single shared HMAC
 * secret and nests the full `JWTUser` under a `profile` claim), tokens issued here are signed with the
 * per-deployment RSA key from `SigningKeyUtils` and carry flat, spec-defined OAuth/OIDC claims
 * (`sub`/`aud`/`azp`/`client_id`/`scope`/`jti`) for verification by arbitrary third-party relying parties.
 *
 * Not exported from `src/auth/index.ts` — like `TokenUtils`, this is an internal service constructed by a
 * route's `@Init` hook (`this._objectFactory.newInstance(OAuthTokenUtils, {name, args: [signingKeyUtils]})`).
 *
 * @author Jean-Philippe Steinmetz
 */
export class OAuthTokenUtils {
    @Config("auth:oauth_server", {})
    protected config: OAuthServerConfig = {};

    private readonly signingKeyUtils: SigningKeyUtils;

    constructor(signingKeyUtils: SigningKeyUtils) {
        this.signingKeyUtils = signingKeyUtils;
    }

    /**
     * Returns the configured issuer, throwing a deployment-misconfiguration error if it's unset. OIDC Core
     * §2 mandates `iss` be present on every ID Token (and, by the same reasoning, every access token this
     * server signs and later verifies) — unlike `accessTokenTTL`/`idTokenTTL`/etc., there is no sane default
     * to silently fall back to, so this is enforced at the point of use rather than left optional.
     */
    private requireIssuer(): string {
        if (!this.config.issuer) {
            throw new ApiError(
                ApiErrors.INTERNAL_ERROR,
                500,
                "`auth:oauth_server:issuer` must be configured before this authorization server can issue or verify tokens.",
            );
        }
        return this.config.issuer;
    }

    /**
     * Builds the `jwt.SignOptions` passed through `JWTUtilsConfig.options` for a token signed with `kid`.
     * Declared as `any` (rather than a `JWTUtilsConfig["options"]` object literal) to avoid TypeScript's
     * excess-property check rejecting `algorithm`/`keyid` — `SignOptions`-only fields the stricter
     * `jwt.VerifyOptions` shape `JWTUtilsConfig.options` doesn't declare, even though `JWTUtils.createToken`
     * forwards them to `jwt.sign()` correctly.
     */
    private buildSignOptions(kid: string, expiresIn: number): any {
        return {
            algorithm: "RS256",
            algorithms: ["RS256"],
            keyid: kid,
            expiresIn,
            issuer: this.requireIssuer(),
        };
    }

    /**
     * Signs a new OAuth access token for `client`. When `user` is provided, the token is scoped to that
     * resource owner (`sub` = `user.uid`); otherwise (the `client_credentials` grant) it's scoped to the
     * client itself (`sub` = `client.clientId`).
     *
     * @param client The client the token is being issued to.
     * @param user The resource owner the token acts on behalf of, or `undefined` for `client_credentials`.
     * @param scope The final, already down-selected set of scopes to grant.
     */
    public async createAccessToken(
        client: Client,
        user: JWTUser | undefined,
        scope: string[],
    ): Promise<{ token: string; jti: string; expiresIn: number }> {
        const { kid, privateKeyPem } = await this.signingKeyUtils.getSigningMaterial();
        const expiresIn: number = parseDuration(this.config.accessTokenTTL, "sec") || 900;
        const jti: string = uuid.v4();
        const config: JWTUtilsConfig = { secret: privateKeyPem, options: this.buildSignOptions(kid, expiresIn) };

        // A synthetic minimal `JWTUser` for `client_credentials` grants, where there is no resource owner —
        // `JWTUtils.createToken` mandates a `user.uid`, and this keeps the resulting `profile` claim (an
        // artifact of reusing `createToken` — see its own doc comment) a faithful reflection of who/what the
        // token actually represents, rather than an arbitrary placeholder.
        const tokenUser: JWTUser = user ?? { uid: client.clientId, roles: [], scopes: scope };

        const token: string = await JWTUtils.createToken(config, tokenUser, {
            sub: user?.uid ?? client.clientId,
            aud: client.clientId,
            azp: client.clientId,
            client_id: client.clientId,
            scope: scope.join(" "),
            jti,
        });

        return { token, jti, expiresIn };
    }

    /**
     * Signs a new OIDC `id_token` asserting `user`'s identity to `client`. Carries only the claims required
     * by OIDC Core §2 — richer profile claims are exposed via the `/userinfo` endpoint (scope-gated), not
     * embedded here.
     *
     * @param client The client the token is being issued to.
     * @param user The resource owner the token asserts the identity of.
     * @param nonce The `nonce` the client supplied at `/authorize`, if any, echoed back for replay protection.
     */
    public async createIdToken(client: Client, user: JWTUser, nonce: string | undefined): Promise<string> {
        const { kid, privateKeyPem } = await this.signingKeyUtils.getSigningMaterial();
        const expiresIn: number = parseDuration(this.config.idTokenTTL, "sec") || 900;
        const config: JWTUtilsConfig = { secret: privateKeyPem, options: this.buildSignOptions(kid, expiresIn) };

        return JWTUtils.createToken(config, user, {
            sub: user.uid,
            aud: client.clientId,
            azp: client.clientId,
            auth_time: Math.floor(Date.now() / 1000),
            ...(nonce ? { nonce } : {}),
        });
    }

    /**
     * Generates a new opaque refresh token. Unlike access/ID tokens, a refresh token is not a JWT — it's a
     * cryptographically random value, returned to the caller exactly once, so its `tokenHash` (the only
     * form ever persisted, via `hashOpaqueToken()`) can never be reversed back into a usable credential from
     * a database read alone.
     *
     * @param familyId The rotation lineage this token belongs to. Omit to start a new lineage (the initial
     * grant from the `authorization_code` exchange); pass the previous token's `familyId` when rotating.
     */
    public createRefreshToken(familyId: string = uuid.v4()): { token: string; familyId: string; expiresIn: number } {
        const expiresIn: number = parseDuration(this.config.refreshTokenTTL, "sec") || 60 * 60 * 24 * 30;
        const token: string = crypto.randomBytes(32).toString("base64url");

        return { token, familyId, expiresIn };
    }

    /**
     * Verifies `token` as an access token this authorization server issued and returns its decoded claims,
     * or `undefined` for anything invalid, expired, or unverifiable — every caller (`BaseOAuthRevokeRoute`,
     * `BaseOAuthIntrospectRoute`, and `OAuthBearerStrategy`) treats every such failure identically, so there
     * is nothing for them to distinguish.
     *
     * Resolves the signing key named by the token's `kid` header via `SigningKeyUtils.getSigningMaterial()`
     * — deliberately not restricted to the currently *active* key, so a token signed just before a key
     * rotation still verifies correctly up until it naturally expires. Verification itself goes through
     * `JWTUtils.decodeToken()`, the same call whose `assertSafeAlgorithm()` guard protects every other token
     * this library decodes, pinned to `algorithms: ["RS256"]` so a token can't smuggle in a different
     * algorithm than this server ever signs with.
     */
    public async verifyAccessToken(token: string): Promise<any | undefined> {
        const decodedHeader: any = jwt.decode(token, { complete: true });
        const kid: string | undefined = decodedHeader?.header?.kid;
        if (!kid) {
            return undefined;
        }

        let publicKeyPem: string;
        try {
            const { privateKeyPem } = await this.signingKeyUtils.getSigningMaterial(kid);
            publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: "spki", format: "pem" });
        } catch (err) {
            return undefined;
        }

        const config: JWTUtilsConfig = {
            secret: publicKeyPem,
            options: { algorithms: ["RS256"], issuer: this.requireIssuer() },
        };

        try {
            return await JWTUtils.decodeToken(config, token);
        } catch (err) {
            return undefined;
        }
    }
}

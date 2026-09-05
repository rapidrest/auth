///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, JWTUtils, JWTUtilsConfig, ObjectDecorators } from "@rapidrest/core";
import parseDuration from "parse-duration";
import * as uuid from "uuid";
import { Client } from "../models/types.js";
import { SigningKeyUtils } from "./SigningKeyUtils.js";

const { Config } = ObjectDecorators;

/**
 * Configuration options for `OAuthTokenUtils`.
 */
export interface OAuthServerConfig {
    /** This authorization server's issuer identifier, stamped into every token's `iss` claim. */
    issuer?: string;
    /** How long an issued access token is valid for. Default `"15m"`. */
    accessTokenTTL?: string;
    /** How long an issued `id_token` is valid for. Default `"15m"`. */
    idTokenTTL?: string;
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
     * Builds the `jwt.SignOptions` passed through `JWTUtilsConfig.options` for a token signed with `kid`.
     * Declared as `any` (rather than a `JWTUtilsConfig["options"]` object literal) to avoid TypeScript's
     * excess-property check rejecting `algorithm`/`keyid` — `SignOptions`-only fields the stricter
     * `jwt.VerifyOptions` shape `JWTUtilsConfig.options` doesn't declare, even though `JWTUtils.createToken`
     * forwards them to `jwt.sign()` correctly. `issuer` is omitted entirely (not just left `undefined`) when
     * unconfigured — `jsonwebtoken` rejects a present-but-`undefined` `issuer` key outright.
     */
    private buildSignOptions(kid: string, expiresIn: number): any {
        return {
            algorithm: "RS256",
            algorithms: ["RS256"],
            keyid: kid,
            expiresIn,
            ...(this.config.issuer ? { issuer: this.config.issuer } : {}),
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
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ObjectDecorators } from "@rapidrest/core";
import { DocDecorators, HttpRequest, HttpResponse, ObjectFactory, RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { Client, OAuthRefreshToken, SigningKey } from "../models/types.js";
import { AccessTokenDenylist } from "../auth/AccessTokenDenylist.js";
import { ClientAuthUtils } from "../auth/ClientAuthUtils.js";
import { OAuthError, toOAuthError } from "../auth/OAuthError.js";
import { OAuthTokenUtils } from "../auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { getRequestData, hashOpaqueToken } from "../auth/shared.js";

const { Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Post, Request, Response } = RouteDecorators;

/**
 * Handles the OAuth 2.0 token revocation endpoint (RFC 7009). Accepts either a refresh token or an access
 * token in the `token` parameter — the optional `token_type_hint` is used only to pick which kind to try
 * first (RFC 7009 §2.1); the other kind is still tried if the hinted lookup doesn't find a match, since a
 * client is allowed to omit or get the hint wrong. Always responds `200`, whether or not `token` actually
 * existed, belonged to a different client, or was already revoked/expired — RFC 7009 §2.2 requires this
 * endpoint to never leak that distinction to the caller. Only a client-authentication failure is reported
 * as an error.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthRevokeRoute<C extends Client, R extends OAuthRefreshToken> {
    protected accessTokenDenylist?: AccessTokenDenylist;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    protected clientAuthUtils?: ClientAuthUtils;

    protected abstract clientClass: any;

    protected clientRepo?: RepoUtils<C>;

    protected oauthTokenUtils?: OAuthTokenUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected abstract refreshTokenClass: any;

    protected refreshTokenRepo?: RepoUtils<R>;

    protected abstract signingKeyClass: any;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.clientRepo && this.clientClass) {
            this.clientRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.clientClass.name,
                args: [this.clientClass],
            });
        }

        if (!this.refreshTokenRepo && this.refreshTokenClass) {
            this.refreshTokenRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.refreshTokenClass.name,
                args: [this.refreshTokenClass],
            });
        }

        if (!this.clientAuthUtils && this.clientRepo) {
            this.clientAuthUtils = await this._objectFactory.newInstance(ClientAuthUtils, {
                name: "default",
                args: [this.clientRepo],
            });
        }

        if (!this.accessTokenDenylist) {
            this.accessTokenDenylist = await this._objectFactory.newInstance(AccessTokenDenylist, { name: "default" });
        }

        if (!this.oauthTokenUtils && this.signingKeyClass) {
            const signingKeyRepo: RepoUtils<SigningKey> = await this._objectFactory.newInstance(RepoUtils, {
                name: this.signingKeyClass.name,
                args: [this.signingKeyClass],
            });
            const signingKeyUtils: SigningKeyUtils = await this._objectFactory.newInstance(SigningKeyUtils, {
                name: "default",
                args: [signingKeyRepo],
            });
            this.oauthTokenUtils = await this._objectFactory.newInstance(OAuthTokenUtils, {
                name: "default",
                args: [signingKeyUtils],
            });
        }
    }

    /**
     * Attempts to revoke `token` as a refresh token belonging to `client`. Returns whether a matching,
     * not-already-revoked token was found — purely for `revoke()`'s own fallback between token kinds, never
     * surfaced to the caller.
     */
    private async tryRevokeRefreshToken(token: string, client: Client): Promise<boolean> {
        const refreshToken = await this.refreshTokenRepo!.findOne(hashOpaqueToken(token), { ignoreACL: true });
        if (!refreshToken || refreshToken.clientId !== client.clientId || refreshToken.revoked) {
            return false;
        }

        await this.refreshTokenRepo!.update(
            { uid: refreshToken.uid, version: refreshToken.version, revoked: true, revokedAt: new Date() } as Partial<R>,
            refreshToken,
            { ignoreACL: true },
        );
        return true;
    }

    /**
     * Attempts to revoke `token` as an access token belonging to `client`, by denylisting its `jti` until
     * natural expiry. Returns whether a valid, matching token was found.
     */
    private async tryRevokeAccessToken(token: string, client: Client): Promise<boolean> {
        const claims = await this.oauthTokenUtils!.verifyAccessToken(token);
        if (!claims || claims.client_id !== client.clientId || typeof claims.jti !== "string") {
            return false;
        }

        const ttlSeconds: number = typeof claims.exp === "number" ? claims.exp - Math.floor(Date.now() / 1000) : 0;
        await this.accessTokenDenylist!.revoke(claims.jti, ttlSeconds);
        return true;
    }

    /**
     * Revokes the given token (RFC 7009). Always responds `200` with an empty body — whether or not `token`
     * actually existed, matched this client, or was already revoked. Only a missing `token` parameter or a
     * client-authentication failure is reported as an error.
     */
    @Summary("OAuth 2.0 token revocation")
    @Description(
        "Revokes a refresh token or access token (RFC 7009). Always succeeds regardless of whether the " +
            "token existed, to avoid leaking that information to the caller.",
    )
    @Returns([Object])
    @Post()
    public async revoke(@Request req: HttpRequest, @Response res: HttpResponse): Promise<any> {
        const { payload } = getRequestData(req, "");

        try {
            await this.rateLimiter?.checkAndIncrement(`oauth_revoke:${payload?.client_id ?? "unknown"}`, req);

            const client: Client = await this.clientAuthUtils!.authenticateClient(req);

            const token: string | undefined = payload?.token;
            if (!token) {
                throw new OAuthError("invalid_request", "token is required.");
            }

            const hint: string | undefined = payload?.token_type_hint;
            if (hint === "access_token") {
                (await this.tryRevokeAccessToken(token, client)) || (await this.tryRevokeRefreshToken(token, client));
            } else {
                (await this.tryRevokeRefreshToken(token, client)) || (await this.tryRevokeAccessToken(token, client));
            }

            res.status(200);
            res.json({});
            return undefined;
        } catch (err) {
            const oauthError = toOAuthError(err);
            res.status(oauthError.status);
            res.json({
                error: oauthError.error,
                ...(oauthError.errorDescription ? { error_description: oauthError.errorDescription } : {}),
            });
            return undefined;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ObjectDecorators } from "@rapidrest/core";
import { DocDecorators, HttpRequest, HttpResponse, ObjectFactory, RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { Client, ClientType, OAuthRefreshToken, SigningKey } from "../models/types.js";
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
 * Handles the OAuth 2.0 token introspection endpoint (RFC 7662). The caller must itself authenticate as a
 * confidential client — unlike `/revoke`, RFC 7662 introspection exposes information about *another*
 * caller's token (its scope, subject, client), so an unauthenticated or public-client caller (which can't
 * prove its identity) is never trusted with it. Returns `{active:false}` for anything invalid, expired,
 * revoked, or simply unrecognized — RFC 7662 §2.2 treats all of those identically, never as an error, so a
 * caller can't distinguish "this token doesn't exist" from "this token exists but isn't yours to see".
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthIntrospectRoute<C extends Client, R extends OAuthRefreshToken> {
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

    /** Returns an RFC 7662 introspection response for `token` as a refresh token, or `undefined` if it
     * isn't one (unknown hash, or found but revoked/expired). */
    private async introspectRefreshToken(token: string): Promise<any | undefined> {
        const refreshToken = await this.refreshTokenRepo!.findOne(hashOpaqueToken(token), { ignoreACL: true });
        if (!refreshToken || refreshToken.revoked || refreshToken.expiresAt.getTime() < Date.now()) {
            return undefined;
        }

        return {
            active: true,
            token_type: "refresh_token",
            client_id: refreshToken.clientId,
            scope: refreshToken.scope,
            exp: Math.floor(refreshToken.expiresAt.getTime() / 1000),
            ...(refreshToken.userUid ? { sub: refreshToken.userUid } : {}),
        };
    }

    /** Returns an RFC 7662 introspection response for `token` as an access token, or `undefined` if it
     * isn't one (invalid/expired signature, or a valid signature whose `jti` has been revoked). */
    private async introspectAccessToken(token: string): Promise<any | undefined> {
        const claims = await this.oauthTokenUtils!.verifyAccessToken(token);
        if (!claims || typeof claims.jti !== "string") {
            return undefined;
        }

        if (await this.accessTokenDenylist!.isRevoked(claims.jti)) {
            return undefined;
        }

        return {
            active: true,
            token_type: "access_token",
            client_id: claims.client_id,
            scope: claims.scope,
            sub: claims.sub,
            exp: claims.exp,
            iat: claims.iat,
        };
    }

    /**
     * Introspects the given token (RFC 7662). Always responds `200` — an unrecognized, expired, or revoked
     * token yields `{active:false}` rather than an error. Only a missing `token` parameter or a
     * client-authentication failure is reported as an error.
     */
    @Summary("OAuth 2.0 token introspection")
    @Description(
        "Reports whether a token is currently active, and its associated metadata (RFC 7662). Requires the " +
            "caller to authenticate as a confidential client.",
    )
    @Returns([Object])
    @Post()
    public async introspect(@Request req: HttpRequest, @Response res: HttpResponse): Promise<any> {
        res.setHeader("Cache-Control", "no-store");

        const { payload } = getRequestData(req, "");

        try {
            await this.rateLimiter?.checkAndIncrement(`oauth_introspect:${payload?.client_id ?? "unknown"}`, req);

            const client: Client = await this.clientAuthUtils!.authenticateClient(req);
            if (client.clientType !== ClientType.CONFIDENTIAL) {
                throw new OAuthError("invalid_client", "Token introspection requires a confidential client.", 401);
            }

            const token: string | undefined = payload?.token;
            if (!token) {
                throw new OAuthError("invalid_request", "token is required.");
            }

            const result = (await this.introspectRefreshToken(token)) ?? (await this.introspectAccessToken(token)) ?? { active: false };

            res.status(200);
            res.json(result);
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

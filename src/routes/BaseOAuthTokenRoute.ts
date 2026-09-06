///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { JWTUser, ObjectDecorators } from "@rapidrest/core";
import { DocDecorators, HttpRequest, HttpResponse, ObjectFactory, RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { AuthorizationCode, Client, ClientType, OAuthRefreshToken, SigningKey } from "../models/types.js";
import { ClientAuthUtils } from "../auth/ClientAuthUtils.js";
import { OAuthError, toOAuthError } from "../auth/OAuthError.js";
import { OAuthTokenUtils } from "../auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { getRequestData, hashOpaqueToken, verifyPkce } from "../auth/shared.js";

export { OAuthError } from "../auth/OAuthError.js";

const { Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Post, Request, Response } = RouteDecorators;

/**
 * Handles the OAuth 2.0 `/token` endpoint (RFC 6749 §3.2), dispatching by `grant_type`.
 * `authorization_code`, `refresh_token`, and `client_credentials` are implemented.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthTokenRoute<C extends Client, A extends AuthorizationCode, R extends OAuthRefreshToken> {
    protected abstract authorizationCodeClass: any;

    protected authorizationCodeRepo?: RepoUtils<A>;

    protected clientAuthUtils?: ClientAuthUtils;

    protected abstract clientClass: any;

    protected clientRepo?: RepoUtils<C>;

    protected oauthTokenUtils?: OAuthTokenUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected abstract refreshTokenClass: any;

    protected refreshTokenRepo?: RepoUtils<R>;

    protected abstract signingKeyClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

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

        if (!this.authorizationCodeRepo && this.authorizationCodeClass) {
            this.authorizationCodeRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.authorizationCodeClass.name,
                args: [this.authorizationCodeClass],
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
     * Builds the token response shared by every grant that issues on behalf of a resource owner: an access
     * token, an `id_token` when `openid` was granted, and — when `client.grantTypes` includes
     * `refresh_token` — a freshly persisted refresh token. `familyId` is omitted for a brand new grant (the
     * `authorization_code` exchange) and carried forward from the presented token when rotating.
     *
     * For an OIDC flow (`openid` in `scope`), a refresh token is only issued when `offline_access` was also
     * granted, per OIDC Core §11 ("Offline Access") — the client must explicitly request that scope to be
     * issued a token usable while the resource owner isn't present. This restriction is specific to OIDC;
     * a plain OAuth flow (no `openid`) is governed by RFC 6749 alone, where `client.grantTypes` is this
     * deployment's own sufficient basis for issuing one.
     */
    private async issueTokenResponse(client: Client, user: JWTUser, scope: string[], nonce: string | undefined, familyId?: string): Promise<any> {
        const access = await this.oauthTokenUtils!.createAccessToken(client, user, scope);

        const result: any = {
            access_token: access.token,
            token_type: "Bearer",
            expires_in: access.expiresIn,
            scope: scope.join(" "),
        };

        if (scope.includes("openid")) {
            result.id_token = await this.oauthTokenUtils!.createIdToken(client, user, nonce);
        }

        const canIssueRefreshToken = client.grantTypes.includes("refresh_token") && (!scope.includes("openid") || scope.includes("offline_access"));
        if (canIssueRefreshToken) {
            const refresh = this.oauthTokenUtils!.createRefreshToken(familyId);
            await this.refreshTokenRepo!.create(
                {
                    tokenHash: hashOpaqueToken(refresh.token),
                    clientId: client.uid,
                    userUid: user.uid,
                    scope: scope.join(" "),
                    familyId: refresh.familyId,
                    expiresAt: new Date(Date.now() + refresh.expiresIn * 1000),
                    revoked: false,
                } as Partial<R>,
                { ignoreACL: true },
            );
            result.refresh_token = refresh.token;
        }

        return result;
    }

    /**
     * Handles `grant_type=authorization_code`: redeems a one-time authorization code for an access token
     * (and an `id_token`, if `openid` was granted). The code is marked used via a single, optimistically-
     * locked `update()` *before* any token is issued — a concurrent second redemption of the same code loses
     * the version race and fails the same way an already-used code does, rather than also succeeding.
     */
    private async handleAuthorizationCodeGrant(req: HttpRequest, payload: any): Promise<any> {
        const client: Client = await this.clientAuthUtils!.authenticateClient(req);

        const code: string | undefined = payload?.code;
        const redirectUri: string | undefined = payload?.redirect_uri;
        const codeVerifier: string | undefined = payload?.code_verifier;

        if (!code || !redirectUri) {
            throw new OAuthError("invalid_request", "code and redirect_uri are required.");
        }

        const authCode: A | undefined = await this.authorizationCodeRepo!.findOne(hashOpaqueToken(code), {
            ignoreACL: true,
        });

        if (!authCode || authCode.clientId !== client.uid) {
            throw new OAuthError("invalid_grant", "The authorization code is invalid.");
        }

        if (authCode.used) {
            throw new OAuthError("invalid_grant", "This authorization code has already been used.");
        }

        if (authCode.expiresAt.getTime() < Date.now()) {
            throw new OAuthError("invalid_grant", "This authorization code has expired.");
        }

        if (authCode.redirectUri !== redirectUri) {
            throw new OAuthError("invalid_grant", "redirect_uri does not match the value used to obtain this code.");
        }

        if (authCode.codeChallenge) {
            if (!codeVerifier || !verifyPkce(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod ?? "plain")) {
                throw new OAuthError("invalid_grant", "code_verifier is missing or does not match the code_challenge.");
            }
        }

        try {
            await this.authorizationCodeRepo!.update(
                { uid: authCode.uid, version: authCode.version, used: true } as Partial<A>,
                authCode,
                { ignoreACL: true },
            );
        } catch (err) {
            // Lost the optimistic-locking race against a concurrent redemption of the same code.
            throw new OAuthError("invalid_grant", "This authorization code has already been used.");
        }

        const scope: string[] = authCode.scope ? authCode.scope.split(" ").filter(Boolean) : [];
        const user: JWTUser = { uid: authCode.userUid, roles: [], scopes: scope };

        return this.issueTokenResponse(client, user, scope, authCode.nonce);
    }

    /**
     * Handles `grant_type=refresh_token`: redeems a refresh token for a new access token (and `id_token`, if
     * `openid` was granted), rotating it into a new refresh token in the same `familyId`. Presenting a token
     * that has already been rotated/revoked (`revoked === true`) is treated as token theft (RFC 9700
     * §4.14.2) — the entire `familyId` is revoked, forcing the resource owner to re-authenticate from
     * scratch, rather than only rejecting the one reused token.
     */
    private async handleOAuthRefreshTokenGrant(req: HttpRequest, payload: any): Promise<any> {
        const client: Client = await this.clientAuthUtils!.authenticateClient(req);

        const rawToken: string | undefined = payload?.refresh_token;
        if (!rawToken) {
            throw new OAuthError("invalid_request", "refresh_token is required.");
        }

        const refreshToken: R | undefined = await this.refreshTokenRepo!.findOne(hashOpaqueToken(rawToken), {
            ignoreACL: true,
        });

        if (!refreshToken || refreshToken.clientId !== client.uid) {
            throw new OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        if (refreshToken.revoked) {
            await this.revokeTokenFamily(refreshToken.familyId);
            throw new OAuthError("invalid_grant", "This refresh token has already been used.");
        }

        if (refreshToken.expiresAt.getTime() < Date.now()) {
            throw new OAuthError("invalid_grant", "This refresh token has expired.");
        }

        const requestedScope: string[] | undefined = payload?.scope
            ? String(payload.scope).split(" ").filter(Boolean)
            : undefined;
        const grantedScope: string[] = refreshToken.scope ? refreshToken.scope.split(" ").filter(Boolean) : [];
        // RFC 6749 §6: a rotation may narrow scope, never widen it.
        const scope: string[] = requestedScope ? requestedScope.filter((s) => grantedScope.includes(s)) : grantedScope;
        if (requestedScope && scope.length !== requestedScope.length) {
            throw new OAuthError("invalid_scope", "Requested scope exceeds the scope originally granted.");
        }

        const user: JWTUser = { uid: refreshToken.userUid!, roles: [], scopes: scope };
        const result = await this.issueTokenResponse(client, user, scope, undefined, refreshToken.familyId);

        try {
            await this.refreshTokenRepo!.update(
                {
                    uid: refreshToken.uid,
                    version: refreshToken.version,
                    revoked: true,
                    revokedAt: new Date(),
                    ...(result.refresh_token ? { replacedByHash: hashOpaqueToken(result.refresh_token) } : {}),
                } as Partial<R>,
                refreshToken,
                { ignoreACL: true },
            );
        } catch (err) {
            // Lost the optimistic-locking race against a concurrent redemption of the same refresh token —
            // the new token was already issued above, so revoke the whole family rather than leave two
            // live refresh tokens outstanding for what should be a single-use credential.
            await this.revokeTokenFamily(refreshToken.familyId);
            throw new OAuthError("invalid_grant", "This refresh token has already been used.");
        }

        return result;
    }

    /** Revokes every non-revoked `OAuthRefreshToken` sharing `familyId` — the RFC 9700 §4.14.2 response to a
     * detected replay of an already-rotated-out token. */
    private async revokeTokenFamily(familyId: string): Promise<void> {
        const tokens: R[] = await this.refreshTokenRepo!.find({ familyId }, { ignoreACL: true, skipCache: true });
        const now = new Date();
        for (const token of tokens) {
            if (token.revoked) {
                continue;
            }
            await this.refreshTokenRepo!.update(
                { uid: token.uid, version: token.version, revoked: true, revokedAt: now } as Partial<R>,
                token,
                { ignoreACL: true },
            );
        }
    }

    /**
     * Handles `grant_type=client_credentials` (RFC 6749 §4.4): issues an access token identifying the client
     * itself, with no resource owner. Requires a confidential client — a public client has no way to prove
     * its identity, and this grant has no PKCE-equivalent fallback. Never issues a refresh token (RFC 6749
     * §4.4.3) or an `id_token` (there is no resource owner to assert an identity for), regardless of what the
     * client is otherwise configured to receive.
     */
    private async handleClientCredentialsGrant(req: HttpRequest, payload: any): Promise<any> {
        const client: Client = await this.clientAuthUtils!.authenticateClient(req);

        if (client.clientType !== ClientType.CONFIDENTIAL) {
            throw new OAuthError("unauthorized_client", "The client_credentials grant requires a confidential client.");
        }

        if (!client.grantTypes.includes("client_credentials")) {
            throw new OAuthError("unauthorized_client", "This client is not authorized to use the client_credentials grant.");
        }

        const clientScope: string[] = client.scope ? client.scope.split(" ").filter(Boolean) : [];
        const requestedScope: string[] | undefined = payload?.scope
            ? String(payload.scope).split(" ").filter(Boolean)
            : undefined;
        const scope: string[] = requestedScope ? requestedScope.filter((s) => clientScope.includes(s)) : clientScope;
        if (requestedScope && scope.length !== requestedScope.length) {
            throw new OAuthError("invalid_scope", "Requested scope exceeds the scope registered for this client.");
        }

        const access = await this.oauthTokenUtils!.createAccessToken(client, undefined, scope);

        return {
            access_token: access.token,
            token_type: "Bearer",
            expires_in: access.expiresIn,
            scope: scope.join(" "),
        };
    }

    /**
     * Dispatches an incoming token request by `grant_type`. Always sets `Cache-Control: no-store` and
     * `Pragma: no-cache` (RFC 6749 §5.1), and always responds with a `2xx`/`4xx` JSON body directly (never
     * throws past this point) so error responses use the RFC 6749 §5.2 shape rather than this library's
     * usual `ApiError` envelope.
     */
    @Summary("OAuth 2.0 token endpoint")
    @Description("Exchanges an authorization grant (authorization_code, refresh_token, client_credentials) for an access token.")
    @Returns([Object])
    @Post()
    public async token(@Request req: HttpRequest, @Response res: HttpResponse): Promise<any> {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Pragma", "no-cache");

        const { payload } = getRequestData(req, "");

        try {
            await this.rateLimiter?.checkAndIncrement(`oauth_token:${payload?.client_id ?? "unknown"}`, req);

            let result: any;
            switch (payload?.grant_type) {
                case "authorization_code":
                    result = await this.handleAuthorizationCodeGrant(req, payload);
                    break;
                case "refresh_token":
                    result = await this.handleOAuthRefreshTokenGrant(req, payload);
                    break;
                case "client_credentials":
                    result = await this.handleClientCredentialsGrant(req, payload);
                    break;
                default:
                    throw new OAuthError("unsupported_grant_type", `Unsupported grant_type: "${payload?.grant_type}".`);
            }

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

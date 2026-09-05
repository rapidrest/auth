///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ApiError, JWTUser, ObjectDecorators } from "@rapidrest/core";
import { DocDecorators, HttpRequest, HttpResponse, ObjectFactory, RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { AuthorizationCode, Client, SigningKey } from "../models/types.js";
import { ClientAuthUtils } from "../auth/ClientAuthUtils.js";
import { OAuthTokenUtils } from "../auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { getRequestData, hashOpaqueToken, verifyPkce } from "../auth/shared.js";

const { Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Post, Request, Response } = RouteDecorators;

/**
 * An OAuth 2.0 token-endpoint error, per RFC 6749 §5.2 — a distinct wire shape (`{error,
 * error_description}`) from this library's usual `ApiError` envelope, since the format here is spec-mandated
 * rather than this library's own convention.
 */
export class OAuthError extends Error {
    public readonly error: string;
    public readonly errorDescription?: string;
    public readonly status: number;

    constructor(error: string, errorDescription?: string, status: number = 400) {
        super(errorDescription ?? error);
        this.error = error;
        this.errorDescription = errorDescription;
        this.status = status;
    }
}

/**
 * Handles the OAuth 2.0 `/token` endpoint (RFC 6749 §3.2), dispatching by `grant_type`. Only the
 * `authorization_code` grant is implemented so far — `refresh_token` and `client_credentials` are added in
 * later phases, which extend this same class's `token()` dispatch.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthTokenRoute<C extends Client, A extends AuthorizationCode> {
    protected abstract authorizationCodeClass: any;

    protected authorizationCodeRepo?: RepoUtils<A>;

    protected clientAuthUtils?: ClientAuthUtils;

    protected abstract clientClass: any;

    protected clientRepo?: RepoUtils<C>;

    protected oauthTokenUtils?: OAuthTokenUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

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

    /** Maps any error thrown while handling a grant into the RFC 6749 §5.2 error shape. */
    private toOAuthError(err: unknown): OAuthError {
        if (err instanceof OAuthError) {
            return err;
        }
        if (err instanceof ApiError) {
            const error = err.status === 401 ? "invalid_client" : err.status >= 500 ? "server_error" : "invalid_request";
            return new OAuthError(error, err.message, err.status);
        }
        return new OAuthError("server_error", undefined, 500);
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

        if (!authCode || authCode.clientId !== client.clientId) {
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

        const access = await this.oauthTokenUtils!.createAccessToken(client, user, scope);

        const result: any = {
            access_token: access.token,
            token_type: "Bearer",
            expires_in: access.expiresIn,
            scope: scope.join(" "),
        };

        if (scope.includes("openid")) {
            result.id_token = await this.oauthTokenUtils!.createIdToken(client, user, authCode.nonce);
        }

        return result;
    }

    /**
     * Dispatches an incoming token request by `grant_type`. Always sets `Cache-Control: no-store` and
     * `Pragma: no-cache` (RFC 6749 §5.1), and always responds with a `2xx`/`4xx` JSON body directly (never
     * throws past this point) so error responses use the RFC 6749 §5.2 shape rather than this library's
     * usual `ApiError` envelope.
     */
    @Summary("OAuth 2.0 token endpoint")
    @Description("Exchanges an authorization grant (currently: authorization_code) for an access token.")
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
                default:
                    throw new OAuthError("unsupported_grant_type", `Unsupported grant_type: "${payload?.grant_type}".`);
            }

            res.status(200);
            res.json(result);
            return undefined;
        } catch (err) {
            const oauthError = this.toOAuthError(err);
            res.status(oauthError.status);
            res.json({
                error: oauthError.error,
                ...(oauthError.errorDescription ? { error_description: oauthError.errorDescription } : {}),
            });
            return undefined;
        }
    }
}

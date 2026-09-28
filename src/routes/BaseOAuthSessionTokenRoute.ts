///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { ApiError, JWTUser, ObjectDecorators } from "@rapidrest/core";
import {
    ApiErrorMessages,
    ApiErrors,
    AuthMiddleware,
    DocDecorators,
    HttpRequest,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { SigningKey, User } from "../models/types.js";
import { AccessTokenDenylist } from "../auth/AccessTokenDenylist.js";
import { OAuthBearerStrategy } from "../auth/OAuthBearerStrategy.js";
import { OAuthTokenUtils } from "../auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";
import { TokenUtils } from "../auth/TokenUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Post, Request } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/** Shared with `BaseOAuthUserInfoRoute` — see that class's own doc comment for why this is a fixed,
 * never-per-subclass name: there is only ever one flavor of access token this authorization server
 * issues. Registering under the same name here is intentional and harmless (`AuthMiddleware.register()`
 * simply (re)sets a map entry by name) - whichever of this route or `BaseOAuthUserInfoRoute` happens to
 * initialize first wins the actual registration, and every other route just resolves the strategy by name
 * at request time, long after every route's `@Init` has run. */
const STRATEGY_NAME = "oauth_bearer";

/**
 * Exchanges a presented OAuth 2.0 access token (`Authorization: Bearer`, verified via the same
 * `OAuthBearerStrategy` that protects `/userinfo`) for one of this library's own ordinary session JWTs -
 * the exact token every other sign-in route (password/MFA/passkey/refresh/OIDC) hands back via
 * `TokenUtils.createAuthResult()`.
 *
 * This exists for a native app (see e.g. `tauri-client`) that signs in entirely through the standard OAuth
 * 2.0 + PKCE authorization-code flow this server already exposes (`/oauth/authorize`, `/oauth/token`, both
 * unmodified) but then also needs to call this deployment's ordinary, `JWTStrategy`-protected `/api/...`
 * routes - which only ever accept a plain session `jwt`, never an OAuth access token directly. Widening
 * every such route to accept `oauth_bearer` was deliberately rejected: those routes live in `service-core`
 * (shared far beyond this library) and would need a new `@rapidrest/auth` dependency they don't have today,
 * and - more fundamentally - an OAuth access token carries no `roles` claim at all
 * (`OAuthBearerStrategy.authenticate()` always mints `{ roles: [] }`), so accepting it directly on a
 * role-gated route would silently authorize as "no roles" rather than fail loudly. This route sidesteps
 * both problems in one small, local place: it looks up the real `User` record behind the token's `sub` and
 * mints a normal session JWT carrying that user's actual `roles`.
 *
 * Deliberately calls `createAuthResult()` with no `res` (no `Set-Cookie` at all - a native app has no
 * cookie jar this endpoint should be writing into; the response body's `token` is the only thing that
 * matters here) and no `authMethod` (this exchange verifies no new credential of its own - the actual
 * credential check already happened when the access token's underlying authorization was granted through
 * the interactive `/oauth/authorize` flow - so, exactly like `BaseAuthRefreshRoute`'s routine refresh, it
 * must never fire a `SIGNED_IN` audit entry; see `TokenUtils.createAuthResult()`'s own doc comment on that
 * gating). Only `token` is ever returned to the caller - never `refresh` - since a native app's long-term
 * credential remains its own OAuth refresh token, renewed via the unmodified `/oauth/token`
 * `refresh_token` grant, not this session-refresh token.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthSessionTokenRoute<U extends User> {
    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    protected oauthTokenUtils?: OAuthTokenUtils;

    protected abstract signingKeyClass: any;

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    protected abstract userClass: any;

    protected userRepo?: RepoUtils<U>;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this.authMiddleware) {
            throw new Error("authMiddleware is not set.");
        }
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
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

        const accessTokenDenylist: AccessTokenDenylist = await this._objectFactory.newInstance(AccessTokenDenylist, {
            name: "default",
        });
        const strategy: OAuthBearerStrategy = await this._objectFactory.newInstance(OAuthBearerStrategy, {
            name: STRATEGY_NAME,
            args: [STRATEGY_NAME, this.oauthTokenUtils, accessTokenDenylist],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Exchanges the presented OAuth access token for an ordinary session JWT. `oauthUser.uid` (the token's
     * `sub`) is trusted only to look up the real account - the token's own `roles`/`scopes` (always `[]`/
     * its OAuth `scope`) are never carried over into the minted session JWT; the account's actual `roles`
     * and this deployment's configured `auth:default_scopes` are used instead, exactly as every other
     * sign-in route does.
     */
    @Summary("OAuth Session Token")
    @Description(
        "Exchanges the presented OAuth 2.0 access token for an ordinary session JWT accepted by this " +
            "server's own session-authenticated routes. Returns only `token` - never `refresh` - since a " +
            "native client's long-term credential remains its own OAuth refresh token.",
    )
    @Returns([Object])
    @Auth([STRATEGY_NAME])
    @Post()
    public async sessionToken(@AuthUser oauthUser: JWTUser, @Request req: HttpRequest): Promise<{ token: string }> {
        const user: U | undefined = await this.userRepo!.findOne(oauthUser.uid, { ignoreACL: true });
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        const result = await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req);

        return { token: result.token };
    }
}

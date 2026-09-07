////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2020-2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUtils, ObjectDecorators, UserUtils, type JWTUser, type JWTUtilsConfig } from "@rapidrest/core";
import {
    ApiErrorMessages,
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { AuthResult, User } from "../models/types.js";
import { TokenUtils } from "../auth/TokenUtils.js";
const { Description, Returns, Summary } = DocDecorators;
const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Auth, Get, Post, Request, RequiresTrustedRole, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/** Matches `JWTStrategyOptions.cookieName`'s hardcoded default — see `JWTStrategy.ts`. */
const SESSION_COOKIE_NAME = "jwt";

/** Holds the impersonator's own session token while they're viewing as someone else. */
const IMPERSONATOR_COOKIE_NAME = "jwt_impersonator";

export interface ImpersonateInput {
    userUid: string;
}

/**
 * A set of routes allowing a trusted user the ability to temporarily impersonate any other user in the system
 * without needing to explicitly log in to that user's account or know their login credentials.
 *
 * This mints a (non-elevated) token for the target user with the same roles and scopes that the target user would
 * acquire after a normal login.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseImpersonationRoute<U extends User> {
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Config("auth")
    private authConfig?: JWTUtilsConfig;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    @Config("trusted_roles", ["admin"])
    private trustedRoles: string[] = ["admin"];

    @Logger
    private logger: any;

    protected userRepo?: RepoUtils<U>;

    @Init
    protected async initialize() {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * `Secure` is only added in production since a real deployment sits behind HTTPS, but local dev (and this
     * route's own tests) commonly run over plain HTTP, where a `Secure` cookie is silently dropped by the
     * browser entirely, breaking the very session it's meant to set.
     */
    private buildCookie(name: string, token: string): string {
        const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
        return `${name}=${token}; Path=/; HttpOnly; SameSite=Lax${secure}`;
    }

    private buildClearCookie(name: string): string {
        return `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`;
    }

    @Summary("Impersonate a user")
    @Description(
        "Trusted-role-only. Mints a token for the given user with no roles of its own — the impersonated " +
            "session sees exactly what that user's own permissions grant, nothing more — stashes the caller's " +
            "own current session so it can be restored later, and sets the new token as the active jwt cookie.",
    )
    @Returns([Object])
    @Auth(["jwt"])
    @Post("/impersonate")
    @RequiresTrustedRole()
    public async impersonate(
        body: ImpersonateInput,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
        @AuthUser user: JWTUser,
    ): Promise<AuthResult> {
        if (!body?.userUid) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, ApiErrorMessages.INVALID_REQUEST);
        }
        if (!this.authConfig) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const currentToken: string | undefined = req.cookies?.[SESSION_COOKIE_NAME];
        if (currentToken) {
            res.appendHeader("Set-Cookie", this.buildCookie(IMPERSONATOR_COOKIE_NAME, currentToken));
        }

        // Retrieve the requested user to impersonate. The caller has already been authorized by
        // @RequiresTrustedRole() above, so this lookup is exempt from the target user's own ACL.
        const toImpersonate: User | undefined = await this.userRepo?.findOne(body.userUid, { ignoreACL: true });
        if (!toImpersonate) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }
        const result = await this.tokenUtils!.createAuthResult(
            toImpersonate,
            this.defaultScopes,
            req,
            res,
            false,
            true,
        );

        this.logger?.warn(`[Impersonation] '${user.uid}' started impersonating '${body.userUid}'.`);

        return result;
    }

    @Summary("Stop impersonating")
    @Description("Restores the caller's own session from the stashed impersonator cookie, if one is present.")
    @Returns([Object])
    @Auth(["jwt"])
    @Get("/impersonate/stop")
    public async stopImpersonating(
        @Request req: HttpRequest,
        @Response res: HttpResponse,
        @AuthUser user: JWTUser,
    ): Promise<{ restored: boolean }> {
        const impersonatorToken: string | undefined = req.cookies?.[IMPERSONATOR_COOKIE_NAME];
        if (!impersonatorToken) {
            return { restored: false };
        }

        res.appendHeader("Set-Cookie", this.buildCookie(SESSION_COOKIE_NAME, impersonatorToken));
        res.appendHeader("Set-Cookie", this.buildClearCookie(IMPERSONATOR_COOKIE_NAME));

        this.logger?.warn(`[Impersonation] Stopped impersonating (was acting as '${user.uid}').`);

        return { restored: true };
    }
}

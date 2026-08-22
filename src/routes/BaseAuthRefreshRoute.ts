///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    RouteDecorators,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    RepoUtils,
    ObjectFactory,
    ApiErrors,
    ApiErrorMessages,
} from "@rapidrest/service-core";
import { ApiError, JWTUtils, ObjectDecorators } from "@rapidrest/core";
import { AuthResult, User } from "../models/types.js";
import { TokenCookieConfig, TokenUtils } from "../auth/TokenUtils.js";

const { Summary, Description, Returns } = DocDecorators;
const { Config, Init, Inject } = ObjectDecorators;
const { Get, Post, Response, Request } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthRefreshRoute<U extends User> {
    protected abstract readonly userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Config("auth")
    protected authConfig: any;

    @Config("auth:cookie:refresh", { name: "refresh" })
    protected cookieConfig: TokenCookieConfig = { name: "refresh" };

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    protected userRepo?: RepoUtils<U>;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    protected async initialize() {
        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory!.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * Scans the provided request object for an authentication token this strategy can process.
     * @param req The request to scan for an auth token.
     * @returns The auth token if found, otherwise `undefined`.
     */
    private getToken(req: HttpRequest): string | undefined {
        // The request body could be a string or an object. `typeof null === "object"` in JS, so `req.body`
        // must also be truthy-checked here - otherwise a `null` body (a common shape for a bodyless
        // request) would crash on `req.body.token` instead of falling through to the cookie checks below.
        if (typeof req.body === "string") {
            return req.body;
        }

        // Now check if the request body is an object with a 'token' property
        if (req.body && typeof req.body === "object" && req.body.token) {
            return req.body.token;
        }

        // If the token wasn't provided in the request body check for the refresh cookie. `req.signedCookies`
        // is checked unconditionally (not gated on `cookieConfig.secure`, which controls the unrelated
        // HTTPS-only cookie attribute) since nothing here actually writes the refresh cookie as a signed
        // cookie - `TokenUtils` sets it via a raw `Set-Cookie` header - so this is purely forward-compatible
        // with a cookie-parser configured to populate `signedCookies` upstream.
        // TODO: Decrypt the signed cookie?
        if (this.cookieConfig.name && req.signedCookies) {
            const cookieToken = req.signedCookies[this.cookieConfig.name];
            if (cookieToken) {
                return cookieToken;
            }
        }

        if (this.cookieConfig.name && req.cookies) {
            const cookieToken = req.cookies[this.cookieConfig.name];
            if (cookieToken) {
                return cookieToken;
            }
        }

        return undefined;
    }

    @Summary("Authenticate")
    @Description("Authenticates the user using a provided refresh token.")
    @Returns([AuthResult])
    @Get()
    @Post()
    public async authenticate(@Request req: HttpRequest, @Response res: HttpResponse): Promise<AuthResult> {
        // Grab the refresh token from the request
        const refresh: string | undefined = this.getToken(req);
        if (!refresh) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        // Decode the provided refresh token. `decodeToken()` verifies the signature (via `jwt.verify()`)
        // despite its name - not a trusting bare decode.
        let payload: any = undefined;
        try {
            payload = await JWTUtils.decodeToken(this.authConfig, refresh);
        } catch (err: any) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        // Make sure the payload is valid and matches the session data
        if (!payload || payload.userUid !== req.session?.userUid || payload.uid !== req.session?.refreshUid) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        // Retrieve the user account referenced in the token
        let user: User | undefined = await this.userRepo!.findOne(payload.userUid, { ignoreACL: true });
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        // `BaseAccountRoute.revokeSessions()` ("log out everywhere") sets this to reject every refresh token
        // issued before that call, even one that's otherwise validly signed and session-bound above - `iat`
        // is in seconds per the JWT spec, `sessionsRevokedAt` in epoch milliseconds to match `Date.now()`
        // usage elsewhere in this codebase (e.g. `TokenUtils.createAuthResult`).
        if (user.sessionsRevokedAt && payload.iat * 1000 < user.sessionsRevokedAt) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        const result: AuthResult = await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req, res);
        return result;
    }
}

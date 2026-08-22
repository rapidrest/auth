///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { EventUtils, JWTUser, JWTUtils, JWTUtilsConfig, ObjectDecorators } from "@rapidrest/core";
import { HttpRequest, NetUtils, type HttpResponse } from "@rapidrest/service-core";
import parseDuration from "parse-duration";
import * as uuid from "uuid";
import { AuthResult } from "../models/types.js";
import { AuthEventType } from "./events.js";

const { Config } = ObjectDecorators;

/**
 * Configuration options controlling the `Set-Cookie` header written alongside a newly issued JWT.
 */
export interface TokenCookieConfig {
    /**
     * The name of the cookie. Should match the `cookieName` configured for `JWTStrategy` if the
     * cookie is meant to be used for authenticating subsequent requests.
     */
    name: string;
    /** The `Path` attribute of the cookie. Default is `/`. */
    path?: string;
    /** The `Max-Age` attribute of the cookie, in seconds. Omitted (session cookie) if not set. */
    maxAge?: number;
    /** The `SameSite` attribute of the cookie. Default is `Lax`. */
    sameSite?: "Strict" | "Lax" | "None";
    /** Set to `false` to omit the `Secure` (HTTPS only) attribute. Default is `true`. */
    secure?: boolean;
    /** Set to `false` to omit the `HttpOnly` attribute. Default is `true`. */
    httpOnly?: boolean;
}

export interface CookieConfig {
    /** Set to `true` to also return the issued JWT as a `Set-Cookie` header. Default is `false`. */
    enabled?: boolean;
    /** Cookie configuration for the access token. */
    access: TokenCookieConfig;
    /** Cookie configuration for the refresh token. */
    refresh: TokenCookieConfig;
}

/**
 * Central utility for issuing the JWT access tokens returned by the various authentication routes
 * (Basic, MFA, OTP, TOTP, FIDO2, Passkey, OIDC, Registration). In addition to signing the token via
 * `JWTUtils`, it optionally writes the token as a `Set-Cookie` header so that browser clients can
 * rely on cookie-based authentication instead of having to store and attach the token themselves.
 *
 * @author Jean-Philippe Steinmetz
 */
export class TokenUtils {
    @Config("auth:cookie", { enabled: false, access: { name: "jwt" }, refresh: { name: "refresh" } })
    protected cookieConfig: CookieConfig = { enabled: false, access: { name: "jwt" }, refresh: { name: "refresh" } };

    @Config("auth")
    private jwtConfig?: any;

    @Config("trusted_proxies", [])
    protected trustedProxies: string[] = [];

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    /**
     * Builds the `Set-Cookie` header value for the given token using the configured cookie options. Pass
     * an empty string to build a header that immediately expires/clears the cookie instead.
     */
    protected buildCookie(token: string, config: TokenCookieConfig): string {
        const clearing: boolean = token === "";
        const parts: string[] = [
            `${config.name ?? "jwt"}=${token}`,
            `Path=${config.path ?? "/"}`,
            `SameSite=${config.sameSite ?? "Lax"}`,
        ];
        if (clearing) {
            parts.push("Max-Age=0");
        } else if (config.maxAge !== undefined) {
            parts.push(`Max-Age=${config.maxAge}`);
        }
        if (config.httpOnly !== false) {
            parts.push("HttpOnly");
        }
        if (config.secure !== false) {
            parts.push("Secure");
        }
        return parts.join("; ");
    }

    /**
     * Clears the cookie previously set by `createAuthResult()`, when cookie issuance is enabled via the
     * `auth:cookie` configuration. An `HttpOnly` cookie can only ever be cleared by the server writing a
     * new `Set-Cookie` header — client-side JavaScript has no ability to read or overwrite it — so a
     * logout flow that relies on cookie-based auth must call this (see `BaseAuthLogoutRoute`) rather than
     * attempting to clear the cookie from the frontend.
     *
     * @param res The response to write the clearing `Set-Cookie` header to. When omitted, nothing happens.
     */
    public clearToken(res?: HttpResponse): void {
        if (res && this.cookieConfig?.enabled) {
            // `appendHeader()`, not `setHeader()`: the latter replaces any value already set for the same
            // header key, so a second `setHeader("Set-Cookie", ...)` call would silently clobber the first
            // and only the refresh cookie would actually be cleared, leaving the access-token cookie alive
            // after "logout".
            res.appendHeader("Set-Cookie", this.buildCookie("", this.cookieConfig.access));
            res.appendHeader("Set-Cookie", this.buildCookie("", this.cookieConfig.refresh));
        }
    }

    /**
     * Signs a new refresh token for the given user. Optionally, stores the refresh `uid` in the session
     * in order to verify future auth attempts (when sessions are enabled).
     */
    public async createRefreshToken(user: JWTUser, req?: HttpRequest): Promise<string> {
        const expires: number = parseDuration(this.jwtConfig.refresh?.expiresIn, "sec") || 1209600; // 14 days
        const uid: string = uuid.v4();
        const config: any = {
            secret: this.jwtConfig.secret,
            options: {
                ...this.jwtConfig.options,
                expiresIn: expires,
            },
        };

        const result: string = await JWTUtils.createToken(config, { uid: user.uid } as any, {
            uid,
            userUid: user.uid,
        });

        // Store the refresh uid in the session
        if (req?.session) {
            req.session.refreshUid = uid;
        }

        return result;
    }

    /**
     * Derives the `JWTUser` that should actually be signed into a token, without mutating the object the
     * caller passed in: an elevated token is stamped with the current time, while a non-elevated token has
     * every trusted role stripped (only an elevated token may carry them). Pulled out so `createAuthResult()`
     * can return a `user` that accurately reflects what its `token` actually grants, rather than the raw,
     * unprocessed input.
     */
    private resolveTokenUser(user: JWTUser, elevated: boolean): JWTUser {
        if (elevated) {
            return { ...user, elevated: Date.now() };
        }
        return { ...user, roles: (user.roles ?? []).filter((role) => !this.trustedRoles.includes(role)) };
    }

    /**
     * Signs a new JWT access token for the given user.
     *
     * @param user The user to encode into the token's payload.
     * @param scopes The scopes to grant the issued token.
     * @param elevated Set to `true` to create an elevated token that includes trusted roles. Default is `false`.
     * @returns The signed JWT.
     */
    public async createAccessToken(user: JWTUser, scopes: string[], elevated: boolean = false): Promise<string> {
        const config: any = {
            secret: this.jwtConfig.secret,
            options: {
                ...this.jwtConfig.options,
            },
        };

        // When issuing an elevated token, we may have a different token expiration configured. Only
        // override the default when a valid duration is actually configured.
        if (elevated) {
            const elevatedExpiresIn: number | null = parseDuration(this.jwtConfig.elevated?.expiresIn, "sec");
            if (elevatedExpiresIn) {
                config.options.expiresIn = elevatedExpiresIn;
            }
        }

        const token: string = await JWTUtils.createToken(config, {
            ...this.resolveTokenUser(user, elevated),
            scopes,
        });

        return token;
    }

    /**
     * Signs new JWT access and refresh tokens for the given user, and optionally issues a cookie.
     * @param user The user to create an auth token for.
     * @param scopes The scopes to grant the user.
     * @param req The original request.
     * @param res The response to set the auth cookie for (if desired).
     * @param elevated Set to `true` to create an elevated access token that includes trusted roles. Default is `false`.
     */
    public async createAuthResult(
        user: JWTUser,
        scopes: string[],
        req?: HttpRequest,
        res?: HttpResponse,
        elevated: boolean = false,
    ): Promise<AuthResult> {
        const refresh: string = await this.createRefreshToken(user, req);
        const token: string = await this.createAccessToken(user, scopes, elevated);

        if (res && this.cookieConfig?.enabled) {
            res.appendHeader("Set-Cookie", this.buildCookie(token, this.cookieConfig.access));
            res.appendHeader("Set-Cookie", this.buildCookie(refresh, this.cookieConfig.refresh));
        }

        const ip: string | undefined = req ? NetUtils.getIPAddress(req, this.trustedProxies) : undefined;

        // If sessions are available, store some useful information about the user
        if (req?.session) {
            const now = Date.now();
            req.session.ip = ip;
            req.session.lastAccess = now;
            if (elevated) {
                req.session.lastElevated = now;
            }
            req.session.lastLogin = req.session.lastLogin ?? now;
            req.session.userUid = user.uid;
        }

        EventUtils.record({
            type: AuthEventType.SESSION_CREATED,
            userUid: user.uid,
            ip,
            path: req?.path,
            elevated,
            scopes,
        }).catch(() => undefined);

        return {
            refresh,
            token,
            // Reflects what `token` actually grants (roles stripped/elevated timestamp stamped as
            // appropriate), not the raw input — a caller reading `AuthResult.user.roles` must see the same
            // privileges the accompanying token itself carries.
            user: this.resolveTokenUser(user, elevated),
        };
    }
}

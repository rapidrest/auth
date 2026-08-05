///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, JWTUtils, JWTUtilsConfig, ObjectDecorators } from "@rapidrest/core";
import type { HttpResponse } from "@rapidrest/service-core";

const { Config } = ObjectDecorators;

/**
 * Configuration options controlling the `Set-Cookie` header written alongside a newly issued JWT.
 */
export interface TokenCookieConfig {
    /** Set to `true` to also return the issued JWT as a `Set-Cookie` header. Default is `false`. */
    enabled?: boolean;
    /**
     * The name of the cookie. Should match the `cookieName` configured for `JWTStrategy` if the
     * cookie is meant to be used for authenticating subsequent requests. Default is `jwt`.
     */
    name?: string;
    /** The `Path` attribute of the cookie. Default is `/`. */
    path?: string;
    /** The `Max-Age` attribute of the cookie, in seconds. Omitted (session cookie) if not set. */
    maxAge?: number;
    /** The `SameSite` attribute of the cookie. Default is `Lax`. */
    sameSite?: "Strict" | "Lax" | "None";
    /** Set to `true` to mark the cookie `Secure` (HTTPS only). Default is `false`. */
    secure?: boolean;
    /** Set to `false` to omit the `HttpOnly` attribute. Default is `true`. */
    httpOnly?: boolean;
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
    @Config("auth:cookie", { enabled: false })
    protected cookieConfig: TokenCookieConfig = { enabled: false };

    /**
     * Signs a new JWT for the given user and, when cookie issuance is enabled via the `auth:cookie`
     * configuration, sets it as a `Set-Cookie` header on the provided response.
     *
     * @param jwtConfig The JWT configuration to use for signing (the `auth` configuration block).
     * @param user The user to encode into the token's payload.
     * @param scopes The scopes to grant the issued token.
     * @param res The response to write the `Set-Cookie` header to. When omitted, no cookie is set
     * regardless of configuration.
     * @returns The signed JWT.
     */
    public async createToken(
        jwtConfig: JWTUtilsConfig,
        user: JWTUser,
        scopes: string[],
        res?: HttpResponse,
    ): Promise<string> {
        const token: string = await JWTUtils.createToken(jwtConfig, {
            ...user,
            scopes,
        });

        if (res && this.cookieConfig?.enabled) {
            // NOTE: the underlying HTTP adapters currently back `res.setHeader()` with a single-value
            // map, so only one `Set-Cookie` header can be represented per response. This is safe for
            // every route that issues a token today since none of them also establish a new session
            // (see `sessionMiddleware`) in the same request, but a route that did both would have one
            // `Set-Cookie` silently clobber the other.
            res.setHeader("Set-Cookie", this.buildCookie(token));
        }

        return token;
    }

    /**
     * Builds the `Set-Cookie` header value for the given token using the configured cookie options.
     */
    protected buildCookie(token: string): string {
        const cfg: TokenCookieConfig = this.cookieConfig ?? {};
        const parts: string[] = [
            `${cfg.name ?? "jwt"}=${token}`,
            `Path=${cfg.path ?? "/"}`,
            `SameSite=${cfg.sameSite ?? "Lax"}`,
        ];
        if (cfg.maxAge !== undefined) {
            parts.push(`Max-Age=${cfg.maxAge}`);
        }
        if (cfg.httpOnly !== false) {
            parts.push("HttpOnly");
        }
        if (cfg.secure) {
            parts.push("Secure");
        }
        return parts.join("; ");
    }
}

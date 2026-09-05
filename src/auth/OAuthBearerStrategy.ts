////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUser } from "@rapidrest/core";
import { ApiErrors, AuthResult, AuthStrategy, HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { AccessTokenDenylist } from "./AccessTokenDenylist.js";
import { OAuthTokenUtils } from "./OAuthTokenUtils.js";
import { getBearerToken } from "./shared.js";

/**
 * Authenticates a request bearing one of this authorization server's own RS256 access tokens
 * (`Authorization: Bearer <token>`) — the strategy that protects `/userinfo` and any downstream resource
 * route mounted with `@Auth(["oauth_bearer"])`. Verifies the token via `OAuthTokenUtils.verifyAccessToken()`
 * (signature, expiry, issuer) and rejects one whose `jti` has been revoked via `AccessTokenDenylist` —
 * exactly the same two checks `BaseOAuthIntrospectRoute.introspectAccessToken()` performs, reused here
 * rather than re-verified a third way.
 *
 * Not exported from `src/auth/index.ts` — like `OAuthTokenUtils`/`AccessTokenDenylist`, this is an internal
 * service constructed by a route's `@Init` hook and registered on `AuthMiddleware` under a fixed name
 * (`"oauth_bearer"`); a downstream route protects itself with `@Auth(["oauth_bearer"])` by name, without
 * needing to import this class directly.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OAuthBearerStrategy implements AuthStrategy {
    public readonly name: string;

    private readonly accessTokenDenylist: AccessTokenDenylist;

    private readonly oauthTokenUtils: OAuthTokenUtils;

    constructor(name: string, oauthTokenUtils: OAuthTokenUtils, accessTokenDenylist: AccessTokenDenylist) {
        this.name = name;
        this.oauthTokenUtils = oauthTokenUtils;
        this.accessTokenDenylist = accessTokenDenylist;
    }

    public async authenticate(req: HttpRequest, res?: HttpResponse, required?: boolean): Promise<AuthResult | undefined> {
        const token = getBearerToken(req);

        if (token) {
            const claims = await this.oauthTokenUtils.verifyAccessToken(token);
            if (claims && typeof claims.jti === "string" && !(await this.accessTokenDenylist.isRevoked(claims.jti))) {
                const scopes: string[] = claims.scope ? String(claims.scope).split(" ").filter(Boolean) : [];
                const user: JWTUser = { uid: claims.sub, roles: [], scopes };
                return { data: token, method: this.name, payload: claims, user };
            }
        }

        if (required) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, "Invalid or expired access token.");
        }

        return undefined;
    }

    public authenticateSync(): AuthResult | undefined {
        throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, "Not supported. This auth strategy must be used asynchronously.");
    }
}

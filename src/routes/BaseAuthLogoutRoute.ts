///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { TokenUtils } from "../auth/TokenUtils.js";

const { Inject } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Post, Response } = RouteDecorators;

/**
 * Clears the authentication cookie previously set by a successful sign-in (see `TokenUtils`/`auth:cookie`
 * configuration). Model-agnostic and shared across every authentication strategy, since logging out isn't
 * specific to how the caller originally authenticated.
 *
 * A no-op (still returns success) when cookie issuance isn't enabled, or the caller was never issued one —
 * a client that only ever used the `Authorization: Bearer` header has nothing here to clear, and simply
 * discards its own token locally.
 *
 * This does not invalidate the JWT itself — a bearer token already issued remains valid until its natural
 * expiry even after this call succeeds; deployments needing server-side revocation must add a token
 * blocklist/short-lived-token strategy on top of this.
 *
 * @example
 * ```ts
 * import { BaseAuthLogoutRoute } from "@rapidrest/auth";
 * import { RouteDecorators } from "@rapidrest/service-core";
 * const { ApiRoute } = RouteDecorators;
 *
 * @ApiRoute("/auth/logout")
 * export class AuthLogoutRoute extends BaseAuthLogoutRoute {}
 * ```
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthLogoutRoute {
    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    @Summary("Log out")
    @Description(
        "Clears the authentication cookie previously set at sign-in, if cookie issuance is enabled. " +
            "Always succeeds, including for callers who were never issued a cookie.",
    )
    @Returns([null])
    @Post()
    public async logout(@Response res: HttpResponse): Promise<void> {
        this.tokenUtils?.clearToken(res);
    }
}

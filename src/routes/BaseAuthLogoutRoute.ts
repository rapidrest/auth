///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { TokenUtils } from "../auth/TokenUtils.js";

const { Inject } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Post, Request, Response } = RouteDecorators;

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
 * blocklist/short-lived-token strategy on top of this. It does, however, invalidate the session-bound
 * refresh token (see `BaseAuthRefreshRoute`): without clearing `req.session.userUid`/`refreshUid` here, a
 * refresh token leaked before logout (e.g. a narrow XSS window, a synced device) would remain fully usable
 * to silently mint new sessions until the session's own independent TTL eventually expired, long after the
 * user believed they'd logged out.
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
    public async logout(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        this.tokenUtils?.clearToken(res);

        // Set rather than deleted: the session-persistence middleware only re-saves the session when it
        // still has at least one key left (see `sessionMiddleware`), so clearing every key here could
        // leave the stale `userUid`/`refreshUid` values sitting in the store, forever unpersisted-over.
        if (req.session) {
            req.session.userUid = undefined;
            req.session.refreshUid = undefined;
        }
    }
}

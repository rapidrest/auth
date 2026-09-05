////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { MemoryStore, ObjectDecorators } from "@rapidrest/core";
import { ConnectionManager } from "@rapidrest/service-core";
import type { RedisClientType } from "redis";

const { Inject } = ObjectDecorators;

const CACHE_KEY_PREFIX = "auth:oauth_server:denylist";

/**
 * Tracks revoked OAuth access token `jti`s until their natural expiry. An access token is a stateless RS256
 * JWT (see `OAuthTokenUtils`) verified independently by every resource server, so revoking one can't delete
 * anything — instead, its `jti` is recorded here for exactly as long as the token would otherwise remain
 * valid, and every path that trusts an access token's signature (`BaseOAuthRevokeRoute`,
 * `BaseOAuthIntrospectRoute`, and `OAuthBearerStrategy`) must also check this list before treating it as
 * live. Backed by Redis when a `cache` connection is configured (shared across server instances, same as
 * `RateLimiter`), and falls back to an in-process in-memory store otherwise.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AccessTokenDenylist {
    @Inject(ConnectionManager)
    private connMgr?: ConnectionManager;

    @Inject(MemoryStore)
    private readonly memoryStore: MemoryStore = new MemoryStore();

    private get cacheClient(): RedisClientType | undefined {
        return this.connMgr?.connections.get("cache") as RedisClientType | undefined;
    }

    /**
     * Records `jti` as revoked for `ttlSeconds` — the token's remaining lifetime. A `jti` whose token has
     * already naturally expired (`ttlSeconds <= 0`) is not recorded at all, since it can never pass
     * signature verification again regardless of this list.
     */
    public async revoke(jti: string, ttlSeconds: number): Promise<void> {
        if (ttlSeconds <= 0) {
            return;
        }

        const key = `${CACHE_KEY_PREFIX}:${jti}`;
        if (this.cacheClient) {
            await this.cacheClient.set(key, "1", { expiration: { type: "EX", value: ttlSeconds } });
        } else {
            this.memoryStore.save(key, { revoked: true }, ttlSeconds);
        }
    }

    /** Returns whether `jti` has been revoked (and not yet naturally expired off this list). */
    public async isRevoked(jti: string): Promise<boolean> {
        const key = `${CACHE_KEY_PREFIX}:${jti}`;
        if (this.cacheClient) {
            return (await this.cacheClient.exists(key)) > 0;
        }
        return this.memoryStore.load(key) !== undefined;
    }
}

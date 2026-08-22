////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, MemoryStore, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors, ConnectionManager } from "@rapidrest/service-core";
import type { RedisClientType } from "redis";

const { Config, Inject } = ObjectDecorators;

const CACHE_KEY_PREFIX = "auth:ratelimit";

/**
 * Configuration options for `RateLimiter`.
 */
export interface RateLimiterConfig {
    /** Set to `false` to disable rate limiting entirely. Default is `true`. */
    enabled?: boolean;
    /** The maximum number of attempts allowed within `windowSeconds` before being rejected. Default is `5`. */
    maxAttempts?: number;
    /** The length of the sliding window, in seconds, that `maxAttempts` applies to. Default is `300` (5 minutes). */
    windowSeconds?: number;
}

/**
 * A simple attempt-count rate limiter used to defend the credential-verification endpoints (Basic, MFA, OTP,
 * TOTP) against brute-force/guessing attacks. Backed by Redis when a `cache` connection is configured (so the
 * count is shared across server instances), and falls back to an in-process in-memory counter otherwise.
 *
 * @author Jean-Philippe Steinmetz
 */
export class RateLimiter {
    @Config("auth:rateLimit", { enabled: true, maxAttempts: 5, windowSeconds: 300 })
    protected config: RateLimiterConfig = {
        enabled: true,
        maxAttempts: 5,
        windowSeconds: 300,
    };

    @Inject(ConnectionManager)
    private connMgr?: ConnectionManager;

    /** In-memory fallback store, used only when no `cache` connection is configured. */
    @Inject(MemoryStore)
    private readonly memoryStore: MemoryStore = new MemoryStore();

    private get cacheClient(): RedisClientType | undefined {
        return this.connMgr?.connections.get("cache") as RedisClientType | undefined;
    }

    /**
     * Records an attempt for the given identifier and throws once it has exceeded the configured
     * `maxAttempts` within `windowSeconds`. A no-op when rate limiting is disabled via config.
     * @param identifier A value that scopes the counter to a particular caller/target (e.g. a claimed username
     * or email). Callers should be aware that an identifier alone can be shared by an attacker and a victim
     * (e.g. a username), so this limits attempts against that identifier globally rather than per-source.
     */
    public async checkAndIncrement(identifier: string): Promise<void> {
        if (this.config.enabled === false) {
            return;
        }

        const maxAttempts: number = this.config.maxAttempts ?? 5;
        const windowSeconds: number = this.config.windowSeconds ?? 300;
        const key = `${CACHE_KEY_PREFIX}:${identifier.toLowerCase()}`;

        const count: number = this.cacheClient
            ? await this.incrementRedis(this.cacheClient, key, windowSeconds)
            : this.incrementMemory(key, windowSeconds);

        if (count > maxAttempts) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 429, "Too many attempts. Please try again later.");
        }
    }

    private async incrementRedis(client: RedisClientType, key: string, windowSeconds: number): Promise<number> {
        // `ENX` ("only set the expiry if the key doesn't already have one yet") anchors the window to the
        // *first* attempt, so a steady stream of attempts doesn't keep pushing the reset time forward -
        // without it, an attacker who never lets the key go idle could be throttled but never actually reset,
        // or (depending on how the window is otherwise consumed) could keep the window sliding indefinitely.
        // This must match `incrementMemory()` below, which anchors the same way (the TTL passed to `save()` is
        // only set once, at creation, and is never refreshed on subsequent increments either).
        const [value] = await client.increx(key, { expiration: { type: "EX", value: windowSeconds, ENX: true } });
        return Number(value);
    }

    private incrementMemory(key: string, windowSeconds: number): number {
        const entry = this.memoryStore.load(key);
        if (!entry) {
            this.memoryStore.save(key, { count: 1 }, windowSeconds);
            return 1;
        }
        // Mutate the object `MemoryStore.load()` handed back in place, rather than calling `save()` again -
        // `save()` always resets the entry's TTL to a fresh `windowSeconds` from *now*, which would slide the
        // window forward on every attempt (`load()` returns the same object it holds internally, not a copy,
        // so this mutation is visible to the next `load()` without needing to write it back). Anchoring the
        // window to the first attempt only, never refreshed here, must match `incrementRedis()`'s `ENX` above.
        entry.count += 1;
        return entry.count;
    }
}

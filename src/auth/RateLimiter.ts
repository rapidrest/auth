////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, MemoryStore, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors, ConnectionManager } from "@rapidrest/service-core";
import type { Redis } from "ioredis";

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
    private readonly memoryStore: MemoryStore = new MemoryStore(); // Map<string, { count: number; resetAt: number }> = new Map();

    private get cacheClient(): Redis | undefined {
        return this.connMgr?.connections.get("cache") as Redis | undefined;
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

    private async incrementRedis(client: Redis, key: string, windowSeconds: number): Promise<number> {
        const [value] = await client.increx(key, "EX", windowSeconds, "ENX");
        return Number(value);
    }

    private incrementMemory(key: string, windowSeconds: number): number {
        const now: number = Date.now();
        const entry = this.memoryStore.load(key);
        if (!entry || entry.resetAt <= now) {
            this.memoryStore.save(key, { count: 1 }, windowSeconds);
            return 1;
        }
        entry.count += 1;
        return entry.count;
    }
}

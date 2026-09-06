////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, EventUtils, MemoryStore, ObjectDecorators } from "@rapidrest/core";
import { ApiErrors, ConnectionManager, HttpRequest, NetUtils } from "@rapidrest/service-core";
import { ErrorReply, type RedisClientType } from "redis";
import { AuthEventType } from "./events.js";

const { Config, Inject, Logger } = ObjectDecorators;

const CACHE_KEY_PREFIX = "auth:ratelimit";

/**
 * Configuration options for the source-IP counter layered alongside the primary, identifier-keyed one. An
 * identifier (username/email/etc.) alone can't catch an attacker who rotates identifiers against a single
 * source, and is itself something an attacker and a victim can share (e.g. a common username) - keying a
 * second, independent counter on the caller's IP address closes that gap without weakening the existing
 * per-identifier throttle. Deliberately more permissive by default than the per-identifier limit, since a
 * single IP can legitimately represent many users behind NAT/a corporate proxy.
 */
export interface IPRateLimiterConfig {
    /** Set to `false` to disable the per-IP counter. Default is `true`. */
    enabled?: boolean;
    /** The maximum number of attempts allowed from a single IP within `windowSeconds`. Default is `100`. */
    maxAttempts?: number;
    /** The length of the window, in seconds, that `maxAttempts` applies to. Default is `300` (5 minutes). */
    windowSeconds?: number;
}

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
    /** Configuration for the additional, independent per-source-IP counter. */
    ip?: IPRateLimiterConfig;
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

    @Config("trusted_proxies", [])
    protected trustedProxies: string[] = [];

    @Inject(ConnectionManager)
    private connMgr?: ConnectionManager;

    /** In-memory fallback store, used both when no `cache` connection is configured and when the connected
     * Redis server is too old to support `INCREX` (see `redisIncrexUnsupported` below). */
    @Inject(MemoryStore)
    private readonly memoryStore: MemoryStore = new MemoryStore();

    @Logger
    protected logger: any;

    /** Set once `incrementRedis()` learns the connected server rejects `INCREX` as unknown (`INCREX` is a
     * Redis 8.8+ command - not yet supported by Redis Software, Redis Cloud, or any Redis-protocol-compatible
     * server that hasn't caught up, e.g. Memurai on Windows) - subsequent calls skip straight to the in-memory
     * fallback instead of paying for (and logging) a failed round trip on every single request. This does mean
     * the per-identifier/per-IP counters stop being atomic across multiple server instances sharing one Redis
     * for as long as this process runs, which is a real, deliberate degradation - see the class doc comment -
     * but a working, non-atomic rate limiter is better than every credential-verification request 500ing.
     */
    private redisIncrexUnsupported = false;

    private get cacheClient(): RedisClientType | undefined {
        return this.connMgr?.connections.get("cache") as RedisClientType | undefined;
    }

    /**
     * Records an attempt for the given identifier and throws once it has exceeded the configured
     * `maxAttempts` within `windowSeconds`. A no-op when rate limiting is disabled via config.
     *
     * When `req` is supplied, an independent, more permissive counter keyed on the caller's source IP is
     * also checked and incremented (see `IPRateLimiterConfig`) - this catches an attacker who rotates
     * identifiers against a single source, which the identifier-keyed counter alone cannot.
     * @param identifier A value that scopes the counter to a particular caller/target (e.g. a claimed username
     * or email). Callers should be aware that an identifier alone can be shared by an attacker and a victim
     * (e.g. a username), so this limits attempts against that identifier globally rather than per-source.
     * @param req The source HTTP request, used to derive the caller's IP for the additional per-IP counter.
     * Omit to check only the identifier-keyed counter (e.g. when no request is available).
     */
    public async checkAndIncrement(identifier: string, req?: HttpRequest): Promise<void> {
        if (this.config.enabled === false) {
            return;
        }

        await this.enforceLimit(
            `${CACHE_KEY_PREFIX}:${identifier.toLowerCase()}`,
            this.config.maxAttempts ?? 5,
            this.config.windowSeconds ?? 300,
            identifier,
            "identifier",
        );

        if (req && this.config.ip?.enabled !== false) {
            // `trustedProxies`-aware: without it, `getIPAddress()` never trusts forwarding headers and
            // always falls back to `req.socket.remoteAddress` - behind any reverse proxy that's the
            // proxy's own fixed address for every caller, collapsing every distinct client behind it onto
            // this one shared counter instead of throttling each of them independently.
            const address: string | undefined = NetUtils.getIPAddress(req, this.trustedProxies);
            if (address) {
                await this.enforceLimit(
                    `${CACHE_KEY_PREFIX}:ip:${address}`,
                    this.config.ip?.maxAttempts ?? 100,
                    this.config.ip?.windowSeconds ?? 300,
                    address,
                    "ip",
                );
            }
        }
    }

    /**
     * Increments the counter for `key` and throws once it exceeds `maxAttempts` within `windowSeconds`.
     * Shared by the identifier-keyed and IP-keyed counters in `checkAndIncrement()` - the two are otherwise
     * entirely independent (different keys, different limits), this just avoids duplicating the
     * increment-then-compare logic between them.
     */
    private async enforceLimit(
        key: string,
        maxAttempts: number,
        windowSeconds: number,
        identifier: string,
        layer: "identifier" | "ip",
    ): Promise<void> {
        const count: number =
            this.cacheClient && !this.redisIncrexUnsupported
                ? await this.incrementRedis(this.cacheClient, key, windowSeconds)
                : this.incrementMemory(key, windowSeconds);

        if (count > maxAttempts) {
            // Only the request that actually crosses the threshold records the event - `count` keeps
            // incrementing on every subsequent (already-429'd) retry within the window, so without this
            // check a caller who keeps hammering an already-limited endpoint would re-fire this event (and
            // whatever outbound telemetry POST it triggers) once per retry for free.
            if (count === maxAttempts + 1) {
                EventUtils.record({ type: AuthEventType.RATELIMIT_EXCEEDED, identifier, layer }).catch(() => undefined);
            }
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
        try {
            const [value] = await client.increx(key, { expiration: { type: "EX", value: windowSeconds, ENX: true } });
            return Number(value);
        } catch (err) {
            // `INCREX` is a Redis 8.8+ command - not yet supported by Redis Software, Redis Cloud, or any
            // Redis-protocol-compatible server that hasn't caught up (e.g. Memurai on Windows, still on the
            // Redis 7.4 command set at the time this comment was written). The server reports this the same
            // way it reports any unrecognized command name: an `ErrorReply` whose message starts with "ERR
            // unknown command". Anything else (a real connectivity failure, a malformed argument, etc.) is a
            // genuine error and must keep propagating rather than silently degrading rate limiting.
            if (err instanceof ErrorReply && /unknown command/i.test(err.message)) {
                this.redisIncrexUnsupported = true;
                this.logger?.warn?.(
                    "Redis rejected INCREX as an unknown command (requires Redis 8.8+) - RateLimiter is " +
                        "falling back to a per-instance in-memory counter for the rest of this process. Attempt " +
                        "counts will no longer be shared across server instances until Redis is upgraded and " +
                        "the process is restarted.",
                );
                return this.incrementMemory(key, windowSeconds);
            }
            throw err;
        }
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

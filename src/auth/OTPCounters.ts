////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import * as crypto from "crypto";
import { ApiError, EventUtils, MemoryStore, ObjectDecorators, type ObjectFactory } from "@rapidrest/core";
import {
    ApiErrors,
    ConnectionManager,
    HttpRequest,
    NetUtils,
    RATELIMIT_EXCEEDED_EVENT,
    RedisSessionStore,
    SessionManager,
} from "@rapidrest/service-core";
import type { RedisClientType } from "redis";

const { Config, Inject, Logger } = ObjectDecorators;

/** Every key is kept under this prefix, which no other part of the library (or the generic rate limiter) uses. */
const KEY_PREFIX = "auth:otp:";

/** The most keys the in-process fallback holds before it starts evicting the oldest. */
const MEMORY_MAX_ENTRIES = 100000;

/** Whether `err` is a Redis error *reply* (`ERR ...`, `WRONGTYPE ...`), as opposed to a connection failure. */
const isRedisErrorReply = (err: any): boolean =>
    /ErrorReply$/.test(err?.constructor?.name ?? "") ||
    /^(ERR|WRONGTYPE|EXECABORT|NOPERM|NOSCRIPT|MISCONF|READONLY)\b/.test(String(err?.message ?? ""));

/** A fixed-window limit. */
export interface CounterLimit {
    maxAttempts: number;
    windowSeconds: number;
}

/**
 * The counters behind one-time codes: the one-time claim of a successful redemption, the per-code guess counter and
 * the throttles on sending and verifying codes.
 *
 * These deliberately talk to the Redis `cache` connection directly with commands available since Redis 7
 * (`SET key 1 NX EX ttl` for the claim and `MULTI`/`INCR`/`EXPIRE key ttl NX`/`EXEC` for a counter) rather than going
 * through service-core's `RateLimiter`, whose atomic counter relies on `INCREX` (Redis 8.8+) and silently degrades to
 * a per-process counter on any older server, on Redis Software and Cloud, and on Memurai. Without a `cache`
 * connection an equivalent in-process store is used. It is the counters' own store (not the shared cache the rate
 * limiter, sessions and the access token denylist use), and it is correct for a single instance, but it is bounded:
 * once it holds `MEMORY_MAX_ENTRIES` keys the oldest are evicted, so a flood of distinct keys can reset a counter or a
 * claim. Use the `cache` connection anywhere that matters.
 *
 * The claim and the guess counter are security controls and are always enforced. The throttles (`throttle()`) are
 * rate limits and follow the service's `rateLimit:enabled` setting.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OTPCounters {
    @Config("rateLimit", { enabled: true })
    protected rateLimitConfig: { enabled?: boolean } = { enabled: true };

    @Config("trusted_proxies", [])
    protected trustedProxies: string[] = [];

    @Inject(ConnectionManager)
    private connMgr?: ConnectionManager;

    /** The in-process fallback. Deliberately its own store rather than the shared injected one (see above). */
    private readonly memoryStore: MemoryStore = (() => {
        const store: MemoryStore = new MemoryStore();
        store.maxSize = MEMORY_MAX_ENTRIES;
        return store;
    })();

    @Logger
    protected logger: any;

    private get cacheClient(): RedisClientType | undefined {
        return this.connMgr?.connections.get("cache") as RedisClientType | undefined;
    }

    /**
     * Warns loudly when the sessions are kept in Redis but these counters have no Redis `cache` connection to use. In
     * that case the counters are per-process, so with several instances the guesses allowed against one code, and the
     * redemptions of one code, multiply with the number of instances.
     *
     * When there is a `cache` connection it must be Redis 7.0 or newer: the counters rely on `EXPIRE ... NX`, which
     * older servers (and some compatible products) reject or ignore, and without it a counter could never expire or
     * never be bounded. This is probed with a scratch transaction, and a server that fails it **refuses to start**
     * (this throws), the same as an unsafe `auth:otp` configuration does.
     *
     * Call it once at startup, and await it.
     *
     * @param objectFactory The service's object factory, used to find its `SessionManager`.
     * @returns `true` if the deployment is unsafe in the per-process way above.
     * @throws If the `cache` connection is not a Redis 7+ compatible server.
     */
    public async checkDeployment(objectFactory?: ObjectFactory): Promise<boolean> {
        const client = this.cacheClient;
        if (client) {
            await this.probe(client);
        }

        const sessionManager: any = objectFactory?.getInstance(SessionManager);
        if (sessionManager?.store instanceof RedisSessionStore && !this.cacheClient) {
            this.logger?.warn?.(
                "One-time code protections are per-process: the session store is Redis but there is no `cache` " +
                    "connection for the one-time code counters. With more than one server instance, wrong guesses " +
                    "against one code and redemptions of one code are NOT limited across instances. Configure the " +
                    "`cache` datasource.",
            );
            return true;
        }
        return false;
    }

    /** Runs the scratch transaction the counters depend on and throws if the server cannot do it. */
    private async probe(client: RedisClientType): Promise<void> {
        const key = `${KEY_PREFIX}probe:${crypto.randomBytes(8).toString("hex")}`;
        let reason: string | undefined;
        let unreachable = false;
        try {
            const reply: any[] = (await client.multi().incr(key).expire(key, 10, "NX").exec()) as any[];
            // The same strict check `increment()` applies: anything but a number (an error reply object, say) means
            // the counters would not work.
            if (
                !Array.isArray(reply) ||
                typeof reply[0] !== "number" ||
                reply[0] !== 1 ||
                typeof reply[1] !== "number" ||
                reply[1] !== 1
            ) {
                reason = `unexpected reply ${JSON.stringify(reply)}`;
            }
        } catch (err: any) {
            reason = err?.message ?? String(err);
            // A command or syntax error reply (`ERR ...`) comes from a server that answered and does not understand
            // the command; anything else (refused, timed out, closed) never got an answer from the server.
            unreachable = !isRedisErrorReply(err);
        }
        try {
            await client.del(key);
        } catch {
            // The scratch key expires by itself (or was never created).
        }
        if (reason) {
            const message = unreachable
                ? "The `cache` connection is unreachable (" +
                  reason +
                  "). The one-time code counters need it; refusing to start rather than run without working limits."
                : "The `cache` connection does not support `MULTI` with `INCR` and `EXPIRE key ttl NX` (" +
                  reason +
                  "). The one-time code counters need Redis 7.0 or newer; refusing to start rather than run without " +
                  "working limits.";
            this.logger?.error?.(message);
            throw new Error(message);
        }
    }

    /** The caller's IP address as the rate limiter would see it, or `unknown`. */
    public ipOf(req: HttpRequest): string {
        return NetUtils.getIPAddress(req, this.trustedProxies) || "unknown";
    }

    /**
     * Claims `key` exactly once for `ttlSeconds`: the first caller gets `true`, anyone else (on any instance sharing the
     * Redis connection) gets `false`.
     */
    public async claim(key: string, ttlSeconds: number): Promise<boolean> {
        key = KEY_PREFIX + key;
        const client = this.cacheClient;
        if (client) {
            const result = await client.set(key, "1", { expiration: { type: "EX", value: ttlSeconds }, condition: "NX" });
            return result === "OK";
        }

        // Synchronous from the load to the save, so no other request in this process can interleave.
        if (this.memoryStore.load(key)) {
            return false;
        }
        this.memoryStore.save(key, { count: 1 }, ttlSeconds);
        return true;
    }

    /**
     * Increments the counter for `key` and returns its new value. The window is anchored to the first increment and is
     * never extended by later ones.
     */
    public async increment(key: string, windowSeconds: number): Promise<number> {
        key = KEY_PREFIX + key;
        const client = this.cacheClient;
        if (client) {
            // MULTI/EXEC makes the pair atomic, so a crash can never leave a counter without an expiry. `NX` only sets
            // the expiry while the key has none, which anchors the window to the first attempt.
            // A reply that is not a number (an error reply from a server that does not understand `NX`, say) must not
            // become `NaN`, which compares false against every limit: fail closed instead.
            const [count] = (await client.multi().incr(key).expire(key, windowSeconds, "NX").exec()) as any[];
            if (typeof count !== "number" || !Number.isFinite(count)) {
                throw new Error("Unexpected reply from the `cache` connection while counting an attempt.");
            }
            return count;
        }

        const entry = this.memoryStore.load(key);
        if (!entry) {
            this.memoryStore.save(key, { count: 1 }, windowSeconds);
            return 1;
        }
        // Mutated in place: `save()` would restart the window.
        entry.count += 1;
        return entry.count;
    }

    /**
     * Counts an event against `key` and throws a 429 `ApiError` once there have been more than `limit.maxAttempts` in
     * the window. A no-op when rate limiting is disabled (`rateLimit:enabled`).
     */
    public async throttle(key: string, limit: CounterLimit): Promise<void> {
        if (this.rateLimitConfig?.enabled === false) {
            return;
        }

        const count: number = await this.increment(key, limit.windowSeconds);
        if (count > limit.maxAttempts) {
            if (count === limit.maxAttempts + 1) {
                EventUtils.record({ type: RATELIMIT_EXCEEDED_EVENT, identifier: key, layer: "otp" }).catch(
                    () => undefined,
                );
            }
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 429, "Too many attempts. Please try again later.");
        }
    }
}

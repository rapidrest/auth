///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError } from "@rapidrest/core";
import { RateLimiter } from "../../src/auth/RateLimiter.js";

/**
 * A minimal fake of a node-redis client's `INCREX` command, faithful enough to exercise
 * `RateLimiter.incrementRedis()`'s actual usage: atomically increments a counter and (unless `ENX` is set and
 * the key already has a TTL) (re)sets its expiration, returning `[currentValue, actualIncrement]` like the real
 * command. Each call mutates its little store synchronously, before yielding to a microtask tick (not a real/
 * fake timer, so this works the same whether or not `vi.useFakeTimers()` is active) - concurrent callers can't
 * observe a torn read/write, the same guarantee a real, atomic Redis command provides regardless of when each
 * caller's response happens to come back over the network.
 */
function makeFakeRedisClient(): { increx: ReturnType<typeof vi.fn> } {
    const store = new Map<string, { count: number; expiresAt: number }>();
    const increx = vi.fn(async (key: string, options?: { expiration?: { type: string; value: number; ENX?: boolean } }) => {
        const now = Date.now();
        let entry = store.get(key);
        if (!entry || entry.expiresAt <= now) {
            entry = { count: 0, expiresAt: 0 };
            store.set(key, entry);
        }
        entry.count += 1;
        const ex = options?.expiration;
        if (ex && ex.type === "EX" && !(ex.ENX && entry.expiresAt > now)) {
            entry.expiresAt = now + ex.value * 1000;
        }
        const result = entry.count;
        await Promise.resolve();
        return [result, 1];
    });
    return { increx };
}

function makeConnMgrWithCache(client: unknown): any {
    return { connections: new Map([["cache", client]]) };
}

describe("RateLimiter Tests", () => {
    describe("in-memory fallback (no `cache` connection configured)", () => {
        it("Uses sensible defaults (enabled, maxAttempts: 5, windowSeconds: 300).", async () => {
            const limiter = new RateLimiter();

            for (let i = 0; i < 5; i++) {
                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            }
            await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);
        });

        it("Throws an ApiError with status 429 once the threshold is exceeded.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");

            await expect(limiter.checkAndIncrement("user-1")).rejects.toMatchObject({ status: 429 });
            await expect(limiter.checkAndIncrement("user-1")).rejects.toBeInstanceOf(ApiError);
        });

        it("Tracks separate identifiers independently.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");
            await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

            // A different identifier has its own independent counter.
            await expect(limiter.checkAndIncrement("user-2")).resolves.toBeUndefined();
        });

        it("Resets the count once the window has elapsed.", async () => {
            vi.useFakeTimers();
            try {
                const limiter = new RateLimiter();
                (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 1 };

                await limiter.checkAndIncrement("user-1");
                await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

                vi.advanceTimersByTime(1100);

                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            } finally {
                vi.useRealTimers();
            }
        });

        // Regression: the window must be anchored to the *first* attempt and never pushed forward by
        // subsequent ones - `incrementMemory()` mutates the existing entry in place rather than calling
        // `MemoryStore.save()` again, specifically so it doesn't reset the entry's TTL on every attempt. A
        // rate limiter whose window keeps sliding forward as long as an attacker keeps sending requests could
        // be kept perpetually short of triggering a full reset without ever backing off.
        it("Does not push the reset time forward when attempts continue after the limit is hit.", async () => {
            vi.useFakeTimers();
            try {
                const limiter = new RateLimiter();
                (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 10 };

                await limiter.checkAndIncrement("user-1");
                await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

                // Keep hammering it well within the original window - none of this should extend it.
                vi.advanceTimersByTime(9000);
                await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

                // The window anchored to the *first* attempt (t=0) elapses at t=10s, not t=9s+10s.
                vi.advanceTimersByTime(1100);
                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            } finally {
                vi.useRealTimers();
            }
        });

        it("Falls back to default maxAttempts/windowSeconds when a partial config is provided.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true };

            for (let i = 0; i < 5; i++) {
                await expect(limiter.checkAndIncrement("user-2")).resolves.toBeUndefined();
            }
            await expect(limiter.checkAndIncrement("user-2")).rejects.toThrow(/Too many attempts/);
        });

        it("Is a no-op when rate limiting is disabled.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: false, maxAttempts: 1, windowSeconds: 300 };

            for (let i = 0; i < 10; i++) {
                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            }
        });

        it("Treats identifiers as case-insensitive so varying case can't be used to dodge the limit.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("User@Example.com");
            await expect(limiter.checkAndIncrement("user@example.com")).rejects.toThrow(/Too many attempts/);
            await expect(limiter.checkAndIncrement("USER@EXAMPLE.COM")).rejects.toThrow(/Too many attempts/);
        });

        // Regression: `incrementMemory()` is fully synchronous (no `await` between its read and its write), so
        // concurrent callers on the same process can never interleave - see the doc comment on `incrementMemory`.
        it("Does not let concurrent requests for the same identifier exceed maxAttempts.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true, maxAttempts: 5, windowSeconds: 300 };

            const results = await Promise.allSettled(
                Array.from({ length: 20 }, () => limiter.checkAndIncrement("attacker")),
            );

            expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(5);
            expect(results.filter((r) => r.status === "rejected")).toHaveLength(15);
        });
    });

    describe("Redis-backed (`cache` connection configured)", () => {
        it("Uses the Redis client's atomic INCREX instead of the in-memory fallback when a `cache` connection is present.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 5, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");

            expect(client.increx).toHaveBeenCalledTimes(1);
        });

        // Regression: node-redis's built-in `INCREX` replaced this project's previous `ioredis`-based custom
        // `increx` Lua command, which was always called with an `ENX` flag - lost in that port. Without `ENX`,
        // every attempt refreshes the key's TTL, so the window keeps sliding forward for as long as an
        // attacker keeps sending requests, instead of being anchored to the first attempt (matching the
        // in-memory fallback's behavior - see the equivalent memory-store test above).
        it("Passes ENX so the Redis-backed window is anchored to the first attempt, not refreshed on every call.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");

            expect(client.increx).toHaveBeenCalledWith(
                "auth:ratelimit:user-1",
                expect.objectContaining({ expiration: expect.objectContaining({ type: "EX", value: 300, ENX: true }) }),
            );
        });

        it("Does not push the reset time forward when attempts continue after the limit is hit.", async () => {
            vi.useFakeTimers();
            try {
                const client = makeFakeRedisClient();
                const limiter = new RateLimiter();
                (limiter as any).connMgr = makeConnMgrWithCache(client);
                (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 10 };

                await limiter.checkAndIncrement("user-1");
                await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

                vi.advanceTimersByTime(9000);
                await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

                vi.advanceTimersByTime(1100);
                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            } finally {
                vi.useRealTimers();
            }
        });

        it("Throws an ApiError with status 429 once the threshold is exceeded.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");

            await expect(limiter.checkAndIncrement("user-1")).rejects.toMatchObject({ status: 429 });
            await expect(limiter.checkAndIncrement("user-1")).rejects.toBeInstanceOf(ApiError);
        });

        it("Tracks separate identifiers independently.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("user-1");
            await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);
            await expect(limiter.checkAndIncrement("user-2")).resolves.toBeUndefined();
        });

        it("Is a no-op when rate limiting is disabled, and never calls Redis.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: false, maxAttempts: 1, windowSeconds: 300 };

            for (let i = 0; i < 10; i++) {
                await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
            }
            expect(client.increx).not.toHaveBeenCalled();
        });

        it("Treats identifiers as case-insensitive so varying case can't be used to dodge the limit.", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

            await limiter.checkAndIncrement("User@Example.com");
            await expect(limiter.checkAndIncrement("user@example.com")).rejects.toThrow(/Too many attempts/);
            await expect(limiter.checkAndIncrement("USER@EXAMPLE.COM")).rejects.toThrow(/Too many attempts/);
        });

        // The atomicity guarantee this backend exists for: unlike the old `RedisStore`-based `load()`-then-
        // `save()` implementation (see git history), `incrementRedis()` is a single round-trip to an atomic
        // Redis command, so there's no client-side read/write gap for concurrent callers to race.
        it("Does not let concurrent requests for the same identifier exceed maxAttempts (globally atomic).", async () => {
            const client = makeFakeRedisClient();
            const limiter = new RateLimiter();
            (limiter as any).connMgr = makeConnMgrWithCache(client);
            (limiter as any).config = { enabled: true, maxAttempts: 5, windowSeconds: 300 };

            const results = await Promise.allSettled(
                Array.from({ length: 20 }, () => limiter.checkAndIncrement("attacker")),
            );

            expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(5);
            expect(results.filter((r) => r.status === "rejected")).toHaveLength(15);
        });
    });
});

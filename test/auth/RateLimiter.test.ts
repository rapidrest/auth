///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError } from "@rapidrest/core";
import { RateLimiter } from "../../src/auth/RateLimiter.js";

describe("RateLimiter Tests", () => {
    describe("In-memory backend", () => {
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

            await expect(limiter.checkAndIncrement("user-1")).rejects.toMatchObject({
                status: 429,
            });
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
    });

    describe("Redis backend", () => {
        // INCREX (Redis >= 8.8) atomically increments the counter and applies the expiry (via `ENX`,
        // "set expiry only if the key has none") in a single round trip, so there's no window between an
        // increment and its expiry being set where a crash/network blip could leave the key stuck forever
        // with no TTL, unlike the old two-step INCR-then-EXPIRE approach.
        function makeRedisClient(startingCount: number = 0) {
            let count = startingCount;
            return {
                increx: vi.fn(async () => {
                    count += 1;
                    return [count, 1];
                }),
            };
        }

        it("Uses the Redis cache connection when available instead of the in-memory store.", async () => {
            const limiter = new RateLimiter();
            const redisClient = makeRedisClient();
            (limiter as any).config = { enabled: true, maxAttempts: 2, windowSeconds: 60 };
            (limiter as any).connMgr = { connections: new Map([["cache", redisClient]]) };

            await limiter.checkAndIncrement("user-1");
            await limiter.checkAndIncrement("user-1");
            await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);

            expect(redisClient.increx).toHaveBeenCalledWith("auth:ratelimit:user-1", "EX", 60, "ENX");
        });

        it("Atomically increments and applies the expiry-if-absent flag on every call, not just the first.", async () => {
            const limiter = new RateLimiter();
            const redisClient = makeRedisClient();
            (limiter as any).config = { enabled: true, maxAttempts: 5, windowSeconds: 60 };
            (limiter as any).connMgr = { connections: new Map([["cache", redisClient]]) };

            await limiter.checkAndIncrement("user-1");
            await limiter.checkAndIncrement("user-1");

            expect(redisClient.increx).toHaveBeenCalledTimes(2);
            expect(redisClient.increx).toHaveBeenNthCalledWith(1, "auth:ratelimit:user-1", "EX", 60, "ENX");
            expect(redisClient.increx).toHaveBeenNthCalledWith(2, "auth:ratelimit:user-1", "EX", 60, "ENX");
        });

        it("Falls back to the in-memory store when no cache connection is configured.", async () => {
            const limiter = new RateLimiter();
            (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 60 };
            (limiter as any).connMgr = { connections: new Map() };

            await limiter.checkAndIncrement("user-1");
            await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);
        });
    });
});

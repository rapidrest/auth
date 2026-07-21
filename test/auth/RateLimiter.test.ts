///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
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
    });

    describe("Redis backend", () => {
        function makeRedisClient(startingCount: number = 0) {
            let count = startingCount;
            return {
                incr: vi.fn(async () => ++count),
                expire: vi.fn(async () => 1),
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

            expect(redisClient.incr).toHaveBeenCalledWith("auth:ratelimit:user-1");
            expect(redisClient.expire).toHaveBeenCalledWith("auth:ratelimit:user-1", 60);
        });

        it("Only sets the expiry on the first increment.", async () => {
            const limiter = new RateLimiter();
            const redisClient = makeRedisClient();
            (limiter as any).config = { enabled: true, maxAttempts: 5, windowSeconds: 60 };
            (limiter as any).connMgr = { connections: new Map([["cache", redisClient]]) };

            await limiter.checkAndIncrement("user-1");
            await limiter.checkAndIncrement("user-1");

            expect(redisClient.expire).toHaveBeenCalledTimes(1);
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

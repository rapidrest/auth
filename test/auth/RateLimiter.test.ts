///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError, RedisStore } from "@rapidrest/core";
import { RateLimiter } from "../../src/auth/RateLimiter.js";

describe("RateLimiter Tests", () => {
    it("Uses sensible defaults (enabled, maxAttempts: 5, windowSeconds: 300).", async () => {
        const limiter = new RateLimiter();
        (limiter as any).cache = new RedisStore("auth:ratelimit");

        for (let i = 0; i < 5; i++) {
            await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
        }
        await expect(limiter.checkAndIncrement("user-1")).rejects.toThrow(/Too many attempts/);
    });

    it("Throws an ApiError with status 429 once the threshold is exceeded.", async () => {
        const limiter = new RateLimiter();
        (limiter as any).cache = new RedisStore("auth:ratelimit");
        (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

        await limiter.checkAndIncrement("user-1");

        await expect(limiter.checkAndIncrement("user-1")).rejects.toMatchObject({
            status: 429,
        });
        await expect(limiter.checkAndIncrement("user-1")).rejects.toBeInstanceOf(ApiError);
    });

    it("Tracks separate identifiers independently.", async () => {
        const limiter = new RateLimiter();
        (limiter as any).cache = new RedisStore("auth:ratelimit");
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
            (limiter as any).cache = new RedisStore("auth:ratelimit");
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
        (limiter as any).cache = new RedisStore("auth:ratelimit");
        (limiter as any).config = { enabled: true };

        for (let i = 0; i < 5; i++) {
            await expect(limiter.checkAndIncrement("user-2")).resolves.toBeUndefined();
        }
        await expect(limiter.checkAndIncrement("user-2")).rejects.toThrow(/Too many attempts/);
    });

    it("Is a no-op when rate limiting is disabled.", async () => {
        const limiter = new RateLimiter();
        (limiter as any).cache = new RedisStore("auth:ratelimit");
        (limiter as any).config = { enabled: false, maxAttempts: 1, windowSeconds: 300 };

        for (let i = 0; i < 10; i++) {
            await expect(limiter.checkAndIncrement("user-1")).resolves.toBeUndefined();
        }
    });

    it("Treats identifiers as case-insensitive so varying case can't be used to dodge the limit.", async () => {
        const limiter = new RateLimiter();
        (limiter as any).cache = new RedisStore("auth:ratelimit");
        (limiter as any).config = { enabled: true, maxAttempts: 1, windowSeconds: 300 };

        await limiter.checkAndIncrement("User@Example.com");
        await expect(limiter.checkAndIncrement("user@example.com")).rejects.toThrow(/Too many attempts/);
        await expect(limiter.checkAndIncrement("USER@EXAMPLE.COM")).rejects.toThrow(/Too many attempts/);
    });
});

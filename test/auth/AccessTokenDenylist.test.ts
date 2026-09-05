///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AccessTokenDenylist } from "../../src/auth/AccessTokenDenylist.js";

/**
 * A minimal fake of a node-redis client's `SET`/`EXISTS` commands, faithful enough to exercise
 * `AccessTokenDenylist`'s actual usage: `set(key, value, {expiration:{type:"EX", value}})` records a key
 * with a TTL, and `exists(key)` returns `1`/`0` depending on whether that TTL has elapsed. Each entry expires
 * lazily (checked on `exists()`) rather than via a real timer, so this works the same with or without
 * `vi.useFakeTimers()`.
 */
function makeFakeRedisClient() {
    const store = new Map<string, number>();
    return {
        set: vi.fn(async (key: string, _value: string, options?: { expiration?: { type: string; value: number } }) => {
            const ttlMs = options?.expiration?.type === "EX" ? options.expiration.value * 1000 : 0;
            store.set(key, Date.now() + ttlMs);
            return "OK";
        }),
        exists: vi.fn(async (key: string) => {
            const expiresAt = store.get(key);
            if (expiresAt === undefined) {
                return 0;
            }
            if (expiresAt <= Date.now()) {
                store.delete(key);
                return 0;
            }
            return 1;
        }),
    };
}

function makeConnMgrWithCache(client: unknown): any {
    return { connections: new Map([["cache", client]]) };
}

describe("AccessTokenDenylist Tests", () => {
    describe("in-memory fallback (no `cache` connection configured)", () => {
        it("Reports a jti as not revoked before it has ever been revoked.", async () => {
            const denylist = new AccessTokenDenylist();
            await expect(denylist.isRevoked("jti-1")).resolves.toBe(false);
        });

        it("Reports a jti as revoked immediately after revoke().", async () => {
            const denylist = new AccessTokenDenylist();
            await denylist.revoke("jti-1", 300);
            await expect(denylist.isRevoked("jti-1")).resolves.toBe(true);
        });

        it("Tracks separate jtis independently.", async () => {
            const denylist = new AccessTokenDenylist();
            await denylist.revoke("jti-1", 300);
            await expect(denylist.isRevoked("jti-2")).resolves.toBe(false);
        });

        it("Expires the revocation once its TTL elapses.", async () => {
            vi.useFakeTimers();
            try {
                const denylist = new AccessTokenDenylist();
                await denylist.revoke("jti-1", 1);
                await expect(denylist.isRevoked("jti-1")).resolves.toBe(true);

                vi.advanceTimersByTime(1100);

                await expect(denylist.isRevoked("jti-1")).resolves.toBe(false);
            } finally {
                vi.useRealTimers();
            }
        });

        it("Does not record a jti whose token has already naturally expired (ttlSeconds <= 0).", async () => {
            const denylist = new AccessTokenDenylist();
            await denylist.revoke("jti-1", 0);
            await denylist.revoke("jti-2", -5);
            await expect(denylist.isRevoked("jti-1")).resolves.toBe(false);
            await expect(denylist.isRevoked("jti-2")).resolves.toBe(false);
        });
    });

    describe("Redis-backed (`cache` connection configured)", () => {
        it("Uses the Redis client's SET/EXISTS instead of the in-memory fallback when a `cache` connection is present.", async () => {
            const client = makeFakeRedisClient();
            const denylist = new AccessTokenDenylist();
            (denylist as any).connMgr = makeConnMgrWithCache(client);

            await denylist.revoke("jti-1", 300);
            await expect(denylist.isRevoked("jti-1")).resolves.toBe(true);

            expect(client.set).toHaveBeenCalledWith(
                "auth:oauth_server:denylist:jti-1",
                "1",
                { expiration: { type: "EX", value: 300 } },
            );
            expect(client.exists).toHaveBeenCalledWith("auth:oauth_server:denylist:jti-1");
        });

        it("Reports a jti as not revoked before it has ever been revoked.", async () => {
            const client = makeFakeRedisClient();
            const denylist = new AccessTokenDenylist();
            (denylist as any).connMgr = makeConnMgrWithCache(client);

            await expect(denylist.isRevoked("jti-1")).resolves.toBe(false);
        });

        it("Tracks separate jtis independently.", async () => {
            const client = makeFakeRedisClient();
            const denylist = new AccessTokenDenylist();
            (denylist as any).connMgr = makeConnMgrWithCache(client);

            await denylist.revoke("jti-1", 300);
            await expect(denylist.isRevoked("jti-2")).resolves.toBe(false);
        });

        it("Does not call Redis's SET for a jti whose token has already naturally expired (ttlSeconds <= 0).", async () => {
            const client = makeFakeRedisClient();
            const denylist = new AccessTokenDenylist();
            (denylist as any).connMgr = makeConnMgrWithCache(client);

            await denylist.revoke("jti-1", 0);

            expect(client.set).not.toHaveBeenCalled();
        });

        it("Expires the revocation once its TTL elapses.", async () => {
            vi.useFakeTimers();
            try {
                const client = makeFakeRedisClient();
                const denylist = new AccessTokenDenylist();
                (denylist as any).connMgr = makeConnMgrWithCache(client);

                await denylist.revoke("jti-1", 1);
                await expect(denylist.isRevoked("jti-1")).resolves.toBe(true);

                vi.advanceTimersByTime(1100);

                await expect(denylist.isRevoked("jti-1")).resolves.toBe(false);
            } finally {
                vi.useRealTimers();
            }
        });
    });
});

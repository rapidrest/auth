///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { EventUtils } from "@rapidrest/core";
import { RedisSessionStore } from "@rapidrest/service-core";
import { OTPCounters } from "../../src/auth/OTPCounters.js";
import { FakeRedisClient } from "../helpers/FakeRedis.js";

const START = new Date("2026-11-05T12:00:00.000Z").getTime();

const connect = (counters: OTPCounters, redis: FakeRedisClient): OTPCounters => {
    (counters as any).connMgr = { connections: new Map([["cache", redis]]) };
    return counters;
};

describe("OTPCounters", () => {
    beforeEach(() => {
        vi.useFakeTimers({ toFake: ["Date"] });
        vi.setSystemTime(START);
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    // The same behaviour is required with and without Redis.
    describe.each([
        ["in-process", () => new OTPCounters()],
        ["Redis", () => connect(new OTPCounters(), new FakeRedisClient())],
    ])("%s", (_name, make) => {
        let counters: OTPCounters;
        beforeEach(() => {
            counters = make();
        });

        it("claim() succeeds once per key and window.", async () => {
            expect(await counters.claim("k", 60)).toBe(true);
            expect(await counters.claim("k", 60)).toBe(false);
            expect(await counters.claim("other", 60)).toBe(true);
            vi.setSystemTime(START + 61_000);
            expect(await counters.claim("k", 60)).toBe(true);
        });

        it("claim() lets exactly one of many parallel callers win.", async () => {
            const results = await Promise.all(Array.from({ length: 10 }, () => counters.claim("race", 60)));
            expect(results.filter(Boolean)).toHaveLength(1);
        });

        it("increment() counts up and anchors the window to the first call.", async () => {
            expect(await counters.increment("k", 60)).toBe(1);
            vi.setSystemTime(START + 30_000);
            expect(await counters.increment("k", 60)).toBe(2);
            // The second call did not extend the window: it still ends 60 seconds after the first.
            vi.setSystemTime(START + 61_000);
            expect(await counters.increment("k", 60)).toBe(1);
        });

        it("increment() hands out every number exactly once to parallel callers.", async () => {
            const counts = await Promise.all(Array.from({ length: 10 }, () => counters.increment("race", 60)));
            expect([...counts].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        });

        it("throttle() allows maxAttempts and then throws a 429.", async () => {
            for (let i = 0; i < 3; i++) {
                await counters.throttle("t", { maxAttempts: 3, windowSeconds: 60 });
            }
            await expect(counters.throttle("t", { maxAttempts: 3, windowSeconds: 60 })).rejects.toMatchObject({
                status: 429,
            });
            await expect(counters.throttle("t", { maxAttempts: 3, windowSeconds: 60 })).rejects.toMatchObject({
                status: 429,
            });
            await expect(counters.throttle("fresh", { maxAttempts: 3, windowSeconds: 60 })).resolves.toBeUndefined();
        });

        it("throttle() records the exceeded event only for the call that crosses the limit.", async () => {
            // Telemetry that cannot be sent (EventUtils not initialized, say) never turns into a failure.
            const record = vi.spyOn(EventUtils, "record").mockRejectedValue(new Error("not initialized"));
            for (let i = 0; i < 4; i++) {
                await counters.throttle("e", { maxAttempts: 1, windowSeconds: 60 }).catch(() => undefined);
            }
            await new Promise((resolve) => setTimeout(resolve, 0));
            expect(record).toHaveBeenCalledTimes(1);
            expect(record).toHaveBeenCalledWith(expect.objectContaining({ identifier: "e", layer: "otp" }));
            record.mockRestore();
        });

        it("throttle() does nothing when rate limiting is disabled, but claim() and increment() still work.", async () => {
            (counters as any).rateLimitConfig = { enabled: false };
            for (let i = 0; i < 5; i++) {
                await counters.throttle("t", { maxAttempts: 1, windowSeconds: 60 });
            }
            expect(await counters.claim("k", 60)).toBe(true);
            expect(await counters.claim("k", 60)).toBe(false);
            expect(await counters.increment("k2", 60)).toBe(1);
            expect(await counters.increment("k2", 60)).toBe(2);
        });
    });

    it("Keeps every key under its own prefix, away from the generic rate limiter's.", async () => {
        const redis = new FakeRedisClient();
        const counters = connect(new OTPCounters(), redis);
        await counters.claim("used:abc", 60);
        await counters.increment("issue:login:x", 60);
        expect([...redis.values.keys()].sort()).toEqual(["auth:otp:issue:login:x", "auth:otp:used:abc"]);
        expect([...redis.values.keys()].some((k) => k.startsWith("ratelimit:"))).toBe(false);
    });

    it("Shares counts and claims between instances that share a Redis, but not between ones that do not.", async () => {
        const redis = new FakeRedisClient(1);
        const a = connect(new OTPCounters(), redis);
        const b = connect(new OTPCounters(), redis);

        expect(await a.claim("k", 60)).toBe(true);
        expect(await b.claim("k", 60)).toBe(false);
        expect(await a.increment("c", 60)).toBe(1);
        expect(await b.increment("c", 60)).toBe(2);

        const solo = new OTPCounters();
        expect(await solo.claim("k", 60)).toBe(true);
        expect(await solo.increment("c", 60)).toBe(1);
    });

    it("Never leaves a counter without an expiry: the increment and the expiry are one transaction.", async () => {
        const redis = new FakeRedisClient();
        const counters = connect(new OTPCounters(), redis);
        await counters.increment("c", 60);
        expect(redis.expiries.has("auth:otp:c")).toBe(true);
        expect(redis.commands).toEqual(["EXEC"]);
    });

    it("ipOf() returns the caller's address, or 'unknown'.", () => {
        const counters = new OTPCounters();
        expect(counters.ipOf({ headers: {}, socket: { remoteAddress: "10.1.2.3" } } as any)).toBe("10.1.2.3");
        expect(counters.ipOf({ headers: {}, socket: {} } as any)).toBe("unknown");
    });

    describe("failing closed", () => {
        it("increment() throws, rather than returning NaN, when the reply is not a number.", async () => {
            for (const reply of [[new Error("ERR syntax error")], [undefined], [null], ["1"], [Number.NaN], []]) {
                const redis = new FakeRedisClient();
                vi.spyOn(redis, "multi").mockReturnValue({
                    incr: () => ({ expire: () => ({ exec: async () => reply }) }),
                } as any);
                await expect(connect(new OTPCounters(), redis).increment("k", 60)).rejects.toThrow(/Unexpected reply/);
            }
        });

        it("throttle() and claim() reject when Redis throws, so a caller never proceeds as if nothing was counted.", async () => {
            const redis = new FakeRedisClient();
            const counters = connect(new OTPCounters(), redis);
            vi.spyOn(redis, "multi").mockImplementation(() => {
                throw new Error("connection lost");
            });
            vi.spyOn(redis, "set").mockRejectedValue(new Error("connection lost"));
            await expect(counters.throttle("k", { maxAttempts: 3, windowSeconds: 60 })).rejects.toThrow(/connection lost/);
            await expect(counters.increment("k", 60)).rejects.toThrow(/connection lost/);
            await expect(counters.claim("k", 60)).rejects.toThrow(/connection lost/);
        });
    });

    describe("checkDeployment", () => {
        const factory = (store: any) => ({ getInstance: () => ({ store }) }) as any;
        let logger: { warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };
        let counters: OTPCounters;
        beforeEach(() => {
            logger = { warn: vi.fn(), error: vi.fn() };
            counters = new OTPCounters();
            (counters as any).logger = logger;
        });

        it("Warns loudly when the sessions are in Redis but there is no cache connection for the counters.", async () => {
            const store = new RedisSessionStore(new FakeRedisClient() as any);
            expect(await counters.checkDeployment(factory(store))).toBe(true);
            expect(logger.warn).toHaveBeenCalledWith(expect.stringMatching(/per-process.*NOT limited across instances/s));
        });

        it("Is quiet when the counters have their Redis connection, and leaves no scratch key behind.", async () => {
            const store = new RedisSessionStore(new FakeRedisClient() as any);
            const redis = new FakeRedisClient();
            connect(counters, redis);
            expect(await counters.checkDeployment(factory(store))).toBe(false);
            expect(logger.warn).not.toHaveBeenCalled();
            expect(logger.error).not.toHaveBeenCalled();
            expect(redis.values.size).toBe(0);
        });

        it("Is quiet when the sessions are in process, or there is no session manager or factory.", async () => {
            expect(await counters.checkDeployment(factory({}))).toBe(false);
            expect(await counters.checkDeployment({ getInstance: () => undefined } as any)).toBe(false);
            expect(await counters.checkDeployment()).toBe(false);
            expect(logger.warn).not.toHaveBeenCalled();
        });

        it("Does not need a logger.", async () => {
            (counters as any).logger = undefined;
            const store = new RedisSessionStore(new FakeRedisClient() as any);
            expect(await counters.checkDeployment(factory(store))).toBe(true);
        });

        describe("a server older than Redis 7.0", () => {
            /** What Redis 6 does with `EXPIRE key ttl NX`: the transaction is refused with a syntax error. */
            const oldRedis = (): FakeRedisClient => {
                const redis = new FakeRedisClient();
                vi.spyOn(redis, "multi").mockReturnValue({
                    incr: () => ({
                        expire: () => ({
                            exec: async () => {
                                throw new Error("ERR wrong number of arguments for 'expire' command");
                            },
                        }),
                    }),
                } as any);
                return redis;
            };

            it("Refuses to start, logging an error that names the requirement.", async () => {
                connect(counters, oldRedis());
                await expect(counters.checkDeployment()).rejects.toThrow(/Redis 7\.0 or newer/);
                expect(logger.error).toHaveBeenCalledWith(expect.stringMatching(/EXPIRE key ttl NX.*Redis 7\.0/s));
            });

            it("Refuses when the server accepts the commands but replies with something else.", async () => {
                for (const reply of [[new Error("ERR syntax error"), 0], [1, 0], [undefined, undefined], "OK"]) {
                    const redis = new FakeRedisClient();
                    vi.spyOn(redis, "multi").mockReturnValue({
                        incr: () => ({ expire: () => ({ exec: async () => reply }) }),
                    } as any);
                    await expect(connect(new OTPCounters(), redis).checkDeployment()).rejects.toThrow(/Redis 7\.0/);
                }
            });

            it("Still refuses, quietly, when there is no logger and the scratch key cannot be removed.", async () => {
                (counters as any).logger = undefined;
                const redis = oldRedis();
                vi.spyOn(redis, "del").mockRejectedValue(new Error("down"));
                connect(counters, redis);
                await expect(counters.checkDeployment()).rejects.toThrow(/Redis 7\.0/);
            });

            it("Also refuses replies that are only numeric-looking, the way increment() does.", async () => {
                for (const reply of [["1", 1], [1, "1"], [true, true]]) {
                    const redis = new FakeRedisClient();
                    vi.spyOn(redis, "multi").mockReturnValue({
                        incr: () => ({ expire: () => ({ exec: async () => reply }) }),
                    } as any);
                    await expect(connect(new OTPCounters(), redis).checkDeployment()).rejects.toThrow(/Redis 7\.0/);
                }
            });

            it("Names the version for an error reply, whatever its text.", async () => {
                class ErrorReply extends Error {}
                for (const err of [new Error("ERR syntax error"), new ErrorReply("something odd")]) {
                    const redis = new FakeRedisClient();
                    vi.spyOn(redis, "multi").mockImplementation(() => {
                        throw err;
                    });
                    const message = await connect(new OTPCounters(), redis)
                        .checkDeployment()
                        .then(() => "")
                        .catch((e) => e.message);
                    expect(message).toMatch(/Redis 7\.0 or newer/);
                    expect(message).not.toMatch(/unreachable/);
                }
            });
        });

        describe("an unreachable cache connection", () => {
            it("Refuses to start and says the connection is unreachable, not that Redis is too old.", async () => {
                for (const text of ["connect ECONNREFUSED 127.0.0.1:6379", "Socket closed unexpectedly", "The client is closed"]) {
                    const redis = new FakeRedisClient();
                    vi.spyOn(redis, "multi").mockImplementation(() => {
                        throw new Error(text);
                    });
                    const log = vi.fn();
                    const c = connect(new OTPCounters(), redis);
                    (c as any).logger = { error: log };
                    const message: string = await c
                        .checkDeployment()
                        .then(() => "")
                        .catch((e) => e.message);
                    expect(message).toMatch(/cache. connection is unreachable/);
                    expect(message).toContain(text);
                    expect(message).not.toMatch(/Redis 7\.0/);
                    expect(log).toHaveBeenCalledWith(message);
                }
            });

            it("Describes a thrown non-Error too.", async () => {
                const redis = new FakeRedisClient();
                vi.spyOn(redis, "multi").mockImplementation(() => {
                    const boom: unknown = "boom";
                    throw boom;
                });
                connect(counters, redis);
                await expect(counters.checkDeployment()).rejects.toThrow(/unreachable.*boom/);
            });
        });
    });
});

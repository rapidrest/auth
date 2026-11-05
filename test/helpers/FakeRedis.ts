///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/**
 * The few commands `RedisSessionStore` and `OTPCounters` use, over an in-memory map, with every call taking `delayMs`
 * to complete so that requests running in parallel genuinely overlap (a request reads its session, other requests read
 * and write theirs, and only then does it write back). Each command is applied atomically once its delay has passed,
 * as on a real server.
 *
 * Like the real thing, values are strings: every `get` returns the serialized copy, so two requests never share
 * session objects the way the default in-process store lets them. That sharing is what hides read-modify-write races.
 *
 * Only commands available on Redis 7 are implemented (in particular, no `INCREX`), so using it also proves the code
 * under test does not need anything newer.
 */
export class FakeRedisClient {
    public readonly values: Map<string, string> = new Map();
    /** Expiry times, in milliseconds since the epoch, of the keys that have one. */
    public readonly expiries: Map<string, number> = new Map();
    /** Every command received, in order, for assertions. */
    public readonly commands: string[] = [];

    constructor(private readonly delayMs: number = 0) {}

    private async tick(): Promise<void> {
        await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }

    /** Drops `key` if its expiry has passed. */
    private sweep(key: string): void {
        const expiry = this.expiries.get(key);
        if (expiry !== undefined && expiry <= Date.now()) {
            this.values.delete(key);
            this.expiries.delete(key);
        }
    }

    private applyGet(key: string): string | null {
        this.sweep(key);
        return this.values.get(key) ?? null;
    }

    private applySet(key: string, value: string, options?: any): string | null {
        this.sweep(key);
        if (options?.condition === "NX" && this.values.has(key)) {
            return null;
        }
        this.values.set(key, value);
        this.expiries.delete(key);
        if (options?.expiration?.type === "EX") {
            this.expiries.set(key, Date.now() + options.expiration.value * 1000);
        }
        return "OK";
    }

    private applyIncr(key: string): number {
        this.sweep(key);
        const next = Number(this.values.get(key) ?? 0) + 1;
        this.values.set(key, String(next));
        return next;
    }

    private applyExpire(key: string, seconds: number, mode?: string): number {
        this.sweep(key);
        if (!this.values.has(key)) {
            return 0;
        }
        if (mode === "NX" && this.expiries.has(key)) {
            return 0;
        }
        this.expiries.set(key, Date.now() + seconds * 1000);
        return 1;
    }

    public async get(key: string): Promise<string | null> {
        await this.tick();
        this.commands.push("GET");
        return this.applyGet(key);
    }

    public async setEx(key: string, seconds: number, value: string): Promise<void> {
        await this.tick();
        this.commands.push("SETEX");
        this.applySet(key, value, { expiration: { type: "EX", value: seconds } });
    }

    public async set(key: string, value: string, options?: any): Promise<string | null> {
        await this.tick();
        this.commands.push("SET");
        return this.applySet(key, value, options);
    }

    public async del(key: string): Promise<void> {
        await this.tick();
        this.commands.push("DEL");
        this.values.delete(key);
        this.expiries.delete(key);
    }

    /** A `MULTI`/`EXEC` transaction: the queued commands are applied together, with nothing between them. */
    public multi() {
        const queue: Array<() => any> = [];
        const tx = {
            incr: (key: string) => {
                queue.push(() => this.applyIncr(key));
                return tx;
            },
            expire: (key: string, seconds: number, mode?: string) => {
                queue.push(() => this.applyExpire(key, seconds, mode));
                return tx;
            },
            exec: async (): Promise<any[]> => {
                await this.tick();
                this.commands.push("EXEC");
                return queue.map((command) => command());
            },
        };
        return tx;
    }
}

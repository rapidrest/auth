///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthDiscoverRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseAuthDiscoverRoute } from "../../src/routes/BaseAuthDiscoverRoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { AliasType, SecretType } from "../../src/models/types.js";

function makeMockObjectFactory(aliasRepo: any, secretRepo: any, userUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeSecretClass.name) return secretRepo;
            return undefined;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        return undefined;
    });
    return { newInstance };
}

class FakeSecretClass {
    static readonly name = "FakeSecret";
}
class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeAliasClass {
    static readonly name = "FakeAlias";
}

class TestAuthDiscoverRoute extends BaseAuthDiscoverRoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

const EMPTY_RESULT = { password: false, totp: false, passkey: false, fido2: false, otp: [] };

describe("BaseAuthDiscoverRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestAuthDiscoverRoute();

            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates aliasRepo, secretRepo, and userUtils using the object factory.", async () => {
            const aliasRepo = { find: vi.fn() };
            const secretRepo = { find: vi.fn() };
            const userUtils = { lookup: vi.fn() };
            const route = new TestAuthDiscoverRoute();
            (route as any).objectFactory = makeMockObjectFactory(aliasRepo, secretRepo, userUtils);

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(aliasRepo);
            expect((route as any).secretRepo).toBe(secretRepo);
            expect((route as any).userUtils).toBe(userUtils);
        });

        it("Does not recreate repos/utils if initialize() runs again.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).objectFactory = makeMockObjectFactory({}, {}, {});
            const existingAliasRepo = { find: vi.fn() };
            const existingSecretRepo = { find: vi.fn() };
            const existingUserUtils = { lookup: vi.fn() };
            (route as any).aliasRepo = existingAliasRepo;
            (route as any).secretRepo = existingSecretRepo;
            (route as any).userUtils = existingUserUtils;

            await (route as any).initialize();

            expect((route as any).aliasRepo).toBe(existingAliasRepo);
            expect((route as any).secretRepo).toBe(existingSecretRepo);
            expect((route as any).userUtils).toBe(existingUserUtils);
        });
    });

    describe("discover", () => {
        it("Treats every secret type as absent when secretRepo is unavailable.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };

            const result = await route.discover("user-1");

            expect(result).toEqual(EMPTY_RESULT);
        });

        it("Treats verified aliases as empty when aliasRepo is unavailable.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };

            const result = await route.discover("user-1");

            expect(result).toEqual(EMPTY_RESULT);
        });

        it("Returns the equalized empty result immediately when no id is given.", async () => {
            const route = new TestAuthDiscoverRoute();
            const result = await route.discover(undefined);
            expect(result).toEqual(EMPTY_RESULT);
        });

        it("Rate-limits by the claimed identifier before doing any lookup.", async () => {
            const route = new TestAuthDiscoverRoute();
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };

            await route.discover("someone@example.com");

            expect(checkAndIncrement).toHaveBeenCalledWith("someone@example.com");
        });

        it("Propagates a rate-limit rejection (429) rather than swallowing it into the equalized result.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).rateLimiter = {
                checkAndIncrement: vi.fn().mockRejectedValue(new Error("Too many attempts.")),
            };

            await expect(route.discover("someone@example.com")).rejects.toThrow(/Too many attempts/);
        });

        it("Returns the equalized empty result when the identifier does not resolve to a user.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };

            const result = await route.discover("nobody@example.com");

            expect(result).toEqual(EMPTY_RESULT);
        });

        it("Returns the equalized empty result if an internal error occurs after resolving the user.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            (route as any).secretRepo = { find: vi.fn().mockRejectedValue(new Error("db exploded")) };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };

            const result = await route.discover("user-1");

            expect(result).toEqual(EMPTY_RESULT);
        });

        it("Reports true for each secret type the user has at least one secret of.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            const find = vi.fn(async (query: any) => {
                if (query.type === SecretType.PASSWORD) return [{ uid: "s1" }];
                if (query.type === SecretType.TOTP) return [{ uid: "s2" }];
                return [];
            });
            (route as any).secretRepo = { find };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };

            const result = await route.discover("user-1");

            expect(result.password).toBe(true);
            expect(result.totp).toBe(true);
            expect(result.passkey).toBe(false);
            expect(result.fido2).toBe(false);
        });

        it("Scopes secret/alias queries to the resolved user's own uid.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            const secretFind = vi.fn().mockResolvedValue([]);
            const aliasFind = vi.fn().mockResolvedValue([]);
            (route as any).secretRepo = { find: secretFind };
            (route as any).aliasRepo = { find: aliasFind };

            await route.discover("someone@example.com");

            expect(secretFind).toHaveBeenCalledWith(
                { type: SecretType.PASSWORD, userUid: "user-1" },
                { ignoreACL: true },
            );
            expect(aliasFind).toHaveBeenCalledWith({ userUid: "user-1", verified: true }, { ignoreACL: true });
        });

        it("Returns obfuscated email/phone hints (no uid, no real value) for verified OTP-eligible aliases.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "a1", alias: "john@example.com", type: AliasType.EMAIL, userUid: "user-1", verified: true },
                    { uid: "a2", alias: "+15551234567", type: AliasType.PHONE, userUid: "user-1", verified: true },
                ]),
            };

            const result = await route.discover("user-1");

            expect(result.otp).toEqual([
                { contact: "j***hn@example.com", type: AliasType.EMAIL },
                { contact: "********4567", type: AliasType.PHONE },
            ]);
            for (const hint of result.otp) {
                expect(hint).not.toHaveProperty("uid");
            }
        });

        it("Excludes non email/phone aliases (e.g. name/oauth) from the OTP hint list.", async () => {
            const route = new TestAuthDiscoverRoute();
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "a1", alias: "coolname", type: AliasType.NAME, userUid: "user-1", verified: true },
                ]),
            };

            const result = await route.discover("user-1");

            expect(result.otp).toEqual([]);
        });
    });

    describe("convertAliasType", () => {
        it("Throws for an unsupported alias type (e.g. name/oauth are not OTP-eligible).", () => {
            const route = new TestAuthDiscoverRoute();
            expect(() => (route as any).convertAliasType(AliasType.NAME)).toThrow(/Unsupported type/);
        });
    });
});

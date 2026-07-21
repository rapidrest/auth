///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for UserUtils — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { UserUtils } from "../../src/routes/UserUtils.js";

class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeAliasClass {
    static readonly name = "FakeAlias";
}

function makeMockObjectFactory(aliasRepo: any, userRepo: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === `${RepoUtils.name}:${FakeAliasClass.name}`) return aliasRepo;
            if (opts.name === `${RepoUtils.name}:${FakeUserClass.name}`) return userRepo;
            return undefined;
        }
        return undefined;
    });
    return { newInstance };
}

describe("UserUtils Tests", () => {
    it("Stores the given userClass and aliasClass on construction.", () => {
        const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);

        expect((userUtils as any).userClass).toBe(FakeUserClass);
        expect((userUtils as any).aliasClass).toBe(FakeAliasClass);
    });

    describe("init", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);

            await expect((userUtils as any).init()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates aliasRepo and userRepo using the object factory.", async () => {
            const aliasRepo = { findOne: vi.fn() };
            const userRepo = { findOne: vi.fn() };
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            (userUtils as any).objectFactory = makeMockObjectFactory(aliasRepo, userRepo);

            await (userUtils as any).init();

            expect((userUtils as any).aliasRepo).toBe(aliasRepo);
            expect((userUtils as any).userRepo).toBe(userRepo);
        });

        it("Does not recreate aliasRepo/userRepo if init() runs again.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            (userUtils as any).objectFactory = makeMockObjectFactory({}, {});
            const existingAliasRepo = { findOne: vi.fn() };
            const existingUserRepo = { findOne: vi.fn() };
            (userUtils as any).aliasRepo = existingAliasRepo;
            (userUtils as any).userRepo = existingUserRepo;

            await (userUtils as any).init();

            expect((userUtils as any).aliasRepo).toBe(existingAliasRepo);
            expect((userUtils as any).userRepo).toBe(existingUserRepo);
        });
    });

    describe("lookup", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            (userUtils as any).userRepo = { findOne: vi.fn() };

            await expect(userUtils.lookup("id-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if userRepo is not set.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            (userUtils as any).aliasRepo = { findOne: vi.fn() };

            await expect(userUtils.lookup("id-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Returns the user directly when the id matches a user's uid.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            const userRepo = { findOne: vi.fn().mockResolvedValue({ uid: "user-1" }) };
            const aliasRepo = { findOne: vi.fn() };
            (userUtils as any).userRepo = userRepo;
            (userUtils as any).aliasRepo = aliasRepo;

            const result = await userUtils.lookup("user-1");

            expect(userRepo.findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(result).toEqual({ uid: "user-1" });
            expect(aliasRepo.findOne).not.toHaveBeenCalled();
        });

        it("Falls back to alias lookup and resolves the owning user when the id is not a user's uid.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            const userRepo = vi
                .fn()
                .mockResolvedValueOnce(undefined)
                .mockResolvedValueOnce({ uid: "user-1" });
            const aliasRepo = { findOne: vi.fn().mockResolvedValue({ userUid: "user-1" }) };
            (userUtils as any).userRepo = { findOne: userRepo };
            (userUtils as any).aliasRepo = aliasRepo;

            const result = await userUtils.lookup("alias-value");

            expect(aliasRepo.findOne).toHaveBeenCalledWith("alias-value", { ignoreACL: true });
            expect(userRepo).toHaveBeenNthCalledWith(2, "user-1", { ignoreACL: true });
            expect(result).toEqual({ uid: "user-1" });
        });

        it("Returns undefined when neither a user nor an alias matches the id.", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            (userUtils as any).userRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (userUtils as any).aliasRepo = { findOne: vi.fn().mockResolvedValue(undefined) };

            const result = await userUtils.lookup("unknown");

            expect(result).toBeUndefined();
        });

        it("Returns undefined without querying either repo when id is not a string (NoSQL operator injection guard).", async () => {
            const userUtils = new UserUtils(FakeUserClass, FakeAliasClass);
            const userFindOne = vi.fn();
            const aliasFindOne = vi.fn();
            (userUtils as any).userRepo = { findOne: userFindOne };
            (userUtils as any).aliasRepo = { findOne: aliasFindOne };

            const result = await userUtils.lookup({ $ne: null } as any);

            expect(result).toBeUndefined();
            expect(userFindOne).not.toHaveBeenCalled();
            expect(aliasFindOne).not.toHaveBeenCalled();
        });
    });
});

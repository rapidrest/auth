///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAccountRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseAccountRoute } from "../../src/routes/BaseAccountRoute.js";

class TestAccountRoute extends BaseAccountRoute<any, any, any, any> {
    protected aliasClass: any = { name: "FakeAlias" };
    protected profileClass: any = { name: "FakeProfile" };
    protected secretClass: any = { name: "FakeSecret" };
    protected userClass: any = { name: "FakeUser" };
}

describe("BaseAccountRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("initialize", () => {
        it("Throws when objectFactory is not set.", async () => {
            const route = new TestAccountRoute();

            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates alias/profile/secret/user repos via the object factory when unset.", async () => {
            const route = new TestAccountRoute();
            const newInstance = vi.fn().mockImplementation((_ctor: any, opts: any) => Promise.resolve({ name: opts.name }));
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeAlias", args: [{ name: "FakeAlias" }] });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, {
                name: "FakeProfile",
                args: [{ name: "FakeProfile" }],
            });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, {
                name: "FakeSecret",
                args: [{ name: "FakeSecret" }],
            });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeUser", args: [{ name: "FakeUser" }] });
            expect((route as any).aliasRepo).toEqual({ name: "FakeAlias" });
            expect((route as any).profileRepo).toEqual({ name: "FakeProfile" });
            expect((route as any).secretRepo).toEqual({ name: "FakeSecret" });
            expect((route as any).userRepo).toEqual({ name: "FakeUser" });
        });

        it("Does not recreate repos that are already set.", async () => {
            const route = new TestAccountRoute();
            const newInstance = vi.fn();
            (route as any)._objectFactory = { newInstance };
            const existingAliasRepo = { find: vi.fn() };
            const existingProfileRepo = { findOne: vi.fn() };
            const existingSecretRepo = { find: vi.fn() };
            const existingUserRepo = { findOne: vi.fn() };
            (route as any).aliasRepo = existingAliasRepo;
            (route as any).profileRepo = existingProfileRepo;
            (route as any).secretRepo = existingSecretRepo;
            (route as any).userRepo = existingUserRepo;

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).aliasRepo).toBe(existingAliasRepo);
            expect((route as any).profileRepo).toBe(existingProfileRepo);
            expect((route as any).secretRepo).toBe(existingSecretRepo);
            expect((route as any).userRepo).toBe(existingUserRepo);
        });
    });

    describe("resolveOwnedUid", () => {
        it("Resolves the 'me' keyword to the caller's own uid.", () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "user-1", roles: [] };

            const result = (route as any).resolveOwnedUid("me", user);

            expect(result).toBe("user-1");
        });

        it("Returns the id unchanged when it already matches the caller's own uid.", () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "user-1", roles: [] };

            const result = (route as any).resolveOwnedUid("user-1", user);

            expect(result).toBe("user-1");
        });

        it("Throws AUTH_PERMISSION_FAILURE when a non-trusted caller targets another user's uid.", () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "attacker-uid", roles: [] };

            expect(() => (route as any).resolveOwnedUid("victim-uid", user)).toThrow(/does not have permission/i);
        });

        it("Allows a trusted (admin) caller to target another user's uid.", () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            const result = (route as any).resolveOwnedUid("victim-uid", user);

            expect(result).toBe("victim-uid");
        });

        it("Resolves 'me' to the caller's own uid even for a trusted caller (not treated as a literal target).", () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            const result = (route as any).resolveOwnedUid("me", user);

            expect(result).toBe("admin-uid");
        });
    });

    describe("cleanSecretData", () => {
        it("Strips the data property from every secret when given an array.", () => {
            const route = new TestAccountRoute();
            const secrets: any[] = [
                { uid: "secret-1", data: "sensitive-1" },
                { uid: "secret-2", data: "sensitive-2" },
            ];

            (route as any).cleanSecretData(secrets);

            expect(secrets[0].data).toBeUndefined();
            expect(secrets[1].data).toBeUndefined();
        });

        it("Strips the data property when given a single secret.", () => {
            const route = new TestAccountRoute();
            const secret: any = { uid: "secret-1", data: "sensitive-1" };

            (route as any).cleanSecretData(secret);

            expect(secret.data).toBeUndefined();
        });
    });

    describe("get", () => {
        it("Throws AUTH_PERMISSION_FAILURE when a non-trusted caller requests another user's account.", async () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "attacker-uid", roles: [] };

            await expect(route.get("victim-uid", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Throws AUTH_PERMISSION_FAILURE when the target user does not exist.", async () => {
            const route = new TestAccountRoute();
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            const user: any = { uid: "user-1", roles: [] };

            await expect(route.get("me", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Resolves 'me' to the caller's own uid and returns the aggregated account data.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "user-1" };
            const findOneUser = vi.fn().mockResolvedValue(eUser);
            const findAliases = vi.fn().mockResolvedValue([{ uid: "alias-1", userUid: "user-1" }]);
            const findOneProfile = vi.fn().mockResolvedValue({ uid: "user-1" });
            const findSecrets = vi.fn().mockResolvedValue([{ uid: "secret-1", userUid: "user-1" }]);
            (route as any).userRepo = { findOne: findOneUser };
            (route as any).aliasRepo = { find: findAliases };
            (route as any).profileRepo = { findOne: findOneProfile };
            (route as any).secretRepo = { find: findSecrets };
            const user: any = { uid: "user-1", roles: [] };

            const result = await route.get("me", user);

            expect(findOneUser).toHaveBeenCalledWith("user-1", { user });
            expect(findAliases).toHaveBeenCalledWith({ userUid: "user-1" }, { user, ignoreACL: true });
            expect(findOneProfile).toHaveBeenCalledWith("user-1", { user, ignoreACL: true });
            expect(findSecrets).toHaveBeenCalledWith({ userUid: "user-1" }, { user, ignoreACL: true });
            expect(result).toEqual({
                user: eUser,
                aliases: [{ uid: "alias-1", userUid: "user-1" }],
                profile: { uid: "user-1" },
                secrets: [{ uid: "secret-1", userUid: "user-1" }],
            });
        });

        it("Allows a trusted (admin) caller to retrieve another user's account data.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "victim-uid" };
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(eUser) };
            (route as any).aliasRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).profileRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            const result = await route.get("victim-uid", user);

            expect(result.user).toEqual(eUser);
        });

        it("Defaults aliases/secrets to empty arrays and profile to undefined when their repos are unset.", async () => {
            const route = new TestAccountRoute();
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue({ uid: "user-1" }) };

            const result = await route.get("me", { uid: "user-1", roles: [] } as any);

            expect(result).toEqual({
                user: { uid: "user-1" },
                aliases: [],
                profile: undefined,
                secrets: [],
            });
        });
    });

    describe("delete", () => {
        it("Throws AUTH_PERMISSION_FAILURE when a non-trusted caller deletes another user's account.", async () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "attacker-uid", roles: [] };

            await expect(route.delete("victim-uid", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Throws AUTH_PERMISSION_FAILURE when the target user does not exist.", async () => {
            const route = new TestAccountRoute();
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            const user: any = { uid: "user-1", roles: [] };

            await expect(route.delete("me", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Deletes all associated account data (aliases, secrets, profile, user) for the caller's own account.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "user-1" };
            const findOneUser = vi.fn().mockResolvedValue(eUser);
            const truncateAliases = vi.fn().mockResolvedValue(undefined);
            const truncateSecrets = vi.fn().mockResolvedValue(undefined);
            const deleteProfile = vi.fn().mockResolvedValue(undefined);
            const deleteUser = vi.fn().mockResolvedValue(undefined);
            (route as any).userRepo = { findOne: findOneUser, delete: deleteUser };
            (route as any).aliasRepo = { truncate: truncateAliases };
            (route as any).secretRepo = { truncate: truncateSecrets };
            (route as any).profileRepo = { delete: deleteProfile };
            const user: any = { uid: "user-1", roles: [] };

            await route.delete("me", user);

            expect(truncateAliases).toHaveBeenCalledWith({ userUid: "user-1" }, { user });
            expect(truncateSecrets).toHaveBeenCalledWith({ userUid: "user-1" }, { user });
            expect(deleteProfile).toHaveBeenCalledWith("user-1", { user, ignoreACL: true });
            expect(deleteUser).toHaveBeenCalledWith("user-1", { user });
        });

        it("Allows a trusted (admin) caller to delete another user's account data.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "victim-uid" };
            const deleteUser = vi.fn().mockResolvedValue(undefined);
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(eUser), delete: deleteUser };
            (route as any).aliasRepo = { truncate: vi.fn().mockResolvedValue(undefined) };
            (route as any).secretRepo = { truncate: vi.fn().mockResolvedValue(undefined) };
            (route as any).profileRepo = { delete: vi.fn().mockResolvedValue(undefined) };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await route.delete("victim-uid", user);

            expect(deleteUser).toHaveBeenCalledWith("victim-uid", { user });
        });

        it("Does not throw when aliasRepo/secretRepo/profileRepo are unset (optional chaining no-ops).", async () => {
            const route = new TestAccountRoute();
            (route as any).userRepo = {
                findOne: vi.fn().mockResolvedValue({ uid: "user-1" }),
                delete: vi.fn().mockResolvedValue(undefined),
            };

            await expect(route.delete("me", { uid: "user-1", roles: [] } as any)).resolves.toBeUndefined();
        });
    });

    describe("revokeSessions", () => {
        it("Throws AUTH_PERMISSION_FAILURE when a non-trusted caller targets another user's account.", async () => {
            const route = new TestAccountRoute();
            const user: any = { uid: "attacker-uid", roles: [] };

            await expect(route.revokeSessions("victim-uid", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Throws AUTH_PERMISSION_FAILURE when the target user does not exist.", async () => {
            const route = new TestAccountRoute();
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            const user: any = { uid: "user-1", roles: [] };

            await expect(route.revokeSessions("me", user)).rejects.toThrow(/does not have permission/i);
        });

        it("Sets sessionsRevokedAt to the current time on the caller's own account.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "user-1", version: 3 };
            const findOneUser = vi.fn().mockResolvedValue(eUser);
            const updateUser = vi.fn().mockResolvedValue(undefined);
            (route as any).userRepo = { findOne: findOneUser, update: updateUser };
            const user: any = { uid: "user-1", roles: [] };
            const before = Date.now();

            await route.revokeSessions("me", user);

            expect(findOneUser).toHaveBeenCalledWith("user-1", { user });
            expect(updateUser).toHaveBeenCalledTimes(1);
            const [updateObj, existingObj, options] = updateUser.mock.calls[0];
            expect(updateObj.uid).toBe("user-1");
            expect(updateObj.version).toBe(3);
            expect(updateObj.sessionsRevokedAt).toBeGreaterThanOrEqual(before);
            expect(existingObj).toBe(eUser);
            expect(options).toEqual({ user });
        });

        it("Allows a trusted (admin) caller to revoke another user's sessions.", async () => {
            const route = new TestAccountRoute();
            const eUser = { uid: "victim-uid", version: 1 };
            const updateUser = vi.fn().mockResolvedValue(undefined);
            (route as any).userRepo = { findOne: vi.fn().mockResolvedValue(eUser), update: updateUser };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await route.revokeSessions("victim-uid", user);

            expect(updateUser).toHaveBeenCalledTimes(1);
            expect(updateUser.mock.calls[0][0].uid).toBe("victim-uid");
        });
    });
});

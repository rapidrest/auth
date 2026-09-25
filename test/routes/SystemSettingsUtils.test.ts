///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for SystemSettingsUtils — no database. The repo is a plain mock.
import { ApiError } from "@rapidrest/core";
import { ApiErrors, RepoUtils } from "@rapidrest/service-core";
import { SYSTEM_SETTINGS_UID, SystemSettingsUtils } from "../../src/routes/SystemSettingsUtils.js";

class FakeSettingsClass {
    static readonly name = "FakeSettings";
    uid?: string;
    allowRegistration?: boolean;
    requireMFA?: boolean;
    allowMultiplePasswords?: boolean;
    constructor(other?: any) {
        if (other) {
            Object.assign(this, other);
        }
    }
}

function makeUtils(
    repo: any,
    allowRegistration: boolean = true,
    requireMFA: boolean = false,
    allowMultiplePasswords: boolean = false,
): SystemSettingsUtils {
    const utils = new SystemSettingsUtils(FakeSettingsClass);
    (utils as any).repo = repo;
    (utils as any).allowRegistration = allowRegistration;
    (utils as any).requireMFA = requireMFA;
    (utils as any).allowMultiplePasswords = allowMultiplePasswords;
    (utils as any).logger = { warn: vi.fn() };
    return utils;
}

describe("SystemSettingsUtils Tests", () => {
    describe("init", () => {
        it("Throws if objectFactory is not set.", async () => {
            const utils = new SystemSettingsUtils(FakeSettingsClass);
            await expect((utils as any).init()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates the settings repo using the object factory.", async () => {
            const repo = { findOne: vi.fn() };
            const newInstance = vi.fn().mockResolvedValue(repo);
            const utils = new SystemSettingsUtils(FakeSettingsClass);
            (utils as any)._objectFactory = { newInstance };

            await (utils as any).init();

            expect(newInstance).toHaveBeenCalledWith(RepoUtils, {
                name: `${RepoUtils.name}:${FakeSettingsClass.name}`,
                args: [FakeSettingsClass],
            });
            expect((utils as any).repo).toBe(repo);
        });

        it("Does not recreate the repo if init() runs again.", async () => {
            const newInstance = vi.fn();
            const existing = { findOne: vi.fn() };
            const utils = new SystemSettingsUtils(FakeSettingsClass);
            (utils as any)._objectFactory = { newInstance };
            (utils as any).repo = existing;

            await (utils as any).init();

            expect(newInstance).not.toHaveBeenCalled();
            expect((utils as any).repo).toBe(existing);
        });
    });

    describe("getEntity", () => {
        it("Throws if repo is not set.", async () => {
            const utils = new SystemSettingsUtils(FakeSettingsClass);
            await expect(utils.getEntity()).rejects.toThrow(/repo is not set/);
        });

        it("Returns the existing record without creating one.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: false, requireMFA: false };
            const repo = { findOne: vi.fn().mockResolvedValue(existing), create: vi.fn() };
            const utils = makeUtils(repo);

            await expect(utils.getEntity()).resolves.toBe(existing);
            expect(repo.findOne).toHaveBeenCalledWith(SYSTEM_SETTINGS_UID, { ignoreACL: true });
            expect(repo.create).not.toHaveBeenCalled();
        });

        it("Creates the record seeded from @Config (both fields) when none exists.", async () => {
            const repo = {
                findOne: vi.fn().mockResolvedValue(undefined),
                create: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo, false, true, true);

            const result = await utils.getEntity();

            expect(result).toBeInstanceOf(FakeSettingsClass);
            expect(result).toMatchObject({
                uid: SYSTEM_SETTINGS_UID,
                allowRegistration: false,
                requireMFA: true,
                allowMultiplePasswords: true,
            });
            expect(repo.create).toHaveBeenCalledWith(expect.any(FakeSettingsClass), { ignoreACL: true });
        });

        it("Re-reads the record when a concurrent create won the race.", async () => {
            const recovered = { uid: SYSTEM_SETTINGS_UID, allowRegistration: true, requireMFA: false };
            const repo = {
                findOne: vi.fn().mockResolvedValueOnce(undefined).mockResolvedValueOnce(recovered),
                create: vi.fn().mockRejectedValue(new ApiError(ApiErrors.IDENTIFIER_EXISTS, 400, "exists")),
            };
            const utils = makeUtils(repo);

            await expect(utils.getEntity()).resolves.toBe(recovered);
        });

        it("Rethrows IDENTIFIER_EXISTS if the record still can't be found afterwards.", async () => {
            const repo = {
                findOne: vi.fn().mockResolvedValue(undefined),
                create: vi.fn().mockRejectedValue(new ApiError(ApiErrors.IDENTIFIER_EXISTS, 400, "exists")),
            };
            const utils = makeUtils(repo);

            await expect(utils.getEntity()).rejects.toThrow(/exists/);
        });

        it("Rethrows any other create error.", async () => {
            const repo = {
                findOne: vi.fn().mockResolvedValue(undefined),
                create: vi.fn().mockRejectedValue(new Error("db down")),
            };
            const utils = makeUtils(repo);

            await expect(utils.getEntity()).rejects.toThrow(/db down/);
        });
    });

    describe("get", () => {
        it.each([true, false])("Uses the stored allowRegistration (%s) over @Config.", async (stored) => {
            const repo = { findOne: vi.fn().mockResolvedValue({ allowRegistration: stored, requireMFA: false }) };
            const utils = makeUtils(repo, !stored);

            await expect(utils.get()).resolves.toMatchObject({ allowRegistration: stored });
        });

        it.each([true, false])("Uses the stored requireMFA (%s) over @Config.", async (stored) => {
            const repo = { findOne: vi.fn().mockResolvedValue({ allowRegistration: true, requireMFA: stored }) };
            const utils = makeUtils(repo, true, !stored);

            await expect(utils.get()).resolves.toMatchObject({ requireMFA: stored });
        });

        it.each([true, false])("Uses the stored allowMultiplePasswords (%s) over @Config.", async (stored) => {
            const repo = {
                findOne: vi.fn().mockResolvedValue({ allowRegistration: true, requireMFA: false, allowMultiplePasswords: stored }),
            };
            const utils = makeUtils(repo, true, false, !stored);

            await expect(utils.get()).resolves.toMatchObject({ allowMultiplePasswords: stored });
        });

        it("Defaults allowMultiplePasswords to false: one password per account.", async () => {
            const utils = makeUtils({ findOne: vi.fn().mockResolvedValue({ allowRegistration: true }) });

            await expect(utils.get()).resolves.toMatchObject({ allowMultiplePasswords: false });
        });

        it("Falls back to @Config and logs a warning when the settings can't be read.", async () => {
            const repo = { findOne: vi.fn().mockRejectedValue(new Error("db down")) };
            const utils = makeUtils(repo, false, true, true);

            await expect(utils.get()).resolves.toMatchObject({
                allowRegistration: false,
                requireMFA: true,
                allowMultiplePasswords: true,
            });
            expect((utils as any).logger.warn).toHaveBeenCalledWith(expect.stringMatching(/db down/));
        });
    });

    describe("update", () => {
        it("Throws if repo is not set.", async () => {
            const utils = new SystemSettingsUtils(FakeSettingsClass);
            await expect(utils.update({ allowRegistration: false })).rejects.toThrow(/repo is not set/);
        });

        it("Persists a new allowRegistration value and returns the effective settings.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: true, requireMFA: false };
            const repo = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo, true);

            await expect(utils.update({ allowRegistration: false })).resolves.toMatchObject({
                allowRegistration: false,
                requireMFA: false,
            });
            expect(repo.update).toHaveBeenCalledWith(
                expect.objectContaining({ uid: SYSTEM_SETTINGS_UID, allowRegistration: false }),
                existing,
                { ignoreACL: true },
            );
        });

        it("Persists a new requireMFA value.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: true, requireMFA: false };
            const repo = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo);

            await expect(utils.update({ requireMFA: true })).resolves.toMatchObject({ requireMFA: true });
        });

        it("Persists a new allowMultiplePasswords value.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: true, requireMFA: false, allowMultiplePasswords: false };
            const repo = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo);

            await expect(utils.update({ allowMultiplePasswords: true })).resolves.toMatchObject({ allowMultiplePasswords: true });
            expect(repo.update).toHaveBeenCalledWith(
                expect.objectContaining({ uid: SYSTEM_SETTINGS_UID, allowMultiplePasswords: true }),
                existing,
                { ignoreACL: true },
            );
        });

        it("Leaves fields untouched when omitted.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: false, requireMFA: true, allowMultiplePasswords: true };
            const repo = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo, true, false);

            await expect(utils.update({})).resolves.toMatchObject({
                allowRegistration: false,
                requireMFA: true,
                allowMultiplePasswords: true,
            });
        });

        it.each([null, "true", 1, undefined])(
            "Rejects a non-boolean allowRegistration (%p) with a 400 INVALID_REQUEST, persisting nothing.",
            async (value) => {
                if (value === undefined) {
                    return; // `undefined` means "omitted" — not a rejection case, covered above.
                }
                const repo = { findOne: vi.fn(), update: vi.fn() };
                const utils = makeUtils(repo);

                await expect(utils.update({ allowRegistration: value })).rejects.toMatchObject({
                    code: ApiErrors.INVALID_REQUEST,
                    status: 400,
                });
                expect(repo.update).not.toHaveBeenCalled();
            },
        );

        it.each([null, "true", 1])(
            "Rejects a non-boolean requireMFA (%p) with a 400 INVALID_REQUEST, persisting nothing.",
            async (value) => {
                const repo = { findOne: vi.fn(), update: vi.fn() };
                const utils = makeUtils(repo);

                await expect(utils.update({ requireMFA: value })).rejects.toMatchObject({
                    code: ApiErrors.INVALID_REQUEST,
                    status: 400,
                });
                expect(repo.update).not.toHaveBeenCalled();
            },
        );

        it.each([null, "true", 1])(
            "Rejects a non-boolean allowMultiplePasswords (%p) with a 400 INVALID_REQUEST, persisting nothing.",
            async (value) => {
                const repo = { findOne: vi.fn(), update: vi.fn() };
                const utils = makeUtils(repo);

                await expect(utils.update({ allowMultiplePasswords: value })).rejects.toMatchObject({
                    code: ApiErrors.INVALID_REQUEST,
                    status: 400,
                });
                expect(repo.update).not.toHaveBeenCalled();
            },
        );

        it("Never lets an unrelated key on the input (e.g. uid) reach the persisted record.", async () => {
            const existing = { uid: SYSTEM_SETTINGS_UID, allowRegistration: true, requireMFA: false };
            const repo = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn(async (obj: any) => obj),
            };
            const utils = makeUtils(repo);

            await utils.update({ allowRegistration: false, uid: "attacker-controlled" } as any);

            expect(repo.update.mock.calls[0][0].uid).toBe(SYSTEM_SETTINGS_UID);
        });
    });
});

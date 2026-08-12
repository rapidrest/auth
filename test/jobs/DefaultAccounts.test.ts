///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for DefaultAccounts — no HTTP server, no database. Repos are mocked directly,
// mirroring the approach used by BaseAccountRoute.test.ts.
import * as argon2 from "argon2";
import { RepoUtils } from "@rapidrest/service-core";
import { DefaultAccounts, DefaultAccountConfig } from "../../src/jobs/DefaultAccounts.js";
import { PasswordConfig } from "../../src/auth/types.js";
import { AliasType, ContactType, SecretType } from "../../src/models/types.js";
import * as path from "path";
import * as fs from "fs";

class FakeAlias {
    constructor(props: any = {}) {
        Object.assign(this, props);
    }
}

class FakeProfile {
    constructor(props: any = {}) {
        Object.assign(this, props);
    }
}

class FakeSecret {
    constructor(props: any = {}) {
        Object.assign(this, props);
    }
}

class FakeUser {
    constructor(props: any = {}) {
        Object.assign(this, props);
    }
}

class TestDefaultAccounts extends DefaultAccounts<any, any, any, any> {
    protected aliasClass: any = FakeAlias;
    protected profileClass: any = FakeProfile;
    protected secretClass: any = FakeSecret;
    protected userClass: any = FakeUser;
}

/** A valid password under the default `PasswordConfig` requirements. */
const VALID_PASSWORD = "Str0ngP@ss";

function makeProfile(overrides: any = {}) {
    return { uid: "user-1", contacts: [], version: 1, ...overrides };
}

/**
 * Builds a `TestDefaultAccounts` wired with sensible default mocks:
 * - No existing alias for the account name (so a new user is created).
 * - An existing profile (so profile creation is skipped by default).
 * - An existing password secret (so password generation/hashing is skipped by default).
 * Individual tests override only the repo behavior relevant to what they're exercising.
 */
function setupDefaultAccounts(
    accounts: DefaultAccountConfig[],
    overrides: {
        trustedRoles?: string[];
        passwordConfig?: PasswordConfig;
        passwordFile?: string;
        logger?: any;
        aliasRepo?: any;
        profileRepo?: any;
        secretRepo?: any;
        userRepo?: any;
    } = {},
) {
    const job = new TestDefaultAccounts();
    (job as any).defaultAccounts = accounts;
    (job as any).trustedRoles = overrides.trustedRoles ?? ["admin"];
    (job as any).passwordConfig = overrides.passwordConfig ?? new PasswordConfig();
    (job as any).passwordFile = "passwordFile" in overrides ? overrides.passwordFile : (job as any).passwordFile;
    (job as any).logger = overrides.logger ?? { info: vi.fn() };
    (job as any).aliasRepo = overrides.aliasRepo ?? {
        find: vi.fn().mockResolvedValue([]),
        create: vi.fn().mockResolvedValue(undefined),
    };
    (job as any).profileRepo = overrides.profileRepo ?? {
        findOne: vi.fn().mockResolvedValue(makeProfile()),
        create: vi.fn(),
        update: vi.fn().mockResolvedValue(undefined),
    };
    (job as any).secretRepo = overrides.secretRepo ?? {
        find: vi.fn().mockResolvedValue([{ uid: "secret-1" }]),
        create: vi.fn(),
    };
    (job as any).userRepo = overrides.userRepo ?? {
        findOne: vi.fn(),
        create: vi.fn().mockResolvedValue({ uid: "user-1", roles: ["admin"] }),
    };
    return job;
}

describe("DefaultAccounts Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();

        const passwordFile: string = path.resolve("passwords");
        if (fs.existsSync(passwordFile)) {
            fs.unlinkSync(passwordFile);
        }
    });

    describe("init", () => {
        it("Throws when objectFactory is not set.", async () => {
            const job = new TestDefaultAccounts();

            await expect((job as any).init()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates alias/profile/secret/user repos via the object factory when unset.", async () => {
            const job = new TestDefaultAccounts();
            const newInstance = vi.fn().mockImplementation((_ctor: any, opts: any) => Promise.resolve({ name: opts.name }));
            (job as any).objectFactory = { newInstance };

            await (job as any).init();

            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeAlias", args: [FakeAlias] });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeProfile", args: [FakeProfile] });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeSecret", args: [FakeSecret] });
            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeUser", args: [FakeUser] });
            expect((job as any).aliasRepo).toEqual({ name: "FakeAlias" });
            expect((job as any).profileRepo).toEqual({ name: "FakeProfile" });
            expect((job as any).secretRepo).toEqual({ name: "FakeSecret" });
            expect((job as any).userRepo).toEqual({ name: "FakeUser" });
        });

        it("Does not recreate repos that are already set.", async () => {
            const job = new TestDefaultAccounts();
            const newInstance = vi.fn();
            (job as any).objectFactory = { newInstance };
            const existingAliasRepo = { find: vi.fn() };
            const existingProfileRepo = { findOne: vi.fn() };
            const existingSecretRepo = { find: vi.fn() };
            const existingUserRepo = { findOne: vi.fn() };
            (job as any).aliasRepo = existingAliasRepo;
            (job as any).profileRepo = existingProfileRepo;
            (job as any).secretRepo = existingSecretRepo;
            (job as any).userRepo = existingUserRepo;

            await (job as any).init();

            expect(newInstance).not.toHaveBeenCalled();
            expect((job as any).aliasRepo).toBe(existingAliasRepo);
            expect((job as any).profileRepo).toBe(existingProfileRepo);
            expect((job as any).secretRepo).toBe(existingSecretRepo);
            expect((job as any).userRepo).toBe(existingUserRepo);
        });
    });

    describe("schedule", () => {
        it("Always returns undefined (single-execution startup job).", () => {
            const job = new TestDefaultAccounts();

            expect(job.schedule).toBeUndefined();
        });
    });

    describe("run", () => {
        it("Does nothing.", () => {
            const job = new TestDefaultAccounts();

            expect(job.run()).toBeUndefined();
        });
    });

    describe("stop", () => {
        it("Does nothing.", () => {
            const job = new TestDefaultAccounts();

            expect(job.stop()).toBeUndefined();
        });
    });

    describe("start", () => {
        describe("roles", () => {
            it("Applies trustedRoles to an account with no roles configured.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, { trustedRoles: ["admin", "superuser"] });

                await job.start();

                expect(accounts[0].roles).toEqual(["admin", "superuser"]);
                expect((job as any).userRepo.create).toHaveBeenCalledWith(
                    expect.objectContaining({ roles: ["admin", "superuser"] }),
                    expect.anything(),
                );
            });

            it("Preserves an explicitly empty roles array instead of applying trustedRoles.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD, roles: [] }];
                const job = setupDefaultAccounts(accounts, { trustedRoles: ["admin"] });

                await job.start();

                expect(accounts[0].roles).toEqual([]);
                expect((job as any).userRepo.create).toHaveBeenCalledWith(
                    expect.objectContaining({ roles: [] }),
                    expect.anything(),
                );
            });

            it("Preserves explicitly configured roles.", async () => {
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, roles: ["editor"] },
                ];
                const job = setupDefaultAccounts(accounts);

                await job.start();

                expect(accounts[0].roles).toEqual(["editor"]);
            });
        });

        describe("user creation/lookup", () => {
            it("Creates a new user granting full owner ACL when no alias exists for the account name.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts);

                await job.start();

                const userRepo = (job as any).userRepo;
                expect(userRepo.create).toHaveBeenCalledTimes(1);
                const [newUser, createOptions] = userRepo.create.mock.calls[0];
                expect(newUser).toEqual(expect.objectContaining({ roles: ["admin"] }));
                expect(createOptions.user).toBe(newUser);
                expect(createOptions.acl).toEqual({
                    uid: newUser.uid,
                    records: [
                        {
                            userOrRoleId: newUser.uid,
                            actions: expect.arrayContaining([
                                "count",
                                "create",
                                "delete",
                                "exists",
                                "read",
                                "list",
                                "truncate",
                                "update",
                            ]),
                        },
                    ],
                });
            });

            it("Looks up an existing alias for the account name before deciding whether to create a user.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts);

                await job.start();

                expect((job as any).aliasRepo.find).toHaveBeenCalledWith({ alias: "admin" }, { ignoreACL: true });
            });

            it("Reuses the existing user found via alias lookup instead of creating a new one.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const aliasFind = vi.fn().mockImplementation((query: any) => {
                    if ("alias" in query) {
                        return Promise.resolve([{ userUid: "existing-1" }]);
                    }
                    return Promise.resolve([]);
                });
                const userFindOne = vi.fn().mockResolvedValue({ uid: "existing-1", roles: ["admin"] });
                const userCreate = vi.fn();
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: aliasFind, create: vi.fn().mockResolvedValue(undefined) },
                    userRepo: { findOne: userFindOne, create: userCreate },
                });

                await job.start();

                expect(userFindOne).toHaveBeenCalledWith("existing-1", { ignoreACL: true });
                expect(userCreate).not.toHaveBeenCalled();
            });

            it("Creates a new user when an alias exists but its referenced user does not.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const aliasFind = vi.fn().mockImplementation((query: any) => {
                    if ("alias" in query) {
                        return Promise.resolve([{ userUid: "ghost-1" }]);
                    }
                    return Promise.resolve([]);
                });
                const userFindOne = vi.fn().mockResolvedValue(undefined);
                const userCreate = vi.fn().mockResolvedValue({ uid: "user-1", roles: ["admin"] });
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: aliasFind, create: vi.fn().mockResolvedValue(undefined) },
                    userRepo: { findOne: userFindOne, create: userCreate },
                });

                await job.start();

                expect(userCreate).toHaveBeenCalledTimes(1);
            });

            it("Treats a nullish alias lookup result as no existing alias and creates a new user.", async () => {
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const userCreate = vi.fn().mockResolvedValue({ uid: "user-1", roles: ["admin"] });
                const aliasFind = vi.fn().mockImplementation((query: any) =>
                    "alias" in query ? Promise.resolve(undefined) : Promise.resolve([]),
                );
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: aliasFind, create: vi.fn().mockResolvedValue(undefined) },
                    userRepo: { findOne: vi.fn(), create: userCreate },
                });

                await job.start();

                expect(userCreate).toHaveBeenCalledTimes(1);
            });
        });

        describe("profile sync", () => {
            it("Skips contact merging and the profile update when profile creation yields no profile.", async () => {
                const profileUpdate = vi.fn();
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, email: "admin@example.com" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(undefined),
                        create: vi.fn().mockResolvedValue(undefined),
                        update: profileUpdate,
                    },
                });

                await job.start();

                expect(profileUpdate).not.toHaveBeenCalled();
            });

            it("Creates a profile with a default given name when the user has none yet.", async () => {
                const profileCreate = vi.fn().mockImplementation((obj: any) => Promise.resolve(obj));
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(undefined),
                        create: profileCreate,
                        update: vi.fn().mockResolvedValue(undefined),
                    },
                });

                await job.start();

                expect(profileCreate).toHaveBeenCalledTimes(1);
                const [newProfile] = profileCreate.mock.calls[0];
                expect(newProfile).toEqual(
                    expect.objectContaining({ uid: "user-1", contacts: [], givenName: "Administrator" }),
                );
            });

            it("Does not create a profile when one already exists.", async () => {
                const profileCreate = vi.fn();
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(makeProfile()),
                        create: profileCreate,
                        update: vi.fn().mockResolvedValue(undefined),
                    },
                });

                await job.start();

                expect(profileCreate).not.toHaveBeenCalled();
            });

            it("Adds a new (lowercased) email contact to the profile when missing.", async () => {
                const profileUpdate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, email: "Admin@Example.com" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(makeProfile({ contacts: [] })),
                        create: vi.fn(),
                        update: profileUpdate,
                    },
                });

                await job.start();

                const [updatedFields] = profileUpdate.mock.calls[0];
                expect(updatedFields.contacts).toEqual([
                    { contact: "admin@example.com", type: ContactType.EMAIL, verified: true },
                ]);
            });

            it("Does not duplicate an existing email contact.", async () => {
                const profileUpdate = vi.fn().mockResolvedValue(undefined);
                const existingContacts = [{ contact: "admin@example.com", type: ContactType.EMAIL, verified: true }];
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, email: "Admin@Example.com" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(makeProfile({ contacts: existingContacts })),
                        create: vi.fn(),
                        update: profileUpdate,
                    },
                });

                await job.start();

                const [updatedFields] = profileUpdate.mock.calls[0];
                expect(updatedFields.contacts).toEqual(existingContacts);
            });

            it("Adds a new phone contact to the profile when missing.", async () => {
                const profileUpdate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, phone: "555-1234" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(makeProfile({ contacts: [] })),
                        create: vi.fn(),
                        update: profileUpdate,
                    },
                });

                await job.start();

                const [updatedFields] = profileUpdate.mock.calls[0];
                expect(updatedFields.contacts).toEqual([
                    { contact: "555-1234", type: ContactType.PHONE, verified: true },
                ]);
            });

            it("Does not duplicate an existing phone contact.", async () => {
                const profileUpdate = vi.fn().mockResolvedValue(undefined);
                const existingContacts = [{ contact: "555-1234", type: ContactType.PHONE, verified: true }];
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, phone: "555-1234" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    profileRepo: {
                        findOne: vi.fn().mockResolvedValue(makeProfile({ contacts: existingContacts })),
                        create: vi.fn(),
                        update: profileUpdate,
                    },
                });

                await job.start();

                const [updatedFields] = profileUpdate.mock.calls[0];
                expect(updatedFields.contacts).toEqual(existingContacts);
            });
        });

        describe("alias sync", () => {
            it("Creates a missing name alias, trimmed and lowercased.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [{ name: " Admin ", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: vi.fn().mockResolvedValue([]), create: aliasCreate },
                });

                await job.start();

                expect(aliasCreate).toHaveBeenCalledWith(
                    { alias: "admin", type: AliasType.NAME, userUid: "user-1", verified: true },
                    { user: expect.anything() },
                );
            });

            it("Does not create a name alias when account.name is falsy.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [{ name: "", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: vi.fn().mockResolvedValue([]), create: aliasCreate },
                });

                await job.start();

                expect(aliasCreate).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AliasType.NAME }),
                    expect.anything(),
                );
            });

            it("Skips creating a name alias when one already exists.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: {
                        find: vi
                            .fn()
                            .mockImplementation((query: any) =>
                                "alias" in query
                                    ? Promise.resolve([])
                                    : Promise.resolve([{ type: AliasType.NAME, alias: "admin" }]),
                            ),
                        create: aliasCreate,
                    },
                });

                await job.start();

                expect(aliasCreate).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AliasType.NAME }),
                    expect.anything(),
                );
            });

            it("Creates a missing email alias, trimmed and lowercased, when an email is configured.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, email: " Admin@Example.com " },
                ];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: vi.fn().mockResolvedValue([]), create: aliasCreate },
                });

                await job.start();

                expect(aliasCreate).toHaveBeenCalledWith(
                    { alias: "admin@example.com", type: AliasType.EMAIL, userUid: "user-1", verified: true },
                    { user: expect.anything() },
                );
            });

            it("Skips creating an email alias when one already exists.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, email: "admin@example.com" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: {
                        find: vi
                            .fn()
                            .mockImplementation((query: any) =>
                                "alias" in query
                                    ? Promise.resolve([])
                                    : Promise.resolve([{ type: AliasType.EMAIL, alias: "admin@example.com" }]),
                            ),
                        create: aliasCreate,
                    },
                });

                await job.start();

                expect(aliasCreate).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AliasType.EMAIL }),
                    expect.anything(),
                );
            });

            it("Creates a missing phone alias, trimmed, when a phone is configured.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, phone: " 555-1234 " },
                ];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: { find: vi.fn().mockResolvedValue([]), create: aliasCreate },
                });

                await job.start();

                expect(aliasCreate).toHaveBeenCalledWith(
                    { alias: "555-1234", type: AliasType.PHONE, userUid: "user-1", verified: true },
                    { user: expect.anything() },
                );
            });

            it("Skips creating a phone alias when one already exists.", async () => {
                const aliasCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, phone: "555-1234" },
                ];
                const job = setupDefaultAccounts(accounts, {
                    aliasRepo: {
                        find: vi
                            .fn()
                            .mockImplementation((query: any) =>
                                "alias" in query
                                    ? Promise.resolve([])
                                    : Promise.resolve([{ type: AliasType.PHONE, alias: "555-1234" }]),
                            ),
                        create: aliasCreate,
                    },
                });

                await job.start();

                expect(aliasCreate).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AliasType.PHONE }),
                    expect.anything(),
                );
            });
        });

        describe("password secret", () => {
            it("Does not touch secrets when a password secret already exists.", async () => {
                const secretCreate = vi.fn();
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const logger = { info: vi.fn() };
                const job = setupDefaultAccounts(accounts, {
                    logger,
                    secretRepo: { find: vi.fn().mockResolvedValue([{ uid: "secret-1" }]), create: secretCreate },
                });

                await job.start();

                expect(secretCreate).not.toHaveBeenCalled();
                expect(logger.info).not.toHaveBeenCalled();
            });

            it("Creates a hashed password secret using the configured password when none exists yet.", async () => {
                const secretCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [{ name: "admin", password: VALID_PASSWORD }];
                const job = setupDefaultAccounts(accounts, {
                    secretRepo: { find: vi.fn().mockResolvedValue([]), create: secretCreate },
                });

                await job.start();

                expect(secretCreate).toHaveBeenCalledTimes(1);
                const [secret, options] = secretCreate.mock.calls[0];
                expect(secret.type).toBe(SecretType.PASSWORD);
                expect(secret.userUid).toBe("user-1");
                expect(options.user).toBeDefined();
                await expect(argon2.verify(secret.data, VALID_PASSWORD)).resolves.toBe(true);
            });

            it("Randomly generates a password satisfying the password config when none is configured, and logs it.", async () => {
                const shared = await import("../../src/auth/shared.js");
                const generatePasswordSpy = vi.spyOn(shared, "generatePassword").mockReturnValue("Gener@ted1Pw");
                const secretCreate = vi.fn().mockResolvedValue(undefined);
                const passwordConfig = new PasswordConfig();
                const accounts: DefaultAccountConfig[] = [{ name: "admin" }];
                const logger = { info: vi.fn() };
                const job = setupDefaultAccounts(accounts, {
                    passwordConfig,
                    logger,
                    secretRepo: { find: vi.fn().mockResolvedValue([]), create: secretCreate },
                });

                await job.start();

                expect(generatePasswordSpy).toHaveBeenCalledWith(passwordConfig);
                expect(accounts[0].password).toBe("Gener@ted1Pw");
                const [secret] = secretCreate.mock.calls[0];
                await expect(argon2.verify(secret.data, "Gener@ted1Pw")).resolves.toBe(true);
            });

            it("Writes the generated account information to default file once a password secret is created.", async () => {
                const secretCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, roles: ["admin"] },
                ];
                const job = setupDefaultAccounts(accounts, {
                    secretRepo: { find: vi.fn().mockResolvedValue([]), create: secretCreate },
                });

                await job.start();

                const filePath: string = path.resolve((job as any).passwordFile);
                const fileContents: string = fs.readFileSync(filePath, { encoding: "utf-8" });
                expect(fileContents).toContain(`Name=admin,Password=${VALID_PASSWORD}`);

                fs.unlinkSync(filePath);
            });

            it("Writes the generated account information to custom file once a password secret is created.", async () => {
                const passwordFile: string = path.resolve("custom-password-file");
                const secretCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, roles: ["admin"] },
                ];
                const job = setupDefaultAccounts(accounts, {
                    secretRepo: { find: vi.fn().mockResolvedValue([]), create: secretCreate },
                    passwordFile,
                });

                await job.start();

                const fileContents: string = fs.readFileSync(passwordFile, { encoding: "utf-8" });
                expect(fileContents).toContain(`Name=admin,Password=${VALID_PASSWORD}`);

                fs.unlinkSync(passwordFile);
            });

            it("Logs the generated account information when no passwordFile is set once a password secret is created.", async () => {
                const secretCreate = vi.fn().mockResolvedValue(undefined);
                const accounts: DefaultAccountConfig[] = [
                    { name: "admin", password: VALID_PASSWORD, roles: ["admin"] },
                ];
                const logger = { info: vi.fn() };
                const job = setupDefaultAccounts(accounts, {
                    logger,
                    passwordFile: undefined,
                    secretRepo: { find: vi.fn().mockResolvedValue([]), create: secretCreate },
                });

                await job.start();

                const loggedLines = logger.info.mock.calls.map((call: any[]) => call[0]);
                expect(loggedLines).toEqual(
                    expect.arrayContaining([`Name: admin`, `Password: '${VALID_PASSWORD}'`, `Roles: admin`]),
                );
            });
        });

        it("Processes every configured account.", async () => {
            const accounts: DefaultAccountConfig[] = [
                { name: "admin", password: VALID_PASSWORD },
                { name: "support", password: VALID_PASSWORD },
            ];
            const userCreate = vi
                .fn()
                .mockResolvedValueOnce({ uid: "user-1", roles: ["admin"] })
                .mockResolvedValueOnce({ uid: "user-2", roles: ["admin"] });
            const job = setupDefaultAccounts(accounts, {
                userRepo: { findOne: vi.fn(), create: userCreate },
            });

            await job.start();

            expect(userCreate).toHaveBeenCalledTimes(2);
        });
    });
});

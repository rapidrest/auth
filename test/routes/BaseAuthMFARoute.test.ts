///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthMFARoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { MFAMethodType, MFAStrategy } from "../../src/auth/MFAStrategy.js";
import { BaseAuthMFARoute } from "../../src/routes/BaseAuthMFARoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { AliasType, SecretType } from "../../src/models/types.js";
import { OTPContactType } from "../../src/auth/types.js";

class FakeSecretClass {
    static readonly name = "FakeSecret";
}
class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeAliasClass {
    static readonly name = "FakeAlias";
}

class TestAuthMFARoute extends BaseAuthMFARoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(aliasRepo: any, secretRepo: any, userRepo: any, userUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeSecretClass.name) return secretRepo;
            if (opts.name === FakeUserClass.name) return userRepo;
            return undefined;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        if (type === MFAStrategy) {
            return new MFAStrategy(opts.args[0]);
        }
        return undefined;
    });
    return { newInstance };
}

describe("BaseAuthMFARoute Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthMFARoute();
        (route as any).objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthMFARoute();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate repos/utils if initialize() runs again.", async () => {
        const route = new TestAuthMFARoute();
        (route as any).authMiddleware = { register: vi.fn() };
        (route as any).objectFactory = makeMockObjectFactory({}, {}, {}, {});
        const existingAliasRepo = { find: vi.fn() };
        const existingSecretRepo = { find: vi.fn() };
        const existingUserRepo = { find: vi.fn() };
        const existingUserUtils = { lookup: vi.fn() };
        (route as any).aliasRepo = existingAliasRepo;
        (route as any).secretRepo = existingSecretRepo;
        (route as any).userRepo = existingUserRepo;
        (route as any).userUtils = existingUserUtils;

        await (route as any).initialize();

        expect((route as any).aliasRepo).toBe(existingAliasRepo);
        expect((route as any).secretRepo).toBe(existingSecretRepo);
        expect((route as any).userRepo).toBe(existingUserRepo);
        expect((route as any).userUtils).toBe(existingUserUtils);
    });

    it("Registers an MFAStrategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthMFARoute();
        (route as any).authMiddleware = { register };
        (route as any).objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("mfa", expect.any(MFAStrategy));
    });

    describe("convertAliasToMethod", () => {
        it("Converts an EMAIL alias into an OTP method.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "user@example.com",
                type: AliasType.EMAIL,
                verified: true,
            });

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "user@example.com", type: OTPContactType.EMAIL, verified: true },
                type: MFAMethodType.OTP,
            });
        });

        it("Obfuscates an EMAIL alias's contact when requested.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod(
                { uid: "alias-1", alias: "user@example.com", type: AliasType.EMAIL, verified: true },
                true,
            );

            expect(result.data.contact).not.toBe("user@example.com");
        });

        it("Converts a PHONE alias into an OTP method.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "+15551234567",
                type: AliasType.PHONE,
                verified: false,
            });

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "+15551234567", type: OTPContactType.SMS, verified: false },
                type: MFAMethodType.OTP,
            });
        });

        it("Obfuscates a PHONE alias's contact when requested.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod(
                { uid: "alias-1", alias: "+15551234567", type: AliasType.PHONE, verified: false },
                true,
            );

            expect(result.data.contact).not.toBe("+15551234567");
        });

        it("Returns undefined for an alias type that has no MFA equivalent.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "John Doe",
                type: AliasType.NAME,
                verified: false,
            });

            expect(result).toBeUndefined();
        });
    });

    describe("convertSecretToMethod", () => {
        it("Converts a FIDO2 secret into a FIDO2 method.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.FIDO2,
                data: { id: "cred-1" },
            });

            expect(result).toEqual({ id: "secret-1", data: { id: "cred-1" }, type: MFAMethodType.FIDO2 });
        });

        it("Converts a TOTP secret into a TOTP method.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.TOTP,
                data: { secret: "AAAA" },
            });

            expect(result).toEqual({ id: "secret-1", data: { secret: "AAAA" }, type: MFAMethodType.TOTP });
        });

        it("Returns undefined for a secret type that has no MFA equivalent.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertSecretToMethod({
                uid: "secret-1",
                type: SecretType.PASSWORD,
                data: "hash",
            });

            expect(result).toBeUndefined();
        });
    });

    describe("getMethod", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { findOne: vi.fn() };
            await expect((route as any).getMethod("id-1", "user-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).aliasRepo = { findOne: vi.fn() };
            await expect((route as any).getMethod("id-1", "user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns the method for a matching secret owned by the given uid.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = {
                findOne: vi.fn().mockResolvedValue({ uid: "secret-1", userUid: "user-1", type: SecretType.TOTP, data: {} }),
            };
            (route as any).aliasRepo = { findOne: vi.fn() };

            const result = await (route as any).getMethod("secret-1", "user-1");

            expect(result).toEqual({ id: "secret-1", data: {}, type: MFAMethodType.TOTP });
            expect((route as any).aliasRepo.findOne).not.toHaveBeenCalled();
        });

        it("Returns undefined when the matching secret belongs to a different user.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = {
                findOne: vi.fn().mockResolvedValue({ uid: "secret-1", userUid: "attacker-1", type: SecretType.TOTP, data: {} }),
            };
            (route as any).aliasRepo = { findOne: vi.fn() };

            const result = await (route as any).getMethod("secret-1", "victim-1");

            expect(result).toBeUndefined();
        });

        it("Falls back to alias lookup when no secret matches.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    userUid: "user-1",
                    alias: "user@example.com",
                    type: AliasType.EMAIL,
                    verified: true,
                }),
            };

            const result = await (route as any).getMethod("alias-1", "user-1");

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "user@example.com", type: OTPContactType.EMAIL, verified: true },
                type: MFAMethodType.OTP,
            });
        });

        it("Returns undefined when the matching alias belongs to a different user.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    userUid: "attacker-1",
                    alias: "attacker@example.com",
                    type: AliasType.EMAIL,
                    verified: true,
                }),
            };

            const result = await (route as any).getMethod("alias-1", "victim-1");

            expect(result).toBeUndefined();
        });

        it("Returns undefined when neither a secret nor an alias matches.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
            (route as any).aliasRepo = { findOne: vi.fn().mockResolvedValue(undefined) };

            const result = await (route as any).getMethod("unknown", "user-1");

            expect(result).toBeUndefined();
        });

        it("Returns undefined without querying the repos when id or uid is not a string.", async () => {
            const route = new TestAuthMFARoute();
            const secretFindOne = vi.fn();
            const aliasFindOne = vi.fn();
            (route as any).secretRepo = { findOne: secretFindOne };
            (route as any).aliasRepo = { findOne: aliasFindOne };

            const result = await (route as any).getMethod({ $ne: null }, "user-1");

            expect(result).toBeUndefined();
            expect(secretFindOne).not.toHaveBeenCalled();
            expect(aliasFindOne).not.toHaveBeenCalled();
        });
    });

    describe("getMethods", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userRepo = { find: vi.fn() };
            await expect((route as any).getMethods("user-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).aliasRepo = { find: vi.fn() };
            (route as any).userRepo = { find: vi.fn() };
            await expect((route as any).getMethods("user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Throws if userRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).aliasRepo = { find: vi.fn() };
            (route as any).secretRepo = { find: vi.fn() };
            await expect((route as any).getMethods("user-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Combines eligible secrets and aliases into a list of methods.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "secret-1", type: SecretType.TOTP, data: {} },
                    { uid: "secret-2", type: SecretType.PASSWORD, data: "hash" },
                ]),
            };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "user@example.com", type: AliasType.EMAIL, verified: true },
                    { uid: "alias-2", alias: "John Doe", type: AliasType.NAME, verified: true },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(2);
            expect(result[0]).toEqual({ id: "secret-1", data: {}, type: MFAMethodType.TOTP });
            expect(result[1].type).toBe(MFAMethodType.OTP);
        });
    });

    describe("getUser", () => {
        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthMFARoute();
            await expect((route as any).getUser("user-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Delegates to userUtils.lookup().", async () => {
            const route = new TestAuthMFARoute();
            const lookup = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).userUtils = { lookup };

            const result = await (route as any).getUser("user-1");

            expect(lookup).toHaveBeenCalledWith("user-1");
            expect(result).toEqual({ uid: "user-1" });
        });
    });

    describe("notifyContact", () => {
        it("Sends an email when the contact type is EMAIL.", async () => {
            const route = new TestAuthMFARoute();
            const sendEmail = vi.fn();
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn() };

            await (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456");

            expect(sendEmail).toHaveBeenCalledWith(
                "login-otp",
                { totp: "123456" },
                { to: "user@example.com" },
            );
        });

        it("Sends an SMS when the contact type is SMS.", async () => {
            const route = new TestAuthMFARoute();
            const sendSMS = vi.fn();
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };

            await (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456");

            expect(sendSMS).toHaveBeenCalledWith(
                "login-otp",
                { totp: "123456" },
                { to: "+15551234567" },
            );
        });

        it("Does nothing (and does not throw) when messagingUtils is unset.", async () => {
            const route = new TestAuthMFARoute();
            await expect(
                (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).resolves.toBeUndefined();
        });
    });

    describe("obfuscateAlias", () => {
        it("Obfuscates an EMAIL alias.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).obfuscateAlias("user@example.com", AliasType.EMAIL);
            expect(result).not.toBe("user@example.com");
            expect(result).toContain("@example.com");
        });

        it("Obfuscates a NAME alias.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).obfuscateAlias("John Doe", AliasType.NAME);
            expect(result).not.toBe("John Doe");
        });

        it("Obfuscates a PHONE alias.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).obfuscateAlias("+15551234567", AliasType.PHONE);
            expect(result).not.toBe("+15551234567");
        });

        it("Returns the alias unchanged for an unhandled type.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).obfuscateAlias("something", "unknown-type");
            expect(result).toBe("something");
        });
    });

    describe("verify", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).userUtils = { lookup: vi.fn() };
            await expect((route as any).verify("user1", "pass1")).rejects.toThrow(/Secret repository not set/);
        });

        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn() };
            await expect((route as any).verify("user1", "pass1")).rejects.toThrow(/User repository not set/);
        });

        it("Throws when the user cannot be found.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };

            await expect((route as any).verify("unknown-user", "pass1")).rejects.toThrow(
                /Invalid authorization request/,
            );
        });

        it("Performs a dummy Argon2 verification when the user cannot be found, to equalize response timing.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn() };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect((route as any).verify("unknown-user", "pass1")).rejects.toThrow(
                /Invalid authorization request/,
            );

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1");
        });

        it("Throws when none of the user's stored passwords match.", async () => {
            const route = new TestAuthMFARoute();
            const argon2 = await import("argon2");
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([{ data: await argon2.hash("correct-password") }]),
            };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };

            await expect((route as any).verify("user1", "wrong-password")).rejects.toThrow(
                /Invalid authorization request/,
            );
        });

        it("Resolves the user when at least one stored password matches.", async () => {
            const route = new TestAuthMFARoute();
            const argon2 = await import("argon2");
            (route as any).secretRepo = {
                find: vi.fn().mockResolvedValue([
                    { data: await argon2.hash("another-password") },
                    { data: await argon2.hash("correct-password") },
                ]),
            };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };

            const user = await (route as any).verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
        });
    });
});

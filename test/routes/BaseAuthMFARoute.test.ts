///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
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
                verified: true,
            });

            expect(result).toEqual({
                id: "alias-1",
                data: { contact: "+15551234567", type: OTPContactType.SMS, verified: true },
                type: MFAMethodType.OTP,
            });
        });

        it("Obfuscates a PHONE alias's contact when requested.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod(
                { uid: "alias-1", alias: "+15551234567", type: AliasType.PHONE, verified: true },
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
                verified: true,
            });

            expect(result).toBeUndefined();
        });

        // Regression: a 2FA method must be a *proven* point of contact. Without this check, a caller
        // holding only the account's password could add a brand-new, self-controlled, unverified
        // email/phone alias via BaseAliasRoute.create() (which requires no elevation), then use it as a
        // 2FA method to receive and submit a real OTP code — completing 2FA without ever proving anything
        // beyond knowledge of the password. Mirrors BaseAuthElevationRoute.convertAliasToMethod()'s guard.
        it("Returns undefined for an unverified EMAIL alias, even though it would otherwise convert.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "attacker@evil.com",
                type: AliasType.EMAIL,
                verified: false,
            });

            expect(result).toBeUndefined();
        });

        it("Returns undefined for an unverified PHONE alias, even though it would otherwise convert.", () => {
            const route = new TestAuthMFARoute();
            const result = (route as any).convertAliasToMethod({
                uid: "alias-1",
                alias: "+15551234567",
                type: AliasType.PHONE,
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

    describe("getCredentialById", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            await expect((route as any).getCredentialById("cred-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns undefined if no matching secret exists.", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(findOne).toHaveBeenCalledWith("cred-1", { ignoreACL: true });
            expect(result).toBeUndefined();
        });

        it("Returns undefined without querying the repo when credentialId is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn();
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById({ $ne: null });

            expect(result).toBeUndefined();
            expect(findOne).not.toHaveBeenCalled();
        });

        it("Returns the .data of a matching secret of type FIDO2.", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.FIDO2, data: { id: "cred-1" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(result).toEqual({ id: "cred-1" });
        });

        it("Returns undefined for a matching secret of a different type (e.g. PASSKEY).", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.PASSKEY, data: { id: "cred-1" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

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

        // Regression: this list is returned to the client (see the class doc comment above getMethods()),
        // so a real contact value here would leak a compromised account's email/phone to whoever holds the
        // (possibly stolen) access token.
        it("Obfuscates alias contact info in the returned methods.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "user@example.com", type: AliasType.EMAIL, verified: true },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(1);
            expect(result[0].data.contact).not.toBe("user@example.com");
            expect(result[0].data.contact).toBe((route as any).obfuscateAlias("user@example.com", AliasType.EMAIL));
        });

        // Regression: an unverified alias must never be offered as a 2FA method — see
        // convertAliasToMethod's regression test for the full exploit this closes.
        it("Excludes unverified aliases from the list of methods.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).aliasRepo = {
                find: vi.fn().mockResolvedValue([
                    { uid: "alias-1", alias: "verified@example.com", type: AliasType.EMAIL, verified: true },
                    { uid: "alias-2", alias: "attacker@evil.com", type: AliasType.EMAIL, verified: false },
                ]),
            };
            (route as any).userRepo = {};

            const result = await (route as any).getMethods("user-1");

            expect(result).toHaveLength(1);
            expect(result[0].id).toBe("alias-1");
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
            const sendEmail = vi.fn().mockResolvedValue(undefined);
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
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn(), sendSMS };

            await (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456");

            expect(sendSMS).toHaveBeenCalledWith(
                "login-otp",
                { totp: "123456" },
                { to: "+15551234567" },
            );
        });

        // Regression: a rejected sendEmail/sendSMS promise used to have no .catch(), so under Node's
        // default `--unhandled-rejections=throw` a single transient messaging-provider failure during an
        // MFA challenge send would crash the entire process for every user, not just this request.
        it("Does not throw (and logs instead) when sendEmail rejects.", async () => {
            const route = new TestAuthMFARoute();
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockRejectedValue(new Error("provider unavailable")),
                sendSMS: vi.fn(),
            };

            await expect(
                (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).resolves.toBeUndefined();
            // Flush the rejected .catch() microtask registered inside notifyContact.
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification e-mail"));
        });

        it("Does not throw (and logs instead) when sendSMS rejects.", async () => {
            const route = new TestAuthMFARoute();
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn(),
                sendSMS: vi.fn().mockRejectedValue(new Error("provider unavailable")),
            };

            await expect(
                (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456"),
            ).resolves.toBeUndefined();
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification SMS"));
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

    describe("updateCredentialCounter", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            await expect((route as any).updateCredentialCounter("cred-1", 5)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's counter when a matching secret is found.", async () => {
            const route = new TestAuthMFARoute();
            const secret = { uid: "secret-1", version: 1, data: { id: "cred-1", counter: 1 } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(secret.data.counter).toBe(5);
            expect(update).toHaveBeenCalledWith(
                { uid: "secret-1", version: 1, data: secret.data },
                secret,
                { ignoreACL: true, recordEvent: false },
            );
        });
    });

    describe("updateSecretTimeStep", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthMFARoute();
            await expect((route as any).updateSecretTimeStep("secret-1", 42)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthMFARoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's lastTimeStep when a matching secret is found.", async () => {
            const route = new TestAuthMFARoute();
            const secret = { uid: "secret-1", version: 1, data: { secret: "abc" } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(secret.data.lastTimeStep).toBe(42);
            expect(update).toHaveBeenCalledWith(
                { uid: "secret-1", version: 1, data: secret.data },
                secret,
                { ignoreACL: true, recordEvent: false },
            );
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

        // Regression: the dummy-Argon2 timing equalization above only covered the "no such user" case —
        // when the user exists but has zero password-type secrets (e.g. an OIDC-only/passkey-only account),
        // the verify loop used to never execute at all, returning near-instantly and creating a third,
        // faster timing class an attacker could use to distinguish this case via response latency.
        it("Performs a dummy Argon2 verification when the user has no password secret, to equalize response timing.", async () => {
            const route = new TestAuthMFARoute();
            (route as any).secretRepo = { find: vi.fn().mockResolvedValue([]) };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect((route as any).verify("user1", "pass1")).rejects.toThrow(/Invalid authorization request/);

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

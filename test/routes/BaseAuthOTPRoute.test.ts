///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthOTPRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { OTPStrategy } from "../../src/auth/OTPStrategy.js";
import { BaseAuthOTPRoute } from "../../src/routes/BaseAuthOTPRoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { AliasType } from "../../src/models/types.js";
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

class TestAuthOTPRoute extends BaseAuthOTPRoute<any, any, any> {
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
        if (type === OTPStrategy) {
            return new OTPStrategy(opts.args[0]);
        }
        return undefined;
    });
    return { newInstance };
}

describe("BaseAuthOTPRoute Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthOTPRoute();
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthOTPRoute();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate repos/utils if initialize() runs again.", async () => {
        const route = new TestAuthOTPRoute();
        (route as any).authMiddleware = { register: vi.fn() };
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});
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

    it("Registers an OTPStrategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthOTPRoute();
        (route as any).authMiddleware = { register };
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("otp", expect.any(OTPStrategy));
    });

    describe("convertAliasType", () => {
        it("Converts EMAIL to OTPContactType.EMAIL.", () => {
            const route = new TestAuthOTPRoute();
            expect((route as any).convertAliasType(AliasType.EMAIL)).toBe(OTPContactType.EMAIL);
        });

        it("Converts PHONE to OTPContactType.SMS.", () => {
            const route = new TestAuthOTPRoute();
            expect((route as any).convertAliasType(AliasType.PHONE)).toBe(OTPContactType.SMS);
        });

        it("Throws for an unsupported alias type.", () => {
            const route = new TestAuthOTPRoute();
            expect(() => (route as any).convertAliasType(AliasType.NAME)).toThrow(/Unsupported type/);
        });
    });

    describe("getContact", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthOTPRoute();
            await expect((route as any).getContact("alias-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Returns undefined if no matching alias exists.", async () => {
            const route = new TestAuthOTPRoute();
            (route as any).aliasRepo = { findOne: vi.fn().mockResolvedValue(undefined) };

            const result = await (route as any).getContact("alias-1");

            expect(result).toBeUndefined();
        });

        it("Returns the contact for a matching alias.", async () => {
            const route = new TestAuthOTPRoute();
            (route as any).aliasRepo = {
                findOne: vi
                    .fn()
                    .mockResolvedValue({ alias: "user@example.com", type: AliasType.EMAIL, verified: true }),
            };

            const result = await (route as any).getContact("alias-1");

            expect(result).toEqual({ contact: "user@example.com", type: OTPContactType.EMAIL, verified: true });
        });

        it("Returns undefined without querying the repo when id is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn();
            (route as any).aliasRepo = { findOne };

            const result = await (route as any).getContact({ $ne: null });

            expect(result).toBeUndefined();
            expect(findOne).not.toHaveBeenCalled();
        });
    });

    describe("getContacts", () => {
        it("Throws if aliasRepo is not set.", async () => {
            const route = new TestAuthOTPRoute();
            (route as any).userRepo = { findOne: vi.fn() };
            await expect((route as any).getContacts("id-1")).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if userRepo is not set.", async () => {
            const route = new TestAuthOTPRoute();
            (route as any).aliasRepo = { find: vi.fn() };
            await expect((route as any).getContacts("id-1")).rejects.toThrow(/userRepo is not set/);
        });

        it("Returns an empty list without querying the repo when id is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn();
            const find = vi.fn();
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts({ $ne: null });

            expect(result).toEqual([]);
            expect(findOne).not.toHaveBeenCalled();
            expect(find).not.toHaveBeenCalled();
        });

        it("Looks up aliases by userUid when the id resolves to a user.", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1" });
            const find = vi
                .fn()
                .mockResolvedValue([{ alias: "user@example.com", type: AliasType.EMAIL, verified: true }]);
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts("user-1");

            expect(find).toHaveBeenCalledWith({ userUid: "user-1" }, { ignoreACL: true });
            expect(result).toEqual([{ contact: "user@example.com", type: OTPContactType.EMAIL, verified: true }]);
        });

        it("Falls back to alias lookup by value, then re-resolves by userUid, when the id is not a user.", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn().mockResolvedValueOnce(undefined).mockResolvedValueOnce({ uid: "user-1" });
            const find = vi
                .fn()
                .mockResolvedValueOnce([{ alias: "user@example.com", type: AliasType.EMAIL, userUid: "user-1" }])
                .mockResolvedValueOnce([
                    { alias: "user@example.com", type: AliasType.EMAIL, userUid: "user-1", verified: true },
                    { alias: "+15551234567", type: AliasType.PHONE, userUid: "user-1", verified: false },
                ]);
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts("user@example.com");

            expect(find).toHaveBeenNthCalledWith(1, { alias: "user@example.com" }, { ignoreACL: true });
            expect(find).toHaveBeenNthCalledWith(2, { userUid: "user-1" }, { ignoreACL: true });
            // Regression: this re-fetch of the user by the re-resolved userUid must bypass ACL like
            // every other lookup in this unauthenticated, pre-login discovery path — omitting it
            // throws a 403 instead of gracefully resolving.
            expect(findOne).toHaveBeenNthCalledWith(2, "user-1", { ignoreACL: true });
            expect(result).toHaveLength(2);
        });

        it("Leaves the user unresolved when the re-fetch by userUid yields no aliases.", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const find = vi
                .fn()
                .mockResolvedValueOnce([{ alias: "user@example.com", type: AliasType.EMAIL, userUid: "user-1" }])
                .mockResolvedValueOnce([]);
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts("user@example.com");

            expect(findOne).toHaveBeenCalledTimes(1);
            expect(result).toEqual([]);
        });

        it("Returns an empty list when the id is not a user and no aliases match it.", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const find = vi.fn().mockResolvedValue([]);
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts("unknown");

            expect(result).toEqual([]);
            expect(findOne).toHaveBeenCalledTimes(1);
        });

        it("Filters out non-notifiable alias types (e.g. NAME) instead of throwing (regression: the " +
            "filter's result used to be discarded instead of reassigned, so a user with a username alias " +
            "could never complete OTP discovery/login).", async () => {
            const route = new TestAuthOTPRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1" });
            const find = vi.fn().mockResolvedValue([
                { alias: "coolname", type: AliasType.NAME, verified: true },
                { alias: "user@example.com", type: AliasType.EMAIL, verified: true },
            ]);
            (route as any).userRepo = { findOne };
            (route as any).aliasRepo = { find };

            const result = await (route as any).getContacts("user-1");

            expect(result).toEqual([{ contact: "user@example.com", type: OTPContactType.EMAIL, verified: true }]);
        });
    });

    describe("getUser", () => {
        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthOTPRoute();
            await expect((route as any).getUser("user-1")).rejects.toThrow(/userUtils is not set/);
        });

        it("Delegates to userUtils.lookup().", async () => {
            const route = new TestAuthOTPRoute();
            const lookup = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).userUtils = { lookup };

            const result = await (route as any).getUser("user-1");

            expect(lookup).toHaveBeenCalledWith("user-1");
            expect(result).toEqual({ uid: "user-1" });
        });
    });

    describe("notifyContact", () => {
        it("Sends an email when the contact type is EMAIL.", async () => {
            const route = new TestAuthOTPRoute();
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };

            await (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456");

            expect(sendEmail).toHaveBeenCalledWith("login-otp", { totp: "123456" }, { to: "user@example.com" });
        });

        it("Sends an SMS when the contact type is SMS.", async () => {
            const route = new TestAuthOTPRoute();
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS };

            await (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456");

            expect(sendSMS).toHaveBeenCalledWith("login-otp", { totp: "123456" }, { to: "+15551234567" });
        });

        it("Does nothing (and does not throw) when messagingUtils is unset.", async () => {
            const route = new TestAuthOTPRoute();
            await expect(
                (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).resolves.toBeUndefined();
        });

        it("Does not crash the process when the messaging provider rejects (e.g. Twilio/SMTP not configured).", async () => {
            const route = new TestAuthOTPRoute();
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockRejectedValue(new Error("Twilio is not configured.")),
                sendSMS: vi.fn().mockRejectedValue(new Error("Twilio is not configured.")),
            };
            (route as any).logger = { debug: vi.fn() };

            await expect(
                (route as any).notifyContact({ contact: "user@example.com", type: OTPContactType.EMAIL }, "123456"),
            ).resolves.toBeUndefined();
        });

        it("Does not crash the process when sendSMS rejects.", async () => {
            const route = new TestAuthOTPRoute();
            const debug = vi.fn();
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockResolvedValue(undefined),
                sendSMS: vi.fn().mockRejectedValue(new Error("Twilio is not configured.")),
            };
            (route as any).logger = { debug };

            await (route as any).notifyContact({ contact: "+15551234567", type: OTPContactType.SMS }, "123456");
            // Flush the rejected .catch() microtask registered inside notifyContact.
            await new Promise((resolve) => setImmediate(resolve));

            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification SMS"));
        });

        it("Does not log the verification code to debug in production.", async () => {
            const route = new TestAuthOTPRoute();
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockResolvedValue(undefined),
                sendSMS: vi.fn().mockResolvedValue(undefined),
            };
            const originalEnv = process.env.environment;
            process.env.environment = "production";

            try {
                await (route as any).notifyContact(
                    { contact: "user@example.com", type: OTPContactType.EMAIL },
                    "123456",
                );
            } finally {
                process.env.environment = originalEnv;
            }

            expect(debug).not.toHaveBeenCalledWith(expect.stringContaining("verification code for"));
        });
    });
});

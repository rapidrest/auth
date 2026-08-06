///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAliasRoute — no HTTP server, no database. otplib is real (the
// established pattern in this test suite, see BaseRegistrationRoute.test.ts), so the verification
// tests below exercise genuine OTP tokens rather than mocked ones.
import { CRUDRoute } from "@rapidrest/service-core";
import { BaseAliasRoute } from "../../src/routes/BaseAliasRoute.js";
import { generateOTP } from "../../src/auth/shared.js";
import { AliasType, ContactType } from "../../src/models/types.js";

class TestAliasRoute extends BaseAliasRoute<any> {
    protected profileClass: any = { name: "FakeProfile" };
}

describe("BaseAliasRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("validateCreate", () => {
        it("Delegates to CRUDRoute.validateCreate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "user@example.com" };
            const user: any = { uid: "user-1" };

            await (route as any).validateCreate(obj, user);

            expect(spy).toHaveBeenCalledWith(obj, user);
        });

        it("Defaults obj.userUid to the authenticated caller's uid when unset.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "user@example.com" };

            await (route as any).validateCreate(obj, { uid: "user-1" });

            expect(obj.userUid).toBe("user-1");
        });

        it("Allows a caller to explicitly create an alias for their own uid.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "user@example.com", userUid: "user-1" };

            await expect((route as any).validateCreate(obj, { uid: "user-1" })).resolves.toBeUndefined();
        });

        it("Rejects creating an alias for another user's uid without a trusted role.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "victim@example.com", userUid: "victim-uid" };

            await expect((route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] })).rejects.toThrow(
                /does not have permission/,
            );
        });

        it("Allows a trusted (admin) caller to create an alias for another user's uid.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "victim@example.com", userUid: "victim-uid" };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.userUid).toBe("victim-uid");
        });

        it("Does enforce ownership when there is no authenticated user (unauthenticated create).", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const obj: any = { alias: "someone@example.com", userUid: "someone-else" };

            await expect((route as any).validateCreate(obj, undefined)).rejects.toThrow(/Authorization is required/);
        });

        it("Processes each object in an array of aliases.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const objs: any = [{ alias: "a@example.com" }, { alias: "b@example.com" }];

            await (route as any).validateCreate(objs, { uid: "user-1" });

            expect(objs[0].userUid).toBe("user-1");
            expect(objs[1].userUid).toBe("user-1");
        });

        describe("verified:true ownership check (email/phone)", () => {
            it("Leaves verified:true intact when the caller's Profile lists the contact as verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const findOne = vi.fn().mockResolvedValue({
                    contacts: [{ contact: "user@example.com", type: ContactType.EMAIL, verified: true }],
                });
                (route as any).profileRepo = { findOne };
                const obj: any = { type: AliasType.EMAIL, alias: "user@example.com", verified: true };
                const user = { uid: "user-1" };

                await (route as any).validateCreate(obj, user);

                expect(obj.verified).toBe(true);
                // Regression guard: RepoUtils.findOne() strips @RequiresScope-gated properties (like
                // Profile.contacts, which requires `profile:contacts`) whenever no `user` is passed in the
                // options, silently returning an object with `contacts` missing entirely — which made every
                // claim look unproven regardless of the caller's actual state. `user` must always be passed.
                expect(findOne).toHaveBeenCalledWith("user-1", { skipCache: true, ignoreACL: true, user });
            });

            it("Downgrades verified:true to false when the caller has no matching verified Profile contact.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).profileRepo = { findOne: vi.fn().mockResolvedValue({ contacts: [] }) };
                const obj: any = { type: AliasType.EMAIL, alias: "victim@example.com", verified: true };

                await (route as any).validateCreate(obj, { uid: "attacker-1" });

                expect(obj.verified).toBe(false);
            });

            it("Downgrades verified:true to false when the Profile has the contact but only unverified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).profileRepo = {
                    findOne: vi.fn().mockResolvedValue({
                        contacts: [{ contact: "user@example.com", type: ContactType.EMAIL, verified: false }],
                    }),
                };
                const obj: any = { type: AliasType.EMAIL, alias: "user@example.com", verified: true };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(false);
            });

            it("Downgrades verified:true to false when profileRepo is unavailable.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const obj: any = { type: AliasType.PHONE, alias: "+15551234567", verified: true };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(false);
            });

            it("Does not apply to name-type aliases (handled by the separate uniqueness check).", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const findOne = vi.fn();
                (route as any).profileRepo = { findOne };
                const obj: any = { type: AliasType.NAME, alias: "coolname" };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
                expect(findOne).not.toHaveBeenCalled();
            });
        });

        describe("name uniqueness check", () => {
            it("Throws IDENTIFIER_EXISTS when a name alias with the same value already exists.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const find = vi.fn().mockResolvedValue([{ uid: "existing-alias" }]);
                (route as any).repoUtils = { find };
                const obj: any = { type: AliasType.NAME, alias: "taken-name" };

                await expect((route as any).validateCreate(obj, { uid: "user-1" })).rejects.toThrow(
                    /already exists/i,
                );
                expect(find).toHaveBeenCalledWith({ alias: "taken-name" }, { ignoreACL: true });
            });

            it("Marks a new, unique name alias as verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const obj: any = { type: AliasType.NAME, alias: "unique-name" };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
            });
        });
    });

    describe("create", () => {
        it("Sends a verification code for an unverified alias created.", async () => {
            const route = new TestAliasRoute();
            const created: any = { alias: "new@example.com", type: AliasType.EMAIL, verified: false };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue(created);
            const sendVerificationCode = vi
                .spyOn(route as any, "sendVerificationCode")
                .mockResolvedValue(undefined);
            const req: any = {};

            const result = await route.create(created, req, { uid: "user-1" } as any);

            expect(result).toBe(created);
            expect(sendVerificationCode).toHaveBeenCalledWith(created, req);
        });

        it("Does not send a verification code for an alias that's already verified.", async () => {
            const route = new TestAliasRoute();
            const created: any = { alias: "coolname", type: AliasType.NAME, verified: true };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue(created);
            const sendVerificationCode = vi
                .spyOn(route as any, "sendVerificationCode")
                .mockResolvedValue(undefined);

            await route.create(created, {} as any, { uid: "user-1" } as any);

            expect(sendVerificationCode).not.toHaveBeenCalled();
        });

        it("Handles an array of created aliases, sending codes only for the unverified ones.", async () => {
            const route = new TestAliasRoute();
            const verified: any = { alias: "coolname", type: AliasType.NAME, verified: true };
            const unverified: any = { alias: "new@example.com", type: AliasType.EMAIL, verified: false };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue([verified, unverified]);
            const sendVerificationCode = vi
                .spyOn(route as any, "sendVerificationCode")
                .mockResolvedValue(undefined);
            const req: any = {};

            await route.create([verified, unverified], req, { uid: "user-1" } as any);

            expect(sendVerificationCode).toHaveBeenCalledTimes(1);
            expect(sendVerificationCode).toHaveBeenCalledWith(unverified, req);
        });
    });

    describe("requestVerificationCode", () => {
        it("Looks up the alias (scoped to the caller via ACL) and sends a verification code for it.", async () => {
            const route = new TestAliasRoute();
            const alias: any = { uid: "alias-1", alias: "new@example.com", type: AliasType.EMAIL, verified: false };
            const findOne = vi.fn().mockResolvedValue(alias);
            (route as any).repoUtils = { findOne };
            const sendVerificationCode = vi
                .spyOn(route as any, "sendVerificationCode")
                .mockResolvedValue(undefined);
            const user: any = { uid: "user-1" };
            const req: any = {};

            await route.requestVerificationCode("alias-1", req, user);

            expect(findOne).toHaveBeenCalledWith("alias-1", { user });
            expect(sendVerificationCode).toHaveBeenCalledWith(alias, req);
        });

        it("Is a no-op when the alias does not exist (or the caller isn't permitted to see it).", async () => {
            const route = new TestAliasRoute();
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(undefined) };
            const sendVerificationCode = vi
                .spyOn(route as any, "sendVerificationCode")
                .mockResolvedValue(undefined);

            await expect(
                route.requestVerificationCode("missing", {} as any, { uid: "user-1" } as any),
            ).resolves.toBeUndefined();
            expect(sendVerificationCode).not.toHaveBeenCalled();
        });
    });

    describe("sendVerificationCode", () => {
        it("Does nothing for an already-verified alias.", async () => {
            const route = new TestAliasRoute();
            const checkAndIncrement = vi.fn();
            (route as any).rateLimiter = { checkAndIncrement };
            const alias: any = { alias: "user@example.com", type: AliasType.EMAIL, verified: true };

            await (route as any).sendVerificationCode(alias, { session: {} });

            expect(checkAndIncrement).not.toHaveBeenCalled();
        });

        it("Rate-limits by the alias value and sends an e-mail for an unverified e-mail alias.", async () => {
            const route = new TestAliasRoute();
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            const alias: any = { alias: "user@example.com", type: AliasType.EMAIL, verified: false };
            const req: any = { session: {} };

            await (route as any).sendVerificationCode(alias, req);

            expect(checkAndIncrement).toHaveBeenCalledWith("user@example.com");
            expect(sendEmail).toHaveBeenCalledWith(
                "verify-contact-otp",
                { totp: expect.any(String) },
                { to: "user@example.com" },
            );
            // generateOTP() stores the OTP session keyed on the alias's own value — verifyContact() must
            // check against this same value (regression guard for a bug where it instead compared against
            // the alias's uid, which could never match and made verification permanently impossible).
            expect(req.session.id).toBe("user@example.com");
        });

        it("Sends an SMS for an unverified phone alias.", async () => {
            const route = new TestAliasRoute();
            (route as any).rateLimiter = { checkAndIncrement: vi.fn().mockResolvedValue(undefined) };
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS };
            const alias: any = { alias: "+15551234567", type: AliasType.PHONE, verified: false };

            await (route as any).sendVerificationCode(alias, { session: {} });

            expect(sendSMS).toHaveBeenCalledWith(
                "verify-contact-otp",
                { totp: expect.any(String) },
                { to: "+15551234567" },
            );
        });

        it("Sends nothing for a name-type alias (not OTP-eligible).", async () => {
            const route = new TestAliasRoute();
            (route as any).rateLimiter = { checkAndIncrement: vi.fn().mockResolvedValue(undefined) };
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS };
            const alias: any = { alias: "coolname", type: AliasType.NAME, verified: false };

            await (route as any).sendVerificationCode(alias, { session: {} });

            expect(sendEmail).not.toHaveBeenCalled();
            expect(sendSMS).not.toHaveBeenCalled();
        });
    });

    describe("update / updateBulk / updateProperty", () => {
        // An Alias is intentionally immutable post-creation — to change one, remove and re-add it. These
        // overrides close off CRUDRoute's default update endpoints entirely rather than leaving them
        // reachable with no ownership/verification semantics applied. They throw synchronously (rather
        // than returning a rejected Promise), so the call is wrapped in an async closure below to
        // normalize both forms for `.rejects`.
        it("update() always throws NOT_FOUND.", async () => {
            const route = new TestAliasRoute();

            await expect(
                (async () => route.update("alias-1", {} as any, {} as any, { uid: "user-1" } as any))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("updateBulk() always throws NOT_FOUND.", async () => {
            const route = new TestAliasRoute();

            await expect(
                (async () => route.updateBulk([{} as any], {} as any, { uid: "user-1" } as any))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("updateProperty() always throws NOT_FOUND.", async () => {
            const route = new TestAliasRoute();

            await expect(
                (async () => route.updateProperty("alias-1", "alias", "new-value", { uid: "user-1" } as any))(),
            ).rejects.toThrow(/no resource could be found/i);
        });
    });

    describe("verifyContact", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestAliasRoute();

            await expect(
                route.verifyContact("alias-1", { token: "123456" }, {} as any, { uid: "user-1" } as any),
            ).rejects.toThrow(/internal error/i);
        });

        it("Throws NOT_FOUND when the alias does not exist.", async () => {
            const route = new TestAliasRoute();
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(undefined) };

            await expect(
                route.verifyContact("alias-1", { token: "123456" }, {} as any, { uid: "user-1" } as any),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Throws 400 on a wrong code and leaves the alias unverified.", async () => {
            const route = new TestAliasRoute();
            const req: any = { session: {} };
            await generateOTP(req, { id: "new@example.com" });
            const update = vi.fn();
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    version: 0,
                    alias: "new@example.com",
                    type: AliasType.EMAIL,
                    verified: false,
                }),
                update,
            };

            await expect(
                route.verifyContact("alias-1", { token: "000000" }, req, { uid: "user-1" } as any),
            ).rejects.toThrow(/invalid or expired/i);
            expect(update).not.toHaveBeenCalled();
        });

        // Regression test for the id-mismatch bug: sendVerificationCode() generates the OTP session keyed
        // on the alias's own value (`alias.alias`), so verifyContact() must check against that same value
        // to ever succeed — checking against `alias.uid` instead (a different value) made verification
        // fail unconditionally, even with the correct code.
        it("Flips verified to true on a correct code.", async () => {
            const route = new TestAliasRoute();
            const req: any = { session: {} };
            const token = await generateOTP(req, { id: "new@example.com" });
            const existingAlias = {
                uid: "alias-1",
                version: 0,
                alias: "new@example.com",
                type: AliasType.EMAIL,
                verified: false,
            };
            const update = vi.fn().mockResolvedValue({ ...existingAlias, verified: true });
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(existingAlias), update };
            const user: any = { uid: "user-1" };

            const findOne = (route as any).repoUtils.findOne;
            const result = await route.verifyContact("alias-1", { token }, req, user);

            expect(update).toHaveBeenCalledWith(
                { uid: "alias-1", version: 0, verified: true },
                existingAlias,
                { user },
            );
            expect(result.verified).toBe(true);
            // Regression guard: RepoUtils.findOne()'s ACL check runs as an anonymous request whenever
            // `user` isn't passed in the options — and Alias's class-level ACL deliberately does not grant
            // READ to `.*`, so an anonymous-context lookup always 403s here, even for the record's own
            // owner. `user` must always be passed.
            expect(findOne).toHaveBeenCalledWith("alias-1", { user });
        });
    });
});

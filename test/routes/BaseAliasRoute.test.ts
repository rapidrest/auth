///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
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

    describe("init", () => {
        it("Does nothing when objectFactory is not set.", async () => {
            const route = new TestAliasRoute();

            await (route as any).init();

            expect((route as any).profileRepo).toBeUndefined();
        });

        it("Does not recreate profileRepo if init() runs again.", async () => {
            const route = new TestAliasRoute();
            const newInstance = vi.fn();
            (route as any)._objectFactory = { newInstance };
            const existingProfileRepo = { findOne: vi.fn() };
            (route as any).profileRepo = existingProfileRepo;

            await (route as any).init();

            expect((route as any).profileRepo).toBe(existingProfileRepo);
            expect(newInstance).not.toHaveBeenCalled();
        });

        it("Creates profileRepo using the object factory.", async () => {
            const route = new TestAliasRoute();
            const profileRepo = { findOne: vi.fn() };
            const newInstance = vi.fn().mockResolvedValue(profileRepo);
            (route as any)._objectFactory = { newInstance };

            await (route as any).init();

            expect((route as any).profileRepo).toBe(profileRepo);
        });
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

            it("Leaves verified:true intact for a phone alias when the caller's Profile lists it as verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).profileRepo = {
                    findOne: vi.fn().mockResolvedValue({
                        contacts: [{ contact: "+15551234567", type: ContactType.PHONE, verified: true }],
                    }),
                };
                const obj: any = { type: AliasType.PHONE, alias: "+15551234567", verified: true };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
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

        // Regression: email/phone creation used to rely entirely on the datastore's unique-index constraint to
        // reject a collision, surfacing as a raw/uncaught error instead of a clean, expected response — and
        // relying on it alone is also what let the alias-squatting bug (see "name format restriction" below)
        // leave an orphaned `User` row behind in `BaseRegistrationRoute`, since the collision wasn't detected
        // until the insert itself. The check now runs once, up front, for every alias type.
        describe("uniqueness check (all types)", () => {
            it("Throws IDENTIFIER_EXISTS when a name alias with the same value already exists and is verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const find = vi.fn().mockResolvedValue([{ uid: "existing-alias", verified: true }]);
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

            it("Throws IDENTIFIER_EXISTS when an email alias with the same value already exists and is verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const find = vi.fn().mockResolvedValue([{ uid: "existing-alias", verified: true }]);
                (route as any).repoUtils = { find };
                const findOne = vi.fn();
                (route as any).profileRepo = { findOne };
                const obj: any = { type: AliasType.EMAIL, alias: "taken@example.com" };

                await expect((route as any).validateCreate(obj, { uid: "user-1" })).rejects.toThrow(
                    /already exists/i,
                );
                expect(find).toHaveBeenCalledWith({ alias: "taken@example.com" }, { ignoreACL: true });
                // The collision check short-circuits before the (unnecessary) verified-contact lookup.
                expect(findOne).not.toHaveBeenCalled();
            });

            it("Throws IDENTIFIER_EXISTS when a phone alias with the same value already exists and is verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = {
                    find: vi.fn().mockResolvedValue([{ uid: "existing-alias", verified: true }]),
                };
                const obj: any = { type: AliasType.PHONE, alias: "+14155552671" };

                await expect((route as any).validateCreate(obj, { uid: "user-1" })).rejects.toThrow(
                    /already exists/i,
                );
            });

            // Regression: an unverified alias is only a pending, unproven claim - it must not let anyone
            // permanently squat an e-mail/phone they don't control and block the real owner's later
            // registration/claim (see BaseRegistrationRoute.verify()). A stale unverified claim for the same
            // value is displaced rather than treated as a conflict.
            it("Displaces a stale unverified email alias claim for the same value instead of throwing.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                const find = vi.fn().mockResolvedValue([{ uid: "squatter-alias", verified: false }]);
                const del = vi.fn().mockResolvedValue(undefined);
                (route as any).repoUtils = { find, delete: del };
                (route as any).profileRepo = { findOne: vi.fn().mockResolvedValue(undefined) };
                const obj: any = { type: AliasType.EMAIL, alias: "victim@example.com" };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(del).toHaveBeenCalledWith("squatter-alias", { ignoreACL: true });
                expect(obj.verified).toBe(false);
            });

            it("Proceeds to the verified-contact check when no colliding alias exists.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                (route as any).profileRepo = {
                    findOne: vi.fn().mockResolvedValue({
                        contacts: [{ contact: "user@example.com", type: ContactType.EMAIL, verified: true }],
                    }),
                };
                const obj: any = { type: AliasType.EMAIL, alias: "user@example.com", verified: true };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
            });
        });

        // Regression: a `name` alias is free-form and instantly self-verified, and the uniqueness index on
        // `alias` spans all types - without this restriction, an attacker could squat a victim's future
        // e-mail/phone as a `name` alias before the victim ever registers it, blocking their registration and
        // colliding with the `email`/`phone` alias `BaseRegistrationRoute` later tries to create for them.
        describe("name format restriction (anti-squatting)", () => {
            it("Rejects a name alias that looks like an e-mail address.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const obj: any = { type: AliasType.NAME, alias: "victim@example.com" };

                await expect((route as any).validateCreate(obj, { uid: "attacker-1" })).rejects.toThrow(
                    /may not resemble/i,
                );
            });

            it("Rejects a name alias that looks like a phone number.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                // "+15551234567" (used elsewhere in this file) is a reserved 555-prefixed number that this
                // validator library doesn't actually recognize as valid, so a real mobile-format number is
                // needed here to exercise the phone branch of checkName().
                const obj: any = { type: AliasType.NAME, alias: "+14155552671" };

                await expect((route as any).validateCreate(obj, { uid: "attacker-1" })).rejects.toThrow(
                    /may not resemble/i,
                );
            });

            it("Rejects a name alias containing characters outside the allowed charset.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const obj: any = { type: AliasType.NAME, alias: "bad name!" };

                await expect((route as any).validateCreate(obj, { uid: "attacker-1" })).rejects.toThrow();
            });

            it("Allows a name alias that doesn't resemble an e-mail address or phone number.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const obj: any = { type: AliasType.NAME, alias: "coolname" };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
            });

            it("Skips the format check when alias is not a string, but still marks it verified.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestAliasRoute();
                (route as any).repoUtils = { find: vi.fn().mockResolvedValue([]) };
                const obj: any = { type: AliasType.NAME };

                await (route as any).validateCreate(obj, { uid: "user-1" });

                expect(obj.verified).toBe(true);
            });
        });
    });

    describe("find", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestAliasRoute();

            await expect(route.find({}, {}, { uid: "user-1" } as any)).rejects.toThrow(/internal error/i);
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

    // create()/delete() are @RequiresElevation(60)-gated (enforced by middleware at HTTP dispatch, before
    // this method body ever runs — see AliasRoute.test.ts for the enforcement itself). This override exists
    // only to carry that decorator; it otherwise delegates straight to CRUDRoute.delete().
    describe("delete", () => {
        it("Delegates to CRUDRoute.delete() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "delete").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const req: any = {};
            const user: any = { uid: "user-1" };

            await route.delete("alias-1", "1", "true", req, user);

            expect(spy).toHaveBeenCalledWith("alias-1", "1", "true", req, user);
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

            expect(checkAndIncrement).toHaveBeenCalledWith("user@example.com", req);
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

        it("Does not throw when sendSMS rejects (failure is logged, not propagated).", async () => {
            const route = new TestAliasRoute();
            (route as any).rateLimiter = { checkAndIncrement: vi.fn().mockResolvedValue(undefined) };
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = {
                sendEmail: vi.fn().mockResolvedValue(undefined),
                sendSMS: vi.fn().mockRejectedValue(new Error("provider unavailable")),
            };
            const alias: any = { alias: "+15551234567", type: AliasType.PHONE, verified: false };

            await expect((route as any).sendVerificationCode(alias, { session: {} })).resolves.toBeUndefined();

            // Flush the rejected .catch() microtask registered inside sendVerificationCode.
            await new Promise((resolve) => setImmediate(resolve));
            expect(debug).toHaveBeenCalledWith(expect.stringContaining("Failed to send verification SMS"));
        });

        it("Does not log the verification code to debug in production.", async () => {
            const route = new TestAliasRoute();
            (route as any).rateLimiter = { checkAndIncrement: vi.fn().mockResolvedValue(undefined) };
            const debug = vi.fn();
            (route as any).logger = { debug };
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS: vi.fn() };
            const alias: any = { alias: "user@example.com", type: AliasType.EMAIL, verified: false };
            const originalEnv = process.env.environment;
            process.env.environment = "production";

            try {
                await (route as any).sendVerificationCode(alias, { session: {} });
            } finally {
                process.env.environment = originalEnv;
            }

            expect(debug).not.toHaveBeenCalledWith(expect.stringContaining("verification code for"));
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

        // Regression: verifyOTP() itself has no internal lockout — it's a pure single-use session check —
        // so without a rate limit here an attacker who knows the alias's value could brute-force the
        // 6-digit code with unlimited guesses. This mirrors the throttle already applied when the code is
        // first sent (see sendVerificationCode's tests above).
        it("Rate-limits by the alias value before verifying the code.", async () => {
            const route = new TestAliasRoute();
            const req: any = { session: {} };
            await generateOTP(req, { id: "new@example.com" });
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).rateLimiter = { checkAndIncrement };
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "alias-1",
                    version: 0,
                    alias: "new@example.com",
                    type: AliasType.EMAIL,
                    verified: false,
                }),
                update: vi.fn(),
            };

            await expect(
                route.verifyContact("alias-1", { token: "000000" }, req, { uid: "user-1" } as any),
            ).rejects.toThrow(/invalid or expired/i);

            expect(checkAndIncrement).toHaveBeenCalledWith("new@example.com", req);
        });

        it("Propagates the rate limiter's error and does not attempt verification.", async () => {
            const route = new TestAliasRoute();
            const req: any = { session: {} };
            const token = await generateOTP(req, { id: "new@example.com" });
            const checkAndIncrement = vi.fn().mockRejectedValue(new Error("Too many attempts"));
            (route as any).rateLimiter = { checkAndIncrement };
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
                route.verifyContact("alias-1", { token }, req, { uid: "user-1" } as any),
            ).rejects.toThrow(/Too many attempts/);
            expect(update).not.toHaveBeenCalled();
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

        // Regression/branch guard: verifyOTP() itself throws (rather than returning false) for a malformed
        // request, e.g. a missing token - that internal error must be caught and translated into the same
        // clean 400 "Invalid or expired verification code." response, not leak out as a raw/unhandled error.
        it("Throws 400 (not a raw error) when verifyOTP itself throws for a malformed request.", async () => {
            const route = new TestAliasRoute();
            const req: any = { session: {} };
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
                route.verifyContact("alias-1", {}, req, { uid: "user-1" } as any),
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

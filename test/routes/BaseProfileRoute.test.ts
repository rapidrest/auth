///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseProfileRoute — no HTTP server, no database. otplib is real (the
// established pattern in this test suite, see BaseRegistrationRoute.test.ts), so the contact
// verification tests below exercise genuine OTP tokens rather than mocked ones.
import { CRUDRoute } from "@rapidrest/service-core";
import { BaseProfileRoute } from "../../src/routes/BaseProfileRoute.js";
import { generateOTP } from "../../src/auth/shared.js";
import { ContactType } from "../../src/models/types.js";

class TestProfileRoute extends BaseProfileRoute<any> {}

function makeReq(overrides: any = {}): any {
    return {
        method: "POST",
        path: "/",
        url: "/",
        headers: {},
        params: {},
        query: {},
        body: undefined,
        cookies: {},
        signedCookies: {},
        session: {},
        socket: {},
        ...overrides,
    };
}

describe("BaseProfileRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("validateCreate", () => {
        it("Throws when there is no authenticated user.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John" };

            await expect((route as any).validateCreate(obj, undefined)).rejects.toThrow(
                /Authorization is required/,
            );
        });

        it("Delegates to CRUDRoute.validateCreate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John" };
            const user: any = { uid: "user-1" };

            await (route as any).validateCreate(obj, user);

            expect(spy).toHaveBeenCalledWith(obj, user);
        });

        it("Defaults obj.uid to the authenticated caller's uid when unset.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John" };

            await (route as any).validateCreate(obj, { uid: "user-1" });

            expect(obj.uid).toBe("user-1");
        });

        it("Allows a caller to explicitly create a profile for their own uid.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John", uid: "user-1" };

            await expect((route as any).validateCreate(obj, { uid: "user-1" })).resolves.toBeUndefined();
        });

        it("Rejects creating a profile for another user's uid without a trusted role.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const obj: any = { givenName: "Victim", uid: "victim-uid" };

            await expect(
                (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] }),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Allows a trusted (admin) caller to create a profile for another user's uid.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const obj: any = { givenName: "Victim", uid: "victim-uid" };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.uid).toBe("victim-uid");
        });
    });

    describe("validateUpdate", () => {
        it("Throws when there is no authenticated user.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { uid: "user-1", givenName: "John" };

            await expect((route as any).validateUpdate("user-1", obj, undefined)).rejects.toThrow(
                /Authorization is required/,
            );
        });

        it("Allows a caller to update their own profile.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { uid: "user-1", givenName: "John" };

            await expect(
                (route as any).validateUpdate("user-1", obj, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        it("Rejects updating another user's profile without a trusted role.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { uid: "victim-uid", givenName: "Hijacked" };

            await expect(
                (route as any).validateUpdate("victim-uid", obj, { uid: "attacker-uid", roles: [] }),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Allows a trusted (admin) caller to update another user's profile.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { uid: "victim-uid", givenName: "Updated" };

            await expect(
                (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] }),
            ).resolves.toBeUndefined();
        });

        it("Allows a caller to update their own profile when the payload omits uid.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John" };

            await expect(
                (route as any).validateUpdate("user-1", obj, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        // Regression test: checking `obj.uid` only fired when `uid` was present in the payload, so a caller
        // could edit any *other* field of a profile they don't own just by leaving `uid` out of the body
        // (e.g. via PUT /profile/:id/:property, which never includes it). The check now compares against the
        // `id` path param - the record actually being targeted - regardless of what the payload contains.
        it("Rejects modifying another user's profile without a trusted role, even when the payload omits uid.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { givenName: "Hijacked" };

            await expect(
                (route as any).validateUpdate("victim-uid", obj, { uid: "attacker-uid", roles: [] }),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Treats the 'me' keyword as the authenticated caller's own uid.", async () => {
            const route = new TestProfileRoute();
            const obj: any = { givenName: "John" };

            await expect(
                (route as any).validateUpdate("me", obj, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        // Regression: a client could PUT {contacts:[{contact:"victim@example.com", type:"email",
        // verified:true}]} with no OTP round-trip, then create a matching Alias that auto-verifies itself
        // off this fabricated "verified" contact - permanently pre-empting the real owner's registration.
        // `verified` must only ever be settable via verifyContact()'s real OTP check.
        describe("contacts[].verified reconciliation", () => {
            it("Discards a client-supplied verified:true on an existing unverified contact.", async () => {
                const route = new TestProfileRoute();
                (route as any).repoUtils = {
                    validate: vi.fn().mockResolvedValue(undefined),
                    findOne: vi.fn().mockResolvedValue({
                        uid: "user-1",
                        contacts: [{ contact: "victim@example.com", type: ContactType.EMAIL, verified: false }],
                    }),
                };
                const obj: any = {
                    contacts: [{ contact: "victim@example.com", type: ContactType.EMAIL, verified: true }],
                };

                await (route as any).validateUpdate("user-1", obj, { uid: "user-1" });

                expect(obj.contacts).toEqual([
                    { contact: "victim@example.com", type: ContactType.EMAIL, verified: false },
                ]);
            });

            it("Forces verified:false on a brand-new contact even if the client sent verified:true.", async () => {
                const route = new TestProfileRoute();
                (route as any).repoUtils = {
                    validate: vi.fn().mockResolvedValue(undefined),
                    findOne: vi.fn().mockResolvedValue({ uid: "user-1", contacts: [] }),
                };
                const obj: any = {
                    contacts: [{ contact: "victim@example.com", type: ContactType.EMAIL, verified: true }],
                };

                await (route as any).validateUpdate("user-1", obj, { uid: "user-1" });

                expect(obj.contacts).toEqual([
                    { contact: "victim@example.com", type: ContactType.EMAIL, verified: false },
                ]);
            });

            it("Preserves an already-verified contact's true value when echoed back unchanged.", async () => {
                const route = new TestProfileRoute();
                (route as any).repoUtils = {
                    validate: vi.fn().mockResolvedValue(undefined),
                    findOne: vi.fn().mockResolvedValue({
                        uid: "user-1",
                        contacts: [{ contact: "user@example.com", type: ContactType.EMAIL, verified: true }],
                    }),
                };
                const obj: any = {
                    contacts: [{ contact: "user@example.com", type: ContactType.EMAIL, verified: true }],
                };

                await (route as any).validateUpdate("user-1", obj, { uid: "user-1" });

                expect(obj.contacts).toEqual([
                    { contact: "user@example.com", type: ContactType.EMAIL, verified: true },
                ]);
            });

            it("Does not touch obj.contacts when the update doesn't include contacts.", async () => {
                const route = new TestProfileRoute();
                (route as any).repoUtils = { validate: vi.fn().mockResolvedValue(undefined), findOne: vi.fn() };
                const obj: any = { givenName: "John" };

                await (route as any).validateUpdate("user-1", obj, { uid: "user-1" });

                expect(obj.contacts).toBeUndefined();
                expect((route as any).repoUtils.findOne).not.toHaveBeenCalled();
            });
        });
    });

    describe("updateProperty", () => {
        // Disabled outright: CRUDRoute.updateProperty (PUT /:id/:property) invokes validateUpdate() with a
        // throwaway wrapper object ({[propertyName]: obj}), not the object that actually gets persisted, so
        // the `contacts[].verified` reconciliation in validateUpdate() (see below) cannot protect this path -
        // a client could otherwise self-verify an email/phone via PUT /profile/:id/contacts. Rather than
        // special-case `contacts`, the whole endpoint is disabled, the same way BaseAliasRoute disables it.
        // These throw synchronously (rather than returning a rejected Promise), so the call is wrapped in an
        // async closure below to normalize both forms for `.rejects` (same pattern as BaseAliasRoute.test.ts).
        it("Always rejects, regardless of caller or property.", async () => {
            const route = new TestProfileRoute();

            await expect(
                (async () =>
                    (route as any).updateProperty("victim-uid", "uid", "third-party-uid", {
                        uid: "attacker-uid",
                        roles: [],
                    }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Rejects even for the record's own owner.", async () => {
            const route = new TestProfileRoute();

            await expect(
                (async () => (route as any).updateProperty("user-1", "contacts", [], { uid: "user-1" }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Rejects even for a trusted (admin) caller.", async () => {
            const route = new TestProfileRoute();

            await expect(
                (async () =>
                    (route as any).updateProperty("victim-uid", "contacts", [], {
                        uid: "admin-uid",
                        roles: ["admin"],
                    }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });
    });

    describe("create — contact verification side effect", () => {
        it("Sends a verification code for each contact on a newly-created profile.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue({
                uid: "user-1",
                contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
            });
            const route = new TestProfileRoute();
            const sendContactsVerification = vi
                .spyOn(route as any, "sendContactsVerification")
                .mockResolvedValue(undefined);
            const req = makeReq();
            const obj: any = { contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }] };

            const result = await route.create(obj, req, { uid: "user-1" } as any);

            expect(spy).toHaveBeenCalledWith(obj, req, { uid: "user-1" });
            expect(sendContactsVerification).toHaveBeenCalledWith(req, [], [
                { contact: "new@example.com", type: ContactType.EMAIL, verified: false },
            ]);
            expect(result).toEqual({
                uid: "user-1",
                contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
            });
        });

        it("Does nothing when the created profile has no contacts.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue({ uid: "user-1", givenName: "Ada" });
            const route = new TestProfileRoute();
            const sendContactsVerification = vi
                .spyOn(route as any, "sendContactsVerification")
                .mockResolvedValue(undefined);

            await route.create({ givenName: "Ada" } as any, makeReq(), { uid: "user-1" } as any);

            expect(sendContactsVerification).not.toHaveBeenCalled();
        });

        it("Handles an array of created profiles, sending verification per-profile.", async () => {
            const profileA = { uid: "user-1", contacts: [{ contact: "a@example.com", type: ContactType.EMAIL, verified: false }] };
            const profileB = { uid: "user-2", contacts: [] };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue([profileA, profileB]);
            const route = new TestProfileRoute();
            const sendContactsVerification = vi
                .spyOn(route as any, "sendContactsVerification")
                .mockResolvedValue(undefined);
            const req = makeReq();

            await route.create([{} as any, {} as any], req, { uid: "user-1" } as any);

            expect(sendContactsVerification).toHaveBeenCalledTimes(2);
            expect(sendContactsVerification).toHaveBeenCalledWith(req, [], profileA.contacts);
            expect(sendContactsVerification).toHaveBeenCalledWith(req, [], profileB.contacts);
        });

        it("Still returns the created profile even if sending verification throws.", async () => {
            const created = {
                uid: "user-1",
                contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
            };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue(created);
            const route = new TestProfileRoute();
            vi.spyOn(route as any, "sendContactsVerification").mockRejectedValue(new Error("boom"));

            const result = await route.create({} as any, makeReq(), { uid: "user-1" } as any);

            expect(result).toBe(created);
        });
    });

    describe("requestVerificationCode", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestProfileRoute();

            await expect(
                route.requestVerificationCode("me", "new@example.com", {}, makeReq(), { uid: "user-1" } as any),
            ).rejects.toThrow(/internal error/i);
        });

        it("Rejects looking up another user's profile without a trusted role.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = { findOne: vi.fn() };

            await expect(
                route.requestVerificationCode("victim-uid", "new@example.com", {}, makeReq(), {
                    uid: "attacker-uid",
                    roles: [],
                } as any),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Throws NOT_FOUND when the profile does not exist.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(undefined) };

            await expect(
                route.requestVerificationCode("me", "new@example.com", {}, makeReq(), { uid: "user-1" } as any),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Sends a verification code for the matching contact.", async () => {
            const route = new TestProfileRoute();
            const existing = {
                uid: "user-1",
                contacts: [
                    { contact: "other@example.com", type: ContactType.EMAIL, verified: true },
                    { contact: "new@example.com", type: ContactType.EMAIL, verified: false },
                ],
            };
            const findOne = vi.fn().mockResolvedValue(existing);
            (route as any).repoUtils = { findOne };
            const sendVerificationCode = vi.spyOn(route as any, "sendVerificationCode").mockResolvedValue(undefined);
            const user: any = { uid: "user-1" };
            const req = makeReq();

            await route.requestVerificationCode("me", "new@example.com", {}, req, user);

            expect(findOne).toHaveBeenCalledWith("user-1", { version: undefined, user, ignoreACL: true });
            expect(sendVerificationCode).toHaveBeenCalledTimes(1);
            expect(sendVerificationCode).toHaveBeenCalledWith(existing.contacts[1], req);
        });

        it("Does nothing when no contact matches the given id.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({ uid: "user-1", contacts: [] }),
            };
            const sendVerificationCode = vi.spyOn(route as any, "sendVerificationCode").mockResolvedValue(undefined);

            await route.requestVerificationCode("me", "missing@example.com", {}, makeReq(), {
                uid: "user-1",
            } as any);

            expect(sendVerificationCode).not.toHaveBeenCalled();
        });
    });

    describe("sendVerificationForNewContacts", () => {
        it("Sends an e-mail and rate-limits by the contact for a newly-added unverified e-mail.", async () => {
            const route = new TestProfileRoute();
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            const checkAndIncrement = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            (route as any).rateLimiter = { checkAndIncrement };
            const req = makeReq();
            const next = [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }];

            await (route as any).sendContactsVerification(req, [], next);

            expect(checkAndIncrement).toHaveBeenCalledWith("new@example.com");
            expect(sendEmail).toHaveBeenCalledWith(
                "verify-contact-otp",
                { totp: expect.any(String) },
                { to: "new@example.com" },
            );
            expect(req.session.id).toBe("new@example.com");
        });

        it("Sends an SMS for a newly-added unverified phone contact.", async () => {
            const route = new TestProfileRoute();
            const sendSMS = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail: vi.fn().mockResolvedValue(undefined), sendSMS };
            (route as any).rateLimiter = { checkAndIncrement: vi.fn() };
            const req = makeReq();
            const next = [{ contact: "+15551234567", type: ContactType.PHONE, verified: false }];

            await (route as any).sendContactsVerification(req, [], next);

            expect(sendSMS).toHaveBeenCalledWith(
                "verify-contact-otp",
                { totp: expect.any(String) },
                { to: "+15551234567" },
            );
        });

        it("Does not send for a contact that is already verified.", async () => {
            const route = new TestProfileRoute();
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            (route as any).rateLimiter = { checkAndIncrement: vi.fn() };
            const req = makeReq();
            const next = [{ contact: "already@example.com", type: ContactType.EMAIL, verified: true }];

            await (route as any).sendContactsVerification(req, [], next);

            expect(sendEmail).not.toHaveBeenCalled();
        });

        it("Does not re-send for a contact already present in the previous array (unrelated resave).", async () => {
            const route = new TestProfileRoute();
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            (route as any).rateLimiter = { checkAndIncrement: vi.fn() };
            const req = makeReq();
            const existing = [{ contact: "pending@example.com", type: ContactType.EMAIL, verified: false }];

            await (route as any).sendContactsVerification(req, existing, existing);

            expect(sendEmail).not.toHaveBeenCalled();
        });
    });

    describe("update — contact verification side effect", () => {
        it("Sends a verification code when a new unverified contact is added via update().", async () => {
            const route = new TestProfileRoute();
            const existing = { uid: "user-1", version: 0, contacts: [] };
            const updated = {
                uid: "user-1",
                version: 1,
                contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
            };
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn().mockResolvedValue(updated),
            };
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            (route as any).rateLimiter = { checkAndIncrement: vi.fn() };
            const req = makeReq();
            const obj = { contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }] };

            const result = await route.update("user-1", obj as any, req, { uid: "user-1" } as any);

            expect(result).toBe(updated);
            expect(sendEmail).toHaveBeenCalledWith(
                "verify-contact-otp",
                { totp: expect.any(String) },
                { to: "new@example.com" },
            );
        });

        it("Does not attempt to send anything when the update doesn't touch contacts.", async () => {
            const route = new TestProfileRoute();
            const existing = { uid: "user-1", version: 0, contacts: [] };
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn().mockResolvedValue({ uid: "user-1", version: 1, givenName: "Ada" }),
            };
            const sendEmail = vi.fn().mockResolvedValue(undefined);
            (route as any).messagingUtils = { sendEmail, sendSMS: vi.fn().mockResolvedValue(undefined) };
            const req = makeReq();

            await route.update("user-1", { givenName: "Ada" } as any, req, { uid: "user-1" } as any);

            expect(sendEmail).not.toHaveBeenCalled();
        });

        it("Still returns the updated profile even if the verification send fails.", async () => {
            const route = new TestProfileRoute();
            const existing = { uid: "user-1", version: 0, contacts: [] };
            const updated = {
                uid: "user-1",
                version: 1,
                contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
            };
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue(existing),
                update: vi.fn().mockResolvedValue(updated),
            };
            (route as any).rateLimiter = {
                checkAndIncrement: vi.fn().mockRejectedValue(new Error("Too many attempts.")),
            };
            const req = makeReq();
            const obj = { contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }] };

            const result = await route.update("user-1", obj as any, req, { uid: "user-1" } as any);

            expect(result).toBe(updated);
        });
    });

    describe("verifyContact", () => {
        it("Throws 400 when no contact is given in the body.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = {};
            const req = makeReq();

            await expect(
                route.verifyContact("user-1", { token: "123456" }, req, { uid: "user-1" } as any),
            ).rejects.toThrow(/'contact' is required/i);
        });

        it("Throws 404 when the profile does not exist.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(undefined) };
            const req = makeReq();

            await expect(
                route.verifyContact("user-1", { contact: "new@example.com", token: "123456" }, req, {
                    uid: "user-1",
                } as any),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Throws 404 when the contact isn't on the profile.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({ uid: "user-1", version: 0, contacts: [] }),
            };
            const req = makeReq();

            await expect(
                route.verifyContact("user-1", { contact: "missing@example.com", token: "123456" }, req, {
                    uid: "user-1",
                } as any),
            ).rejects.toThrow(/no such contact/i);
        });

        it("Throws 400 on a wrong/expired code and leaves the contact unverified.", async () => {
            const route = new TestProfileRoute();
            const req = makeReq();
            await generateOTP(req, { id: "new@example.com" });
            const update = vi.fn();
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({
                    uid: "user-1",
                    version: 0,
                    contacts: [{ contact: "new@example.com", type: ContactType.EMAIL, verified: false }],
                }),
                update,
            };

            await expect(
                route.verifyContact("user-1", { contact: "new@example.com", token: "000000" }, req, {
                    uid: "user-1",
                } as any),
            ).rejects.toThrow(/invalid or expired/i);
            expect(update).not.toHaveBeenCalled();
        });

        it("Flips verified to true on a correct code, leaving other contacts untouched.", async () => {
            const route = new TestProfileRoute();
            const req = makeReq();
            const token = await generateOTP(req, { id: "new@example.com" });
            const existingProfile = {
                uid: "user-1",
                version: 0,
                contacts: [
                    { contact: "already@example.com", type: ContactType.EMAIL, verified: true },
                    { contact: "new@example.com", type: ContactType.EMAIL, verified: false },
                ],
            };
            const update = vi.fn().mockResolvedValue({ ...existingProfile });
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(existingProfile), update };

            await route.verifyContact("user-1", { contact: "new@example.com", token }, req, { uid: "user-1" } as any);

            expect(update).toHaveBeenCalledWith(
                {
                    uid: "user-1",
                    version: 0,
                    contacts: [
                        { contact: "already@example.com", type: ContactType.EMAIL, verified: true },
                        { contact: "new@example.com", type: ContactType.EMAIL, verified: true },
                    ],
                },
                existingProfile,
                { user: { uid: "user-1" }, ignoreACL: true },
            );
        });

        it("Rejects verifying another user's contact without a trusted role.", async () => {
            const route = new TestProfileRoute();
            (route as any).repoUtils = { findOne: vi.fn() };
            const req = makeReq();

            await expect(
                route.verifyContact("victim-uid", { contact: "new@example.com", token: "123456" }, req, {
                    uid: "attacker-uid",
                    roles: [],
                } as any),
            ).rejects.toThrow(/does not have permission/);
        });
    });
});

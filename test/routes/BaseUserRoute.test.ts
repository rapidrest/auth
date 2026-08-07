///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseUserRoute — no HTTP server, no database.
import { ACLAction, CRUDRoute, ModelRoute } from "@rapidrest/service-core";
import { BaseUserRoute } from "../../src/routes/BaseUserRoute.js";

class TestUserRoute extends BaseUserRoute<any> {}

describe("BaseUserRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("create", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestUserRoute();
            const req: any = {};

            await expect(route.create({ roles: [] } as any, req, { uid: "admin-uid", roles: ["admin"] })).rejects.toThrow(
                /internal error/i,
            );
        });

        it("Processes each object in an array individually and returns the combined results.", async () => {
            const route = new TestUserRoute();
            const doCreate = vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid" });
            (route as any).repoUtils = { instantiateObject: (o: any) => ({ uid: "new-uid", ...o }) };
            const req: any = {};

            const result = await route.create([{ roles: [] }, { roles: [] }] as any, req, {
                uid: "admin-uid",
                roles: ["admin"],
            });

            expect(result).toEqual([{ uid: "new-uid" }, { uid: "new-uid" }]);
            expect(doCreate).toHaveBeenCalledTimes(2);
        });

        it("Grants the newly-created record's own uid full owner ACL access.", async () => {
            const route = new TestUserRoute();
            const doCreate = vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid" });
            (route as any).repoUtils = { instantiateObject: (o: any) => ({ uid: "new-uid", ...o }) };
            const req: any = {};
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await route.create({ roles: [] } as any, req, user);

            expect(doCreate).toHaveBeenCalledWith(
                expect.objectContaining({ uid: "new-uid" }),
                expect.objectContaining({
                    req,
                    user,
                    acl: {
                        uid: "new-uid",
                        records: [
                            {
                                userOrRoleId: "new-uid",
                                actions: [
                                    ACLAction.COUNT,
                                    ACLAction.CREATE,
                                    ACLAction.DELETE,
                                    ACLAction.EXISTS,
                                    ACLAction.READ,
                                    ACLAction.LIST,
                                    ACLAction.TRUNCATE,
                                    ACLAction.UPDATE,
                                ],
                            },
                        ],
                    },
                }),
            );
        });
    });

    describe("validateCreate", () => {
        it("Delegates to CRUDRoute.validateCreate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { roles: [] };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await (route as any).validateCreate(obj, user);

            expect(spy).toHaveBeenCalledWith(obj, user);
        });

        // Regression: without this, a caller able to reach create() by any means other than the class-level
        // ACL gate (e.g. a per-record/role CREATE grant that isn't a globally trusted role, or a looser
        // class ACL configured downstream) could provision a brand-new User with an elevated roles array
        // baked in from the start - the same account-takeover shape as the validateUpdate fix below, just
        // at creation time instead of update time.
        it("Resets roles to an empty array when a non-trusted caller includes it.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] });

            expect(obj.roles).toEqual([]);
        });

        it("Does not add a roles key at all when the client omitted it.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { verified: true };

            await (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] });

            expect("roles" in obj).toBe(false);
        });

        it("Allows a trusted (admin) caller to set roles on a newly-created user.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.roles).toEqual(["admin"]);
        });

        it("Allows an unauthenticated create call to proceed without roles present (delegates auth to the ACL layer).", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, undefined);

            expect(obj.roles).toEqual([]);
        });
    });

    describe("validateUpdate", () => {
        it("Delegates to CRUDRoute.validateUpdate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const obj: any = { uid: "user-1" };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await (route as any).validateUpdate("user-1", obj, user);

            expect(spy).toHaveBeenCalledWith("user-1", obj, user);
        });

        // Regression: `roles` had no `@ReadOnly` protection and every self-registered user is automatically
        // granted UPDATE on their own record, so a plain PUT with an elevated roles array used to persist
        // unmodified - a full account takeover, since roles:["admin"] bypasses every ACL check system-wide.
        // The attempted roles change is silently discarded rather than rejecting the whole request.
        it("Reverts roles to the persisted value when a non-trusted caller attempts to change them.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", roles: [] });
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "user-1", roles: ["admin"] };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.roles).toEqual([]);
        });

        it("Resolves the 'me' keyword to the caller's own uid when looking up the persisted roles.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", roles: [] });
            (route as any).repoUtils = { findOne };
            const obj: any = { roles: ["admin"] };

            await (route as any).validateUpdate("me", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.roles).toEqual([]);
        });

        it("Does not touch obj.roles when the update doesn't include roles at all.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn();
            (route as any).repoUtils = { findOne };
            // `verified: false` here (rather than `true`) is deliberate: it proves the absence of `roles`
            // alone skips the lookup, without also tripping the separate verified-escalation check below.
            const obj: any = { uid: "user-1", verified: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).not.toHaveBeenCalled();
            expect("roles" in obj).toBe(false);
        });

        it("Allows a trusted (admin) caller to change another user's roles.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn();
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "victim-uid", roles: ["admin"] };

            await (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] });

            expect(findOne).not.toHaveBeenCalled();
            expect(obj.roles).toEqual(["admin"]);
        });

        it("Resets verified to false when a non-trusted caller attempts to set it to true and it isn't already verified.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", verified: false });
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "user-1", verified: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.verified).toBe(false);
        });

        it("Allows a non-trusted caller to lower their own verified status without a lookup (no false-positive block).", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn();
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "user-1", verified: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).not.toHaveBeenCalled();
            expect(obj.verified).toBe(false);
        });

        it("Allows verified:true to pass through unchanged when the persisted record is already verified (no false-positive block on a no-op resubmission).", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", verified: true });
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "user-1", verified: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.verified).toBe(true);
        });

        it("Allows a trusted (admin) caller to verify another user without a lookup.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn();
            (route as any).repoUtils = { findOne };
            const obj: any = { uid: "victim-uid", verified: true };

            await (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] });

            expect(findOne).not.toHaveBeenCalled();
            expect(obj.verified).toBe(true);
        });
    });

    describe("updateProperty", () => {
        // Disabled outright: CRUDRoute.updateProperty (PUT /:id/:property) invokes validateUpdate() with a
        // throwaway wrapper object ({[propertyName]: obj}), not the object that actually gets persisted, so
        // the roles reconciliation in validateUpdate() above cannot protect this path - a client could
        // otherwise self-escalate via PUT /users/:id/roles. Rather than special-case `roles`, the whole
        // endpoint is disabled, the same way BaseAliasRoute disables it.
        // These throw synchronously (rather than returning a rejected Promise), so the call is wrapped in an
        // async closure below to normalize both forms for `.rejects` (same pattern as BaseAliasRoute.test.ts).
        it("Always rejects, regardless of caller or property.", async () => {
            const route = new TestUserRoute();

            await expect(
                (async () => route.updateProperty("victim-uid", "roles", ["admin"], { uid: "attacker-uid", roles: [] }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Rejects even for the record's own owner.", async () => {
            const route = new TestUserRoute();

            await expect(
                (async () => route.updateProperty("user-1", "roles", ["admin"], { uid: "user-1", roles: [] }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });

        it("Rejects even for a trusted (admin) caller.", async () => {
            const route = new TestUserRoute();

            await expect(
                (async () =>
                    route.updateProperty("victim-uid", "roles", ["admin"], { uid: "admin-uid", roles: ["admin"] }))(),
            ).rejects.toThrow(/no resource could be found/i);
        });
    });
});

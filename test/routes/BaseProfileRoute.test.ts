///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseProfileRoute — no HTTP server, no database.
import { CRUDRoute } from "@rapidrest/service-core";
import { BaseProfileRoute } from "../../src/routes/BaseProfileRoute.js";

class TestProfileRoute extends BaseProfileRoute<any> {}

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

        it("Processes each object in an array of profiles.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestProfileRoute();
            const objs: any = [{ givenName: "A" }, { givenName: "B" }];

            await (route as any).validateCreate(objs, { uid: "user-1" });

            expect(objs[0].uid).toBe("user-1");
            expect(objs[1].uid).toBe("user-1");
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
    });

    describe("updateProperty", () => {
        // Regression test for a framework-level gap: CRUDRoute.updateProperty (PUT /:id/:property) used to
        // call repoUtils.update() directly with no validation hook at all, bypassing validateUpdate's
        // ownership check entirely. Fixed upstream in @rapidrest/service-core@1.0.0-rc.28 by having
        // updateProperty invoke this.validateUpdate() first.
        it("Rejects hijacking uid via the single-property update route without a trusted role.", async () => {
            const route = new TestProfileRoute();

            await expect(
                (route as any).updateProperty("victim-uid", "uid", "third-party-uid", {
                    uid: "attacker-uid",
                    roles: [],
                }),
            ).rejects.toThrow(/does not have permission/);
        });
    });
});

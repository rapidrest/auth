///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAliasRoute — no HTTP server, no database.
import { CRUDRoute } from "@rapidrest/service-core";
import { BaseAliasRoute } from "../../src/routes/BaseAliasRoute.js";

class TestAliasRoute extends BaseAliasRoute<any> {}

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

            await expect((route as any).validateCreate(obj, undefined)).rejects.toThrow(
                /Authorization is required/,
            );
        });

        it("Processes each object in an array of aliases.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestAliasRoute();
            const objs: any = [{ alias: "a@example.com" }, { alias: "b@example.com" }];

            await (route as any).validateCreate(objs, { uid: "user-1" });

            expect(objs[0].userUid).toBe("user-1");
            expect(objs[1].userUid).toBe("user-1");
        });
    });

    describe("validateUpdate", () => {
        it("Throws when there is no authenticated user.", async () => {
            const route = new TestAliasRoute();
            const obj: any = { alias: "someone@example.com" };

            await expect((route as any).validateUpdate("alias-1", obj, undefined)).rejects.toThrow(
                /Authorization is required/,
            );
        });

        it("Allows an update that does not touch userUid.", async () => {
            const route = new TestAliasRoute();
            const obj: any = { alias: "new-value@example.com" };

            await expect(
                (route as any).validateUpdate("alias-1", obj, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        it("Allows a caller to update userUid to their own uid.", async () => {
            const route = new TestAliasRoute();
            const obj: any = { userUid: "user-1" };

            await expect(
                (route as any).validateUpdate("alias-1", obj, { uid: "user-1" }),
            ).resolves.toBeUndefined();
        });

        it("Rejects updating userUid to another user's uid without a trusted role.", async () => {
            const route = new TestAliasRoute();
            const obj: any = { userUid: "victim-uid" };

            await expect(
                (route as any).validateUpdate("alias-1", obj, { uid: "attacker-uid", roles: [] }),
            ).rejects.toThrow(/does not have permission/);
        });

        it("Allows a trusted (admin) caller to update userUid to another user's uid.", async () => {
            const route = new TestAliasRoute();
            const obj: any = { userUid: "victim-uid" };

            await expect(
                (route as any).validateUpdate("alias-1", obj, { uid: "admin-uid", roles: ["admin"] }),
            ).resolves.toBeUndefined();
        });
    });
});

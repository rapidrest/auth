///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthClientRoute — no HTTP server, no database. argon2 is real (the
// established pattern in this test suite, see BaseSecretRoute.test.ts), so the secret-generation tests
// below verify a genuine hash rather than a mocked one.
import { CRUDRoute } from "@rapidrest/service-core";
import { BaseOAuthClientRoute } from "../../src/routes/BaseOAuthClientRoute.js";
import { ClientType } from "../../src/models/types.js";

class TestOAuthClientRoute extends BaseOAuthClientRoute<any> {}

describe("BaseOAuthClientRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("validateCreate", () => {
        it("Delegates to CRUDRoute.validateCreate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { clientType: ClientType.PUBLIC };
            const user: any = { uid: "user-1" };

            await (route as any).validateCreate(obj, user);

            expect(spy).toHaveBeenCalledWith(obj, user);
        });

        describe("ownership", () => {
            it("Defaults obj.ownerUid to the authenticated caller's uid when unset.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.ownerUid).toBe("user-1");
            });

            it("Leaves obj.ownerUid unset for a trusted (admin) caller who didn't specify one.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC };

                await (route as any).validateCreate(obj, { uid: "admin-1", roles: ["admin"] });

                expect(obj.ownerUid).toBeUndefined();
            });

            it("Allows a caller to explicitly register a client for their own uid.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, ownerUid: "user-1" };

                await expect((route as any).validateCreate(obj, { uid: "user-1", roles: [] })).resolves.toBeUndefined();
            });

            it("Rejects registering a client owned by another user's uid without a trusted role.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, ownerUid: "victim-uid" };

                await expect(
                    (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] }),
                ).rejects.toThrow(/does not have permission/);
            });

            it("Allows a trusted (admin) caller to register a client owned by another user's uid.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, ownerUid: "someone-else" };

                await (route as any).validateCreate(obj, { uid: "admin-1", roles: ["admin"] });

                expect(obj.ownerUid).toBe("someone-else");
            });
        });

        describe("firstParty field-level rule", () => {
            it("Forces firstParty to false for a non-trusted caller.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, firstParty: true };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.firstParty).toBe(false);
            });

            it("Allows a trusted (admin) caller to set firstParty: true.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, firstParty: true };

                await (route as any).validateCreate(obj, { uid: "admin-1", roles: ["admin"] });

                expect(obj.firstParty).toBe(true);
            });

            it("Leaves firstParty untouched when not present on the payload at all.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect("firstParty" in obj).toBe(false);
            });
        });

        describe("PUBLIC clients", () => {
            it("Forces requirePkce to true regardless of what was requested.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, requirePkce: false };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.requirePkce).toBe(true);
            });

            it("Strips any client-supplied clientSecretHash — a public client is never issued a secret.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.PUBLIC, clientSecretHash: "attacker-supplied-hash" };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.clientSecretHash).toBeUndefined();
            });
        });

        it("Does nothing secret-related when clientType is neither PUBLIC nor CONFIDENTIAL.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { clientType: undefined };

            await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

            expect(obj.clientSecretHash).toBeUndefined();
            expect(obj._generatedClientSecret).toBeUndefined();
        });

        describe("CONFIDENTIAL clients", () => {
            it("Generates a fresh secret, persists only its argon2 hash, and stashes the plaintext for the response.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.CONFIDENTIAL };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.clientSecretHash).toBeDefined();
                expect(obj._generatedClientSecret).toBeDefined();
                expect(obj.clientSecretHash).not.toBe(obj._generatedClientSecret);
                const argon = await import("argon2");
                await expect(argon.verify(obj.clientSecretHash, obj._generatedClientSecret)).resolves.toBe(true);
            });

            it("Discards any client-supplied clientSecretHash, always minting a fresh one.", async () => {
                vi.spyOn(CRUDRoute.prototype as any, "validateCreate").mockResolvedValue(undefined);
                const route = new TestOAuthClientRoute();
                const obj: any = { clientType: ClientType.CONFIDENTIAL, clientSecretHash: "attacker-supplied-hash" };

                await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

                expect(obj.clientSecretHash).not.toBe("attacker-supplied-hash");
            });
        });
    });

    describe("create", () => {
        it("Strips clientSecretHash and attaches the one-time plaintext secret for a CONFIDENTIAL client.", async () => {
            const route = new TestOAuthClientRoute();
            const created: any = {
                uid: "client-1",
                clientType: ClientType.CONFIDENTIAL,
                clientSecretHash: "$argon2id$persisted-hash",
                _generatedClientSecret: "plaintext-secret",
            };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue(created);
            const req: any = {};

            const result: any = await route.create(created, req, { uid: "user-1" } as any);

            expect(result.clientSecretHash).toBeUndefined();
            expect(result.clientSecret).toBe("plaintext-secret");
        });

        it("Never attaches a clientSecret for a PUBLIC client (none was generated).", async () => {
            const route = new TestOAuthClientRoute();
            const created: any = { uid: "client-1", clientType: ClientType.PUBLIC };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue(created);

            const result: any = await route.create(created, {} as any, { uid: "user-1" } as any);

            expect(result.clientSecret).toBeUndefined();
        });

        it("Handles an array of created clients, matching each generated secret to its own input by position.", async () => {
            const route = new TestOAuthClientRoute();
            const input1: any = {
                clientType: ClientType.CONFIDENTIAL,
                _generatedClientSecret: "secret-1",
            };
            const input2: any = {
                clientType: ClientType.CONFIDENTIAL,
                _generatedClientSecret: "secret-2",
            };
            const created1: any = { uid: "client-1", clientSecretHash: "hash-1" };
            const created2: any = { uid: "client-2", clientSecretHash: "hash-2" };
            vi.spyOn(CRUDRoute.prototype as any, "create").mockResolvedValue([created1, created2]);

            const result: any = await route.create([input1, input2], {} as any, { uid: "user-1" } as any);

            expect(result).toHaveLength(2);
            expect(result[0].clientSecret).toBe("secret-1");
            expect(result[1].clientSecret).toBe("secret-2");
            expect(result[0].clientSecretHash).toBeUndefined();
            expect(result[1].clientSecretHash).toBeUndefined();
        });
    });

    describe("validateUpdate", () => {
        it("Delegates to CRUDRoute.validateUpdate() for schema validation.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { clientName: "New Name" };
            const user: any = { uid: "user-1" };

            await (route as any).validateUpdate("client-1", obj, user);

            expect(spy).toHaveBeenCalledWith("client-1", obj, user);
        });

        it("Rejects setting clientSecretHash directly, even for a trusted role.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { clientSecretHash: "attacker-supplied-hash" };

            await expect(
                (route as any).validateUpdate("client-1", obj, { uid: "admin-1", roles: ["admin"] }),
            ).rejects.toThrow(/cannot be set directly/);
        });

        it("Rejects changing the owner without a trusted role.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { ownerUid: "someone-else" };

            await expect(
                (route as any).validateUpdate("client-1", obj, { uid: "owner-1", roles: [] }),
            ).rejects.toThrow(/cannot change the owner/i);
        });

        it("Allows a trusted (admin) caller to change the owner.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { ownerUid: "someone-else" };

            await expect(
                (route as any).validateUpdate("client-1", obj, { uid: "admin-1", roles: ["admin"] }),
            ).resolves.toBeUndefined();
        });

        it("Silently drops a firstParty change from a non-trusted caller.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { firstParty: true };

            await (route as any).validateUpdate("client-1", obj, { uid: "owner-1", roles: [] });

            expect("firstParty" in obj).toBe(false);
        });

        it("Allows a trusted (admin) caller to change firstParty.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "validateUpdate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const obj: any = { firstParty: true };

            await (route as any).validateUpdate("client-1", obj, { uid: "admin-1", roles: ["admin"] });

            expect(obj.firstParty).toBe(true);
        });
    });

    describe("update", () => {
        it("Delegates to CRUDRoute.update() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "update").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const req: any = {};
            const user: any = { uid: "user-1" };
            const obj: any = { clientName: "New Name" };

            await route.update("client-1", obj, req, user);

            expect(spy).toHaveBeenCalledWith("client-1", obj, req, user);
        });
    });

    describe("delete", () => {
        it("Delegates to CRUDRoute.delete() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "delete").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const req: any = {};
            const user: any = { uid: "user-1" };

            await route.delete("client-1", "1", "true", req, user);

            expect(spy).toHaveBeenCalledWith("client-1", "1", "true", req, user);
        });
    });

    describe("count / exists / truncate / updateBulk / updateProperty", () => {
        it("count() delegates to CRUDRoute.count() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "count").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const res: any = {};
            const user: any = { uid: "user-1" };

            await route.count({}, {}, res, user);

            expect(spy).toHaveBeenCalledWith({}, {}, res, user);
        });

        it("exists() delegates to CRUDRoute.exists() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "exists").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const res: any = {};
            const user: any = { uid: "user-1" };

            await route.exists("client-1", {}, res, user);

            expect(spy).toHaveBeenCalledWith("client-1", {}, res, user);
        });

        it("truncate() delegates to CRUDRoute.truncate() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "truncate").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const user: any = { uid: "admin-1", roles: ["admin"] };

            await route.truncate({}, {}, user);

            expect(spy).toHaveBeenCalledWith({}, {}, user);
        });

        it("updateBulk() delegates to CRUDRoute.updateBulk() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "updateBulk").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const req: any = {};
            const user: any = { uid: "user-1" };
            const objs: any = [{ clientName: "New Name" }];

            await route.updateBulk(objs, req, user);

            expect(spy).toHaveBeenCalledWith(objs, req, user);
        });

        it("updateProperty() delegates to CRUDRoute.updateProperty() with the same arguments.", async () => {
            const spy = vi.spyOn(CRUDRoute.prototype as any, "updateProperty").mockResolvedValue(undefined);
            const route = new TestOAuthClientRoute();
            const user: any = { uid: "user-1" };

            await route.updateProperty("client-1", "clientName", "New Name", user);

            expect(spy).toHaveBeenCalledWith("client-1", "clientName", "New Name", user);
        });
    });

    describe("find", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestOAuthClientRoute();

            await expect(route.find({}, {}, { uid: "user-1" } as any)).rejects.toThrow(/internal error/i);
        });

        it("Scopes the query to the caller's own ownerUid and bypasses ACL for a non-trusted caller.", async () => {
            const route = new TestOAuthClientRoute();
            const find = vi.fn().mockResolvedValue([{ uid: "client-1", clientSecretHash: "hash" }]);
            (route as any).repoUtils = { find };
            const user: any = { uid: "user-1", roles: [] };

            const result = await route.find({}, { limit: 10, page: 1 }, user);

            expect(find).toHaveBeenCalledWith(
                { limit: 10, page: 1, ownerUid: "user-1" },
                { limit: 10, page: 1, ignoreACL: true, user },
            );
            // clientSecretHash must never round-trip on an ordinary read.
            expect(result[0].clientSecretHash).toBeUndefined();
        });

        it("Discards any client-supplied ownerUid filter, always scoping to the caller's own uid.", async () => {
            const route = new TestOAuthClientRoute();
            const find = vi.fn().mockResolvedValue([]);
            (route as any).repoUtils = { find };
            const user: any = { uid: "user-1", roles: [] };

            await route.find({}, { ownerUid: "someone-else" }, user);

            expect(find).toHaveBeenCalledWith(
                expect.objectContaining({ ownerUid: "user-1" }),
                expect.anything(),
            );
        });

        it("Uses the normal, unscoped CRUDRoute.find() for a trusted (admin) caller.", async () => {
            const spy = vi
                .spyOn(CRUDRoute.prototype as any, "find")
                .mockResolvedValue([{ uid: "client-1", clientSecretHash: "hash" }]);
            const route = new TestOAuthClientRoute();
            (route as any).repoUtils = {};
            const user: any = { uid: "admin-1", roles: ["admin"] };

            const result = await route.find({}, {}, user);

            expect(spy).toHaveBeenCalledWith({}, {}, user);
            expect(result[0].clientSecretHash).toBeUndefined();
        });
    });

    describe("findById", () => {
        it("Strips clientSecretHash from the result.", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "findById").mockResolvedValue({
                uid: "client-1",
                clientSecretHash: "hash",
            });
            const route = new TestOAuthClientRoute();

            const result: any = await route.findById("client-1", {}, { uid: "user-1" } as any);

            expect(result.clientSecretHash).toBeUndefined();
        });

        it("Returns null as-is when the client doesn't exist (or isn't visible to the caller).", async () => {
            vi.spyOn(CRUDRoute.prototype as any, "findById").mockResolvedValue(null);
            const route = new TestOAuthClientRoute();

            const result = await route.findById("missing", {}, { uid: "user-1" } as any);

            expect(result).toBeNull();
        });
    });

    describe("regenerateSecret", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestOAuthClientRoute();

            await expect(route.regenerateSecret("client-1", { uid: "user-1" } as any)).rejects.toThrow(
                /internal error/i,
            );
        });

        it("Throws NOT_FOUND when the client does not exist (or the caller isn't permitted to see it).", async () => {
            const route = new TestOAuthClientRoute();
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(undefined) };

            await expect(route.regenerateSecret("client-1", { uid: "user-1" } as any)).rejects.toThrow(
                /no resource could be found/i,
            );
        });

        it("Rejects regenerating a secret for a PUBLIC client.", async () => {
            const route = new TestOAuthClientRoute();
            (route as any).repoUtils = {
                findOne: vi.fn().mockResolvedValue({ uid: "client-1", version: 0, clientType: ClientType.PUBLIC }),
            };

            await expect(route.regenerateSecret("client-1", { uid: "user-1" } as any)).rejects.toThrow(
                /only a confidential client/i,
            );
        });

        it("Generates a new secret, persists only its hash (with the existing record's uid/version), and returns the plaintext once.", async () => {
            const route = new TestOAuthClientRoute();
            const existing = { uid: "client-1", version: 3, clientType: ClientType.CONFIDENTIAL };
            const update = vi.fn().mockResolvedValue(undefined);
            (route as any).repoUtils = { findOne: vi.fn().mockResolvedValue(existing), update };
            const user: any = { uid: "user-1" };

            const result = await route.regenerateSecret("client-1", user);

            expect(result.clientSecret).toBeDefined();
            expect(update).toHaveBeenCalledWith(
                { uid: "client-1", version: 3, clientSecretHash: expect.any(String) },
                existing,
                { user },
            );
            const [updateObj] = update.mock.calls[0];
            const argon = await import("argon2");
            await expect(argon.verify(updateObj.clientSecretHash, result.clientSecret)).resolves.toBe(true);
        });
    });
});

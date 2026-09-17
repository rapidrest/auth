///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseUserRoute — no HTTP server, no database. `ModelRoute`'s own `do*`
// behaviors are mocked directly on its prototype (BaseUserRoute never overrides them, it only calls
// `super.doX(...)`) so we can exercise BaseUserRoute's own logic (auto-login on create, roles/verified
// reconciliation) without booting a full server.
import { ACLAction, ModelRoute } from "@rapidrest/service-core";
import { BaseUserRoute } from "../../src/routes/BaseUserRoute.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";
import { SystemSettingsUtils } from "../../src/routes/SystemSettingsUtils.js";

/** A permissive default (registration open, MFA not mandated), overridable per test via `route.systemSettingsUtils`. */
function makeSystemSettingsUtils(overrides: { allowRegistration?: boolean; requireMFA?: boolean } = {}): any {
    return { get: vi.fn().mockResolvedValue({ allowRegistration: true, requireMFA: false, ...overrides }) };
}

class TestUserRoute extends BaseUserRoute<any> {
    constructor() {
        super();
        // Every test gets a working `systemSettingsUtils` by default (as `@Init` would provide once a real
        // `systemSettingsClass` is set) so that tests unrelated to registration/MFA policy don't all need to
        // wire this up themselves. A test that cares reconfigures `(route as any).systemSettingsUtils`.
        this.systemSettingsUtils = makeSystemSettingsUtils();
    }
}

function makeRes(): any {
    return { setHeader: vi.fn(), appendHeader: vi.fn() };
}

function makeTokenUtils(cookieEnabled: boolean): TokenUtils {
    const tokenUtils = new TokenUtils();
    (tokenUtils as any).jwtConfig = { secret: "test-secret", refresh: { expiresIn: "14 days" } };
    (tokenUtils as any).cookieConfig = {
        enabled: cookieEnabled,
        access: { name: "jwt" },
        refresh: { name: "refresh" },
    };
    return tokenUtils;
}

describe("BaseUserRoute Tests", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe("create", () => {
        it("Throws INTERNAL_ERROR when repoUtils is not set.", async () => {
            const route = new TestUserRoute();
            const req: any = {};

            await expect(route.create({ roles: [] } as any, req, makeRes())).rejects.toThrow(/internal error/i);
        });

        it("Throws INTERNAL_ERROR when tokenUtils is not set.", async () => {
            const route = new TestUserRoute();
            (route as any).repoUtils = { instantiateObject: (o: any) => o };
            const req: any = {};

            await expect(route.create({ roles: [] } as any, req, makeRes())).rejects.toThrow(/internal error/i);
        });

        it("Runs validateCreate() before creating the object.", async () => {
            const route = new TestUserRoute();
            const doCreate = vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid" });
            (route as any).repoUtils = { instantiateObject: (o: any) => ({ uid: "new-uid", ...o }) };
            (route as any).tokenUtils = makeTokenUtils(false);
            (route as any).authConfig = { secret: "test-secret" };
            const validateCreateSpy = vi.spyOn(route as any, "validateCreate").mockResolvedValue(undefined);
            const req: any = {};
            const user: any = { uid: "admin-uid", roles: ["admin"] };
            const obj: any = { roles: [] };

            await route.create(obj, req, makeRes(), user);

            expect(validateCreateSpy).toHaveBeenCalledWith(obj, user);
            expect(doCreate).toHaveBeenCalled();
        });

        it("Instantiates the object via repoUtils.instantiateObject() and grants the new record's own uid full owner ACL access.", async () => {
            const route = new TestUserRoute();
            const doCreate = vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid" });
            (route as any).repoUtils = {
                instantiateObject: (o: any) => ({ uid: "new-uid", ...o }),
                validate: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).tokenUtils = makeTokenUtils(false);
            (route as any).authConfig = { secret: "test-secret" };
            const req: any = {};
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await route.create({ roles: [] } as any, req, makeRes(), user);

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

        it("Returns an AuthResult with the created user and a freshly minted token, not the bare user object.", async () => {
            const route = new TestUserRoute();
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid", roles: [] });
            (route as any).repoUtils = {
                instantiateObject: (o: any) => ({ uid: "new-uid", ...o }),
                validate: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).tokenUtils = makeTokenUtils(false);
            (route as any).authConfig = { secret: "test-secret" };

            const result = await route.create({ roles: [] } as any, {} as any, makeRes());

            expect(result.user).toEqual({ uid: "new-uid", roles: [], elevated: expect.any(Number) });
            expect(typeof result.token).toBe("string");
            expect(result.token.length).toBeGreaterThan(0);
        });

        it("Mints the auth result using the configured defaultScopes.", async () => {
            const route = new TestUserRoute();
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid", roles: [] });
            (route as any).repoUtils = {
                instantiateObject: (o: any) => ({ uid: "new-uid", ...o }),
                validate: vi.fn().mockResolvedValue(undefined),
            };
            const tokenUtils = makeTokenUtils(false);
            const createAuthResultSpy = vi.spyOn(tokenUtils, "createAuthResult");
            (route as any).tokenUtils = tokenUtils;
            (route as any).authConfig = { secret: "test-secret" };
            (route as any).defaultScopes = ["profile"];
            const res = makeRes();
            const req: any = {};

            await route.create({ roles: [] } as any, req, res);

            expect(createAuthResultSpy).toHaveBeenCalledWith(
                { uid: "new-uid", roles: [] },
                ["profile"],
                req,
                res,
                true,
            );
        });

        it("Sets `Set-Cookie` headers for an unauthenticated (self-registration) call when cookie issuance is enabled.", async () => {
            const route = new TestUserRoute();
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid", roles: [] });
            (route as any).repoUtils = {
                instantiateObject: (o: any) => ({ uid: "new-uid", ...o }),
                validate: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).tokenUtils = makeTokenUtils(true);
            (route as any).authConfig = { secret: "test-secret" };
            const res = makeRes();

            const result = await route.create({ roles: [] } as any, {} as any, res, undefined);

            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining(`jwt=${result.token}`),
            );
            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining(`refresh=${result.refresh}`),
            );
        });

        // Regression: TokenUtils.createAuthResult() writes the issued tokens as Set-Cookie headers on
        // whatever `res` it's given. Before this fix, `res` was always forwarded regardless of caller - so
        // an already-authenticated caller (e.g. an admin provisioning a User for someone else) would have
        // the *new* account's session silently written to their *own* response, clobbering their own
        // session cookie with a session for an account that isn't theirs.
        //
        // Since then, admin-provisioned creation stopped minting a token at all (see the "does not need
        // to generate an access token" branch in BaseUserRoute.create()), so there's no longer a token to
        // leak via Set-Cookie in the first place — this test now confirms both properties together.
        it("Does not set a `Set-Cookie` header when the caller is already authenticated, and returns no token since the caller isn't logging in as the new account.", async () => {
            const route = new TestUserRoute();
            vi.spyOn(ModelRoute.prototype as any, "doCreate").mockResolvedValue({ uid: "new-uid", roles: [] });
            (route as any).repoUtils = {
                instantiateObject: (o: any) => ({ uid: "new-uid", ...o }),
                validate: vi.fn().mockResolvedValue(undefined),
            };
            (route as any).tokenUtils = makeTokenUtils(true);
            (route as any).authConfig = { secret: "test-secret" };
            const res = makeRes();
            const admin: any = { uid: "admin-uid", roles: ["admin"] };

            const result = await route.create({ roles: [] } as any, {} as any, res, admin);

            expect(res.appendHeader).not.toHaveBeenCalled();
            expect(result.token).toBe("");
            expect(result.refresh).toBe("");
            expect(result.user).toEqual({ uid: "new-uid", roles: [] });
        });
    });

    describe("validateCreate", () => {
        it("Runs base validation via this.validate().", async () => {
            const validateSpy = vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { roles: [] };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await (route as any).validateCreate(obj, user);

            expect(validateSpy).toHaveBeenCalledWith(obj, { user });
        });

        // Regression: without this, a caller able to reach create() by any means other than the class-level
        // ACL gate (e.g. a per-record/role CREATE grant that isn't a globally trusted role, or a looser
        // class ACL configured downstream) could provision a brand-new User with an elevated roles array
        // baked in from the start - the same account-takeover shape as the validateUpdate fix below, just
        // at creation time instead of update time.
        it("Resets roles to an empty array when a non-trusted caller includes it.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] });

            expect(obj.roles).toEqual([]);
        });

        it("Does not add a roles key at all when the client omitted it.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { verified: true };

            await (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] });

            expect("roles" in obj).toBe(false);
        });

        it("Allows a trusted (admin) caller to set roles on a newly-created user.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.roles).toEqual(["admin"]);
        });

        it("Allows an unauthenticated create call to proceed without roles present (resets to empty rather than rejecting).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { roles: ["admin"] };

            await (route as any).validateCreate(obj, undefined);

            expect(obj.roles).toEqual([]);
        });

        it("Resets verified to false when a non-trusted caller includes it.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { verified: true };

            await (route as any).validateCreate(obj, { uid: "attacker-uid", roles: [] });

            expect(obj.verified).toBe(false);
        });

        it("Allows a trusted (admin) caller to set verified:true on a newly-created user.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).authConfig = {};
            const obj: any = { verified: true };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.verified).toBe(true);
        });

        it("Forces requireMFA to the runtime system-settings value when set, overriding any client-supplied value.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { requireMFA: false };

            await (route as any).validateCreate(obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.requireMFA).toBe(true);
        });

        it("Leaves the client-supplied requireMFA alone when the system doesn't mandate it.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: false });
            const obj: any = { requireMFA: true };

            await (route as any).validateCreate(obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(true);
        });
    });

    describe("validateUpdate", () => {
        it("Runs base validation via this.validate().", async () => {
            const validateSpy = vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1" };
            const user: any = { uid: "admin-uid", roles: ["admin"] };

            await (route as any).validateUpdate("user-1", obj, user);

            expect(validateSpy).toHaveBeenCalledWith(obj, { user });
        });

        // Every possible change (roles, verified, requireMFA) needs the persisted record to compare
        // against, so the lookup is now unconditional rather than only firing when a specific field known
        // to need reconciliation is present in the request body.
        it("Always retrieves the existing record for comparison, even when the update touches none of roles/verified/requireMFA.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", someOtherField: "x" };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
        });

        // Regression: `roles` had no `@ReadOnly` protection and every self-registered user is automatically
        // granted UPDATE on their own record, so a plain PUT with an elevated roles array used to persist
        // unmodified - a full account takeover, since roles:["admin"] bypasses every ACL check system-wide.
        // The attempted roles change is silently discarded rather than rejecting the whole request.
        it("Reverts roles to the persisted value when a non-trusted caller attempts to change them.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", roles: [] });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", roles: ["admin"] };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.roles).toEqual([]);
        });

        it("Resets roles to an empty array when no existing user record is found.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", roles: ["admin"] };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.roles).toEqual([]);
        });

        it("Resolves the 'me' keyword to the caller's own uid when looking up the persisted roles.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", roles: [] });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { roles: ["admin"] };

            await (route as any).validateUpdate("me", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.roles).toEqual([]);
        });

        it("Does not add a roles key at all when the update doesn't include roles.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", roles: [] });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            // `verified: false` here (rather than `true`) is deliberate: it proves the absence of `roles`
            // alone leaves `obj.roles` untouched, without also tripping the separate verified-escalation
            // check below.
            const obj: any = { uid: "user-1", verified: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect("roles" in obj).toBe(false);
        });

        it("Allows a trusted (admin) caller to change another user's roles.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "victim-uid", roles: [] });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "victim-uid", roles: ["admin"] };

            await (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.roles).toEqual(["admin"]);
        });

        it("Resets verified to false when a non-trusted caller attempts to set it to true and it isn't already verified.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", verified: false });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", verified: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(findOne).toHaveBeenCalledWith("user-1", { ignoreACL: true });
            expect(obj.verified).toBe(false);
        });

        it("Allows a non-trusted caller to lower their own verified status (no false-positive block).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", verified: true });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", verified: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.verified).toBe(false);
        });

        it("Allows verified:true to pass through unchanged when the persisted record is already verified (no false-positive block on a no-op resubmission).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", verified: true });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "user-1", verified: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.verified).toBe(true);
        });

        it("Allows a trusted (admin) caller to verify another user.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "victim-uid", verified: false });
            (route as any).repoUtils = { findOne };
            (route as any).authConfig = {};
            const obj: any = { uid: "victim-uid", verified: true };

            await (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.verified).toBe(true);
        });

        it("Does not touch requireMFA when it's absent from the update.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: true });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "user-1", verified: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect("requireMFA" in obj).toBe(false);
        });

        it("Leaves requireMFA unchanged when it matches the persisted value (no-op resubmission, no override applied).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: true });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "user-1", requireMFA: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(true);
        });

        // Regression/coverage: once the server mandates MFA fleet-wide, a non-trusted caller can't budge
        // `requireMFA` off whatever is currently persisted, in *either* direction - this isn't just "force
        // to true", it's a full freeze for non-admins while the mandate is active.
        it("Freezes requireMFA at the persisted value for a non-trusted caller attempting to disable it while the server mandates MFA.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: true });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "user-1", requireMFA: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(true);
        });

        it("Freezes requireMFA at the persisted value for a non-trusted caller attempting to enable it while the server mandates MFA (a stale/legacy record predating the mandate).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: false });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "user-1", requireMFA: true };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(false);
        });

        it("Allows a trusted (admin) caller to change requireMFA even while the server mandates MFA fleet-wide.", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "victim-uid", requireMFA: true });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "victim-uid", requireMFA: false };

            await (route as any).validateUpdate("victim-uid", obj, { uid: "admin-uid", roles: ["admin"] });

            expect(obj.requireMFA).toBe(false);
        });

        it("Allows requireMFA to be changed freely by a non-trusted caller when the system has no configured opinion (requireMFA not mandated).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: true });
            (route as any).repoUtils = { findOne };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: false });
            const obj: any = { uid: "user-1", requireMFA: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(false);
        });

        it("Uses the runtime system settings over a stale authConfig snapshot (regression: validateUpdate previously read the static config directly).", async () => {
            vi.spyOn(ModelRoute.prototype as any, "validate").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const findOne = vi.fn().mockResolvedValue({ uid: "user-1", requireMFA: true });
            (route as any).repoUtils = { findOne };
            // A stale/never-updated static config says MFA isn't mandated, but an admin has since toggled it
            // on at runtime via `PUT /settings` — the freeze must follow the live value, not this snapshot.
            (route as any).authConfig = { requireMFA: false };
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ requireMFA: true });
            const obj: any = { uid: "user-1", requireMFA: false };

            await (route as any).validateUpdate("user-1", obj, { uid: "user-1", roles: [] });

            expect(obj.requireMFA).toBe(true);
        });
    });

    describe("update", () => {
        it("Delegates to ModelRoute.doUpdate().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doUpdate").mockResolvedValue({ uid: "user-1" });
            const route = new TestUserRoute();
            const req: any = {};
            const user: any = { uid: "user-1", roles: [] };

            const result = await route.update("user-1", { uid: "user-1" } as any, req, user);

            expect(spy).toHaveBeenCalledWith("user-1", { uid: "user-1" }, { user });
            expect(result).toEqual({ uid: "user-1" });
        });
    });

    describe("count / delete / exists / find / findById / truncate", () => {
        it("count() delegates to ModelRoute.doCount().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doCount").mockResolvedValue("count-result");
            const route = new TestUserRoute();
            const res: any = {};

            const result = await route.count({ p: 1 }, { q: 1 }, res, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith({ params: { p: 1 }, query: { q: 1 }, res, user: { uid: "u1" } });
            expect(result).toBe("count-result");
        });

        it("delete() delegates to ModelRoute.doDelete(), converting purge='true' to a boolean.", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doDelete").mockResolvedValue(undefined);
            const route = new TestUserRoute();
            const req: any = {};

            await route.delete("id-1", "2", "true", req, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith("id-1", { user: { uid: "u1" }, req, version: "2", purge: true });
        });

        it("exists() delegates to ModelRoute.doExists().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doExists").mockResolvedValue("exists-result");
            const route = new TestUserRoute();
            const res: any = {};

            const result = await route.exists("id-1", { q: 1 }, res, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith("id-1", { query: { q: 1 }, res, user: { uid: "u1" } });
            expect(result).toBe("exists-result");
        });

        it("find() delegates to ModelRoute.doFind().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doFind").mockResolvedValue(["a", "b"]);
            const route = new TestUserRoute();

            const result = await route.find({ p: 1 }, { q: 1 }, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith({ params: { p: 1 }, query: { q: 1 }, user: { uid: "u1" } });
            expect(result).toEqual(["a", "b"]);
        });

        it("findById() delegates to ModelRoute.doFindById().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doFindById").mockResolvedValue({ uid: "id-1" });
            const route = new TestUserRoute();

            const result = await route.findById("id-1", { q: 1 }, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith("id-1", { query: { q: 1 }, user: { uid: "u1" } });
            expect(result).toEqual({ uid: "id-1" });
        });

        it("truncate() delegates to ModelRoute.doTruncate().", async () => {
            const spy = vi.spyOn(ModelRoute.prototype as any, "doTruncate").mockResolvedValue(undefined);
            const route = new TestUserRoute();

            await route.truncate({ p: 1 }, { q: 1 }, { uid: "u1" } as any);

            expect(spy).toHaveBeenCalledWith({ params: { p: 1 }, query: { q: 1 }, user: { uid: "u1" } });
        });
    });

    describe("registration disabled", () => {
        function makeRoute(allowRegistration: boolean): TestUserRoute {
            const route = new TestUserRoute();
            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ allowRegistration });
            (route as any).trustedRoles = ["admin"];
            vi.spyOn(route as any, "validate").mockResolvedValue(undefined);
            return route;
        }

        it("Rejects an unauthenticated create with 403 when registration is disabled.", async () => {
            const route = makeRoute(false);

            await expect((route as any).validateCreate({}, undefined)).rejects.toMatchObject({ status: 403 });
        });

        it("Rejects a non-trusted authenticated create with 403 when registration is disabled.", async () => {
            const route = makeRoute(false);

            await expect((route as any).validateCreate({}, { uid: "user", roles: [] })).rejects.toMatchObject({
                status: 403,
            });
        });

        it("Never creates the user when registration is disabled.", async () => {
            const route = makeRoute(false);
            const doCreate = vi.spyOn(ModelRoute.prototype as any, "doCreate");
            (route as any).repoUtils = { instantiateObject: (o: any) => o };
            (route as any).tokenUtils = makeTokenUtils(false);

            await expect(route.create({} as any, {} as any, makeRes())).rejects.toMatchObject({ status: 403 });
            expect(doCreate).not.toHaveBeenCalled();
        });

        it("Still allows a trusted (admin) caller to create users when registration is closed.", async () => {
            const route = makeRoute(false);

            await expect(
                (route as any).validateCreate({}, { uid: "admin", roles: ["admin"] }),
            ).resolves.toBeUndefined();
        });

        it("Uses the current (possibly just-toggled) runtime settings on every call.", async () => {
            const route = makeRoute(false);

            await expect((route as any).validateCreate({}, undefined)).rejects.toMatchObject({ status: 403 });

            (route as any).systemSettingsUtils = makeSystemSettingsUtils({ allowRegistration: true });
            await expect((route as any).validateCreate({}, undefined)).resolves.toBeUndefined();
        });

        it("initSystemSettings() creates a shared SystemSettingsUtils for systemSettingsClass.", async () => {
            class FakeSettings {}
            const utils = makeSystemSettingsUtils();
            const newInstance = vi.fn().mockResolvedValue(utils);
            const route = new TestUserRoute();
            (route as any).systemSettingsUtils = undefined;
            (route as any).systemSettingsClass = FakeSettings;
            Object.defineProperty(route, "_objectFactory", { value: { newInstance } });

            await (route as any).initSystemSettings();
            await (route as any).initSystemSettings();

            expect(newInstance).toHaveBeenCalledTimes(1);
            expect(newInstance).toHaveBeenCalledWith(SystemSettingsUtils, {
                name: "FakeSettings",
                args: [FakeSettings],
            });
            expect((route as any).systemSettingsUtils).toBe(utils);
        });

        it("initSystemSettings() leaves an already-set systemSettingsUtils alone without a systemSettingsClass.", async () => {
            const route = new TestUserRoute();
            const existing = (route as any).systemSettingsUtils;

            await (route as any).initSystemSettings();

            expect((route as any).systemSettingsUtils).toBe(existing);
        });
    });
});

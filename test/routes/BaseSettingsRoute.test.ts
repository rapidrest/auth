///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseSettingsRoute — no HTTP server, no database. `SystemSettingsUtils` is a
// plain mock (it has its own dedicated test suite in SystemSettingsUtils.test.ts).
import { BaseSettingsRoute } from "../../src/routes/BaseSettingsRoute.js";
import { SystemSettingsUtils } from "../../src/routes/SystemSettingsUtils.js";
import { SystemSettings } from "../../src/models/types.js";

class FakeSettingsClass {
    static readonly name = "FakeSettings";
}

class TestSettingsRoute extends BaseSettingsRoute {
    protected settingsClass: any = FakeSettingsClass;
}

function makeSettingsUtils(overrides: Partial<SystemSettings> = {}): any {
    // A fresh `SystemSettings` instance per call, matching the real `SystemSettingsUtils.get()` — `get()`
    // mutates its result in place (via `ObjectUtils.deleteScopedProps`), so a shared/cached instance here
    // would let one call's stripped `requireMFA` leak into every later call.
    return {
        get: vi.fn().mockImplementation(async () => new SystemSettings({ allowRegistration: true, requireMFA: false, ...overrides })),
        update: vi.fn().mockResolvedValue(new SystemSettings({ allowRegistration: true, requireMFA: false, ...overrides })),
    };
}

describe("BaseSettingsRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory is not set.", async () => {
            const route = new TestSettingsRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates a SystemSettingsUtils for settingsClass using the object factory.", async () => {
            const utils = makeSettingsUtils();
            const newInstance = vi.fn().mockResolvedValue(utils);
            const route = new TestSettingsRoute();
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).toHaveBeenCalledWith(SystemSettingsUtils, {
                name: FakeSettingsClass.name,
                args: [FakeSettingsClass],
            });
            expect((route as any).settingsUtils).toBe(utils);
        });

        it("Does not recreate settingsUtils if it's already set.", async () => {
            const existing = makeSettingsUtils();
            const newInstance = vi.fn();
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = existing;
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).settingsUtils).toBe(existing);
        });
    });

    describe("get", () => {
        it("Returns the effective settings for an anonymous caller, with requireMFA stripped.", async () => {
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = makeSettingsUtils({ allowRegistration: false, requireMFA: true });

            const result = await route.get(undefined);

            expect(result.allowRegistration).toBe(false);
            expect("requireMFA" in result).toBe(false);
        });

        it("Strips requireMFA for an authenticated but non-trusted caller.", async () => {
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = makeSettingsUtils({ requireMFA: true });

            const result = await route.get({ uid: "user-1", roles: [], scopes: [] });

            expect("requireMFA" in result).toBe(false);
        });

        it("Lets a trusted-role caller see requireMFA, even without a matching token scope.", async () => {
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = makeSettingsUtils({ requireMFA: true });

            const result = await route.get({ uid: "admin-1", roles: ["admin"], scopes: [] });

            expect(result.requireMFA).toBe(true);
        });

        it("Lets a caller whose token itself carries the 'system' scope see requireMFA.", async () => {
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = makeSettingsUtils({ requireMFA: true });

            const result = await route.get({ uid: "svc-1", roles: [], scopes: ["system"] });

            expect(result.requireMFA).toBe(true);
        });

        it("Uses the configured trusted_roles rather than a hardcoded 'admin'.", async () => {
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = makeSettingsUtils({ requireMFA: true });
            (route as any).trustedRoles = ["superuser"];

            const nonTrustedAdmin = await route.get({ uid: "u1", roles: ["admin"], scopes: [] });
            expect("requireMFA" in nonTrustedAdmin).toBe(false);

            const trusted = await route.get({ uid: "u2", roles: ["superuser"], scopes: [] });
            expect(trusted.requireMFA).toBe(true);
        });
    });

    describe("update", () => {
        it("Forwards the request body to settingsUtils.update().", async () => {
            const utils = makeSettingsUtils({ allowRegistration: false });
            const route = new TestSettingsRoute();
            (route as any).settingsUtils = utils;

            const result = await route.update({ allowRegistration: false }, { uid: "admin-1", roles: ["admin"] } as any);

            expect(utils.update).toHaveBeenCalledWith({ allowRegistration: false });
            expect(result.allowRegistration).toBe(false);
        });

        // Route-level access control (trusted-role + elevation via `@RequiresTrustedRole()`) is enforced by
        // the framework's route dispatcher from this decorator metadata, not by this method's own body — this
        // just confirms the metadata is actually attached to the handler that's reachable over POST/PUT.
        it("Is decorated with @Auth(['jwt']) and @RequiresTrustedRole().", () => {
            const route = Reflect.getMetadata("rrst:route", TestSettingsRoute.prototype, "update");

            expect(route?.requiresTrustedRole).toBe(true);
            expect(route?.authStrategies).toEqual(["jwt"]);
        });
    });
});

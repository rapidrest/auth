///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseImpersonationRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { BaseImpersonationRoute } from "../../src/routes/BaseImpersonationRoute.js";

class FakeUserClass {
    static readonly name = "FakeUser";
}

class TestImpersonationRoute extends BaseImpersonationRoute<any> {
    protected userClass: any = FakeUserClass;
}

const target = { uid: "target-1", roles: [], scopes: [] };
const caller = { uid: "admin-1", roles: ["admin"], scopes: [] };

function makeUserRepo(users: any[] = [target]) {
    return {
        findOne: vi.fn(async (uid: string) => users.find((u) => u.uid === uid)),
    };
}

function makeRoute(overrides: { userRepo?: any; authConfig?: any } = {}) {
    const route = new TestImpersonationRoute();
    (route as any)._objectFactory = { newInstance: vi.fn() };
    (route as any).userRepo = overrides.userRepo ?? makeUserRepo();
    (route as any).authConfig = overrides.authConfig ?? { secret: "test-secret" };
    return route;
}

function makeRequest(overrides: any = {}): any {
    return { headers: {}, cookies: {}, socket: {}, ...overrides };
}

function makeResponse(): any {
    return { appendHeader: vi.fn(), setHeader: vi.fn() };
}

describe("BaseImpersonationRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if objectFactory was not injected.", async () => {
            const route = new TestImpersonationRoute();
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Creates userRepo via the object factory when unset.", async () => {
            const userRepo = makeUserRepo();
            const newInstance = vi.fn(async () => userRepo);
            const route = new TestImpersonationRoute();
            (route as any)._objectFactory = { newInstance };

            await (route as any).initialize();

            expect(newInstance).toHaveBeenCalledWith(RepoUtils, { name: "FakeUser", args: [FakeUserClass] });
            expect((route as any).userRepo).toBe(userRepo);
        });

        it("Does not recreate userRepo if already set.", async () => {
            const existingRepo = makeUserRepo();
            const newInstance = vi.fn();
            const route = new TestImpersonationRoute();
            (route as any)._objectFactory = { newInstance };
            (route as any).userRepo = existingRepo;

            await (route as any).initialize();

            expect(newInstance).not.toHaveBeenCalled();
            expect((route as any).userRepo).toBe(existingRepo);
        });
    });

    describe("impersonate", () => {
        it("Throws invalid_request when userUid is missing from the body.", async () => {
            const route = makeRoute();

            await expect(
                route.impersonate({} as any, makeRequest(), makeResponse(), caller),
            ).rejects.toMatchObject({ status: 400 });
        });

        it("Throws invalid_request when the body itself is missing.", async () => {
            const route = makeRoute();

            await expect(
                route.impersonate(undefined as any, makeRequest(), makeResponse(), caller),
            ).rejects.toMatchObject({ status: 400 });
        });

        it("Throws a 500 when auth config is not set.", async () => {
            const route = makeRoute();
            (route as any).authConfig = undefined;

            await expect(
                route.impersonate({ userUid: "target-1" }, makeRequest(), makeResponse(), caller),
            ).rejects.toMatchObject({ status: 500 });
        });

        it("Throws not_found when the target user does not exist.", async () => {
            const route = makeRoute({ userRepo: makeUserRepo([]) });

            await expect(
                route.impersonate({ userUid: "does-not-exist" }, makeRequest(), makeResponse(), caller),
            ).rejects.toMatchObject({ status: 404 });
        });

        it("Stashes the caller's current jwt cookie under jwt_impersonator when one is present.", async () => {
            const route = makeRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn(async () => ({ token: "t", refresh: "", user: target })) };
            const res = makeResponse();
            const req = makeRequest({ cookies: { jwt: "callers-own-token" } });

            await route.impersonate({ userUid: "target-1" }, req, res, caller);

            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining("jwt_impersonator=callers-own-token"),
            );
        });

        it("Does not stash anything when the caller has no current jwt cookie.", async () => {
            const route = makeRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn(async () => ({ token: "t", refresh: "", user: target })) };
            const res = makeResponse();
            const req = makeRequest();

            await route.impersonate({ userUid: "target-1" }, req, res, caller);

            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        it("Issues a non-elevated, impersonation-flagged token for the target user via tokenUtils.", async () => {
            const route = makeRoute();
            const createAuthResult = vi.fn(async () => ({ token: "target-token", refresh: "", user: target }));
            (route as any).tokenUtils = { createAuthResult };
            (route as any).defaultScopes = ["read"];
            const req = makeRequest();
            const res = makeResponse();

            const result = await route.impersonate({ userUid: "target-1" }, req, res, caller);

            expect(createAuthResult).toHaveBeenCalledWith(target, ["read"], req, res, false, true);
            expect(result).toEqual({ token: "target-token", refresh: "", user: target });
        });

        it("Logs a warning naming both the impersonator and the impersonated user.", async () => {
            const route = makeRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn(async () => ({ token: "t", refresh: "", user: target })) };
            const warn = vi.fn();
            (route as any).logger = { warn };

            await route.impersonate({ userUid: "target-1" }, makeRequest(), makeResponse(), caller);

            expect(warn).toHaveBeenCalledWith(expect.stringContaining("admin-1"));
            expect(warn).toHaveBeenCalledWith(expect.stringContaining("target-1"));
        });

        it("Does not throw when no logger was injected.", async () => {
            const route = makeRoute();
            (route as any).tokenUtils = { createAuthResult: vi.fn(async () => ({ token: "t", refresh: "", user: target })) };

            await expect(
                route.impersonate({ userUid: "target-1" }, makeRequest(), makeResponse(), caller),
            ).resolves.toBeDefined();
        });
    });

    describe("stopImpersonating", () => {
        it("Returns restored:false and sets no cookies when no jwt_impersonator cookie is present.", async () => {
            const route = makeRoute();
            const res = makeResponse();

            const result = await route.stopImpersonating(makeRequest(), res, caller);

            expect(result).toEqual({ restored: false });
            expect(res.appendHeader).not.toHaveBeenCalled();
        });

        it("Restores the stashed session as jwt and clears jwt_impersonator when present.", async () => {
            const route = makeRoute();
            const res = makeResponse();
            const req = makeRequest({ cookies: { jwt_impersonator: "admins-original-token" } });

            const result = await route.stopImpersonating(req, res, caller);

            expect(result).toEqual({ restored: true });
            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining("jwt=admins-original-token"),
            );
            expect(res.appendHeader).toHaveBeenCalledWith(
                "Set-Cookie",
                expect.stringContaining("jwt_impersonator=;"),
            );
        });

        it("Logs a warning naming the user that was being impersonated.", async () => {
            const route = makeRoute();
            const warn = vi.fn();
            (route as any).logger = { warn };
            const req = makeRequest({ cookies: { jwt_impersonator: "admins-original-token" } });

            await route.stopImpersonating(req, makeResponse(), target);

            expect(warn).toHaveBeenCalledWith(expect.stringContaining("target-1"));
        });

        it("Does not throw when no logger was injected.", async () => {
            const route = makeRoute();
            const req = makeRequest({ cookies: { jwt_impersonator: "admins-original-token" } });

            await expect(route.stopImpersonating(req, makeResponse(), target)).resolves.toEqual({ restored: true });
        });
    });
});

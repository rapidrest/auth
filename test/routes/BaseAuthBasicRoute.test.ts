///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthBasicRoute — no HTTP server, no database. ObjectFactory and
// AuthMiddleware are mocked directly so initialize() and the verify() closure it builds can be
// exercised (including their defensive "not set" guards) without a full Server/route-scan.
import { EventUtils } from "@rapidrest/core";
import { RepoUtils } from "@rapidrest/service-core";
import { BasicStrategy, BasicStrategyOptions } from "../../src/auth/BasicStrategy.js";
import { AuthEventType } from "../../src/auth/events.js";
import { BaseAuthBasicRoute } from "../../src/routes/BaseAuthBasicRoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { SecretType } from "../../src/models/types.js";

class FakeSecretClass {
    static readonly name = "FakeSecret";
}
class FakeUserClass {
    static readonly name = "FakeUser";
}
class FakeAliasClass {
    static readonly name = "FakeAlias";
}

class TestAuthBasicRoute extends BaseAuthBasicRoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(secretRepo: any, userUtils: any) {
    let capturedOptions: BasicStrategyOptions | undefined;
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            return secretRepo;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        if (type === BasicStrategy) {
            capturedOptions = opts.args[0];
            return new BasicStrategy(capturedOptions);
        }
        return undefined;
    });
    return { objectFactory: { newInstance }, getOptions: () => capturedOptions };
}

describe("BaseAuthBasicRoute Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthBasicRoute();
        (route as any)._objectFactory = makeMockObjectFactory({}, {}).objectFactory;

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthBasicRoute();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate secretRepo/userUtils if initialize() runs again.", async () => {
        const route = new TestAuthBasicRoute();
        (route as any).authMiddleware = { register: vi.fn() };
        const { objectFactory } = makeMockObjectFactory({}, {});
        (route as any)._objectFactory = objectFactory;
        const existingSecretRepo = { find: vi.fn() };
        const existingUserUtils = { lookup: vi.fn() };
        (route as any).secretRepo = existingSecretRepo;
        (route as any).userUtils = existingUserUtils;

        await (route as any).initialize();

        expect((route as any).secretRepo).toBe(existingSecretRepo);
        expect((route as any).userUtils).toBe(existingUserUtils);
    });

    it("Registers a BasicStrategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthBasicRoute();
        (route as any).authMiddleware = { register };
        const { objectFactory } = makeMockObjectFactory({}, {});
        (route as any)._objectFactory = objectFactory;

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("basic", expect.any(BasicStrategy));
    });

    describe("options.verify closure", () => {
        async function setupRoute() {
            const secretRepo = { find: vi.fn() };
            const userUtils = { lookup: vi.fn() };
            const register = vi.fn();
            const route = new TestAuthBasicRoute();
            (route as any).authMiddleware = { register };
            const { objectFactory, getOptions } = makeMockObjectFactory(secretRepo, userUtils);
            (route as any)._objectFactory = objectFactory;

            await (route as any).initialize();

            return { route, secretRepo, userUtils, verify: getOptions()!.verify.bind(getOptions()) };
        }

        it("Throws if secretRepo is not set when verify() runs.", async () => {
            const { route, verify } = await setupRoute();
            (route as any).secretRepo = undefined;

            await expect(verify("user1", "pass1")).rejects.toThrow(/Secret repository not set/);
        });

        it("Throws if userUtils is not set when verify() runs.", async () => {
            const { route, verify } = await setupRoute();
            (route as any).userUtils = undefined;

            await expect(verify("user1", "pass1")).rejects.toThrow(/User repository not set/);
        });

        it("Throws when the user cannot be found.", async () => {
            const { userUtils, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue(undefined);

            await expect(verify("unknown-user", "pass1")).rejects.toThrow(/Invalid name or password/);
        });

        it("Performs a dummy Argon2 verification when the user cannot be found, to equalize response timing.", async () => {
            const { userUtils, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue(undefined);
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect(verify("unknown-user", "pass1")).rejects.toThrow(/Invalid name or password/);

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1", "unknown-user", expect.any(Object));
        });

        // Regression: the dummy-Argon2 timing equalization above only covered the "no such user" case —
        // when the user exists but has zero password-type secrets (e.g. an OIDC-only/passkey-only account),
        // the verify loop used to never execute at all, returning near-instantly and creating a third,
        // faster timing class an attacker could use to distinguish this case via response latency.
        it("Performs a dummy Argon2 verification when the user has no password secret, to equalize response timing.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([]);
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect(verify("user1", "pass1")).rejects.toThrow(/Invalid name or password/);

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1", "user-uid-1", expect.any(Object));
        });

        // Regression/coverage: `requireMFA` accounts must reject basic auth entirely rather than let a
        // correct password succeed, since basic auth has no way to prompt for a second factor.
        it("Throws when the account requires MFA and no app password matches, without ever checking any PASSWORD secret.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
            // No app passwords on this account - the app-password check below finds nothing to match.
            secretRepo.find.mockResolvedValue([]);

            await expect(verify("user1", "pass1")).rejects.toThrow(/Invalid name or password/);
            expect(secretRepo.find).not.toHaveBeenCalledWith(
                expect.objectContaining({ type: SecretType.PASSWORD }),
                expect.anything(),
            );
        });

        // The message and timing must match every other rejection path in this function (unknown user, no
        // password secret, wrong password) - a distinct "requires MFA" message would let an attacker
        // enumerate valid usernames, and which of them have MFA enabled, purely from the error text.
        it("Performs a dummy Argon2 verification when the account requires MFA, to equalize response timing and error message with other rejection paths.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
            secretRepo.find.mockResolvedValue([]);
            const shared = await import("../../src/auth/shared.js");
            const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

            await expect(verify("user1", "pass1")).rejects.toThrow(/Invalid name or password/);

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1", "user-uid-1", expect.any(Object));
        });

        // Stored hashes are built via normalizePasswordSubmission() rather than a raw argon2.hash(password)
        // to mirror what BaseSecretRoute actually persists: the canonical (would-be client-hashed) form of
        // a plaintext password, not the plaintext itself — see BaseSecretRoute.processPasswordSecret().
        it("Allows login to proceed to password verification when requireMFA is false.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: false });
            const canonical = await shared.normalizePasswordSubmission(
                "correct-password",
                "user-uid-1",
                new (await import("../../src/auth/types.js")).PasswordConfig(),
            );
            secretRepo.find.mockResolvedValue([{ data: await argon2.hash(canonical) }]);

            const user = await verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1", requireMFA: false });
        });

        it("Throws when none of the user's stored passwords match.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            const canonical = await shared.normalizePasswordSubmission(
                "correct-password",
                "user-uid-1",
                new (await import("../../src/auth/types.js")).PasswordConfig(),
            );
            secretRepo.find.mockResolvedValue([{ data: await argon2.hash(canonical) }]);

            await expect(verify("user1", "wrong-password")).rejects.toThrow(/Invalid name or password/);
            expect(secretRepo.find).toHaveBeenCalledWith(
                { userUid: "user-uid-1", type: SecretType.PASSWORD },
                { ignoreACL: true },
            );
        });

        it("Resolves the user when at least one stored password matches.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            const config = new (await import("../../src/auth/types.js")).PasswordConfig();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([
                { data: await argon2.hash(await shared.normalizePasswordSubmission("another-password", "user-uid-1", config)) },
                { data: await argon2.hash(await shared.normalizePasswordSubmission("correct-password", "user-uid-1", config)) },
            ]);

            const user = await verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
        });

        // Proves the dual-mode requirement: a capable client submitting its own locally-computed
        // Argon2id hash (instead of the plaintext) authenticates against the same stored credential.
        it("Resolves the user when the submitted value is already a client-side hash of the correct password.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            const config = new (await import("../../src/auth/types.js")).PasswordConfig();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            const clientHash = await argon2.hash("correct-password", {
                salt: shared.deriveClientSalt("user-uid-1"),
                ...shared.CLIENT_ARGON2_PARAMS,
            });
            secretRepo.find.mockResolvedValue([{ data: await argon2.hash(clientHash) }]);

            const user = await verify("user1", clientHash);

            expect(user).toEqual({ uid: "user-uid-1" });
        });

        // Regression/coverage: a non-WeakClientHashError thrown while normalizing (e.g. deriveClientSalt()
        // choking on a malformed uid) must propagate, not be silently swallowed alongside the
        // WeakClientHashError case handled above.
        it("Propagates a non-WeakClientHashError thrown while normalizing, rather than swallowing it.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue({ uid: 123 as any });
            // No app passwords - so the app-password check below (a plain argon2 comparison, no
            // normalization involved) finds nothing to match and falls through to the real password check.
            secretRepo.find.mockImplementation(async (query: any) =>
                query.type === SecretType.APP_PASSWORD ? [] : [{ data: "some-hash" }],
            );

            await expect(verify("user1", "correct-password")).rejects.toThrow(/must be of type string/);
        });

        describe("app passwords", () => {
            // Core feature proof: an app password authenticates even when requireMFA is set, intentionally
            // bypassing the gate a real password is subject to a few lines below.
            it("Resolves the user via a matching app password even when requireMFA is true.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ data: await argon2.hash("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567") }]
                        : [],
                );

                const user = await verify("user1", "ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567");

                expect(user).toEqual({ uid: "user-uid-1", requireMFA: true });
                expect(secretRepo.find).toHaveBeenCalledWith(
                    { userUid: "user-uid-1", type: SecretType.APP_PASSWORD },
                    { ignoreACL: true },
                );
            });

            it("Resolves the user via a matching app password when requireMFA is false too.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: false });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ data: await argon2.hash("ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567") }]
                        : [],
                );

                const user = await verify("user1", "ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567");

                expect(user).toEqual({ uid: "user-uid-1", requireMFA: false });
            });

            it("Resolves the user when any of several app passwords matches, and each is checked with a plain argon2 comparison (never normalizePasswordSubmission()).", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ data: await argon2.hash("first-app-password") }, { data: await argon2.hash("second-app-password") }]
                        : [],
                );

                const user = await verify("user1", "second-app-password");

                expect(user).toEqual({ uid: "user-uid-1" });
            });

            it("Falls through to the normal requireMFA/password checks (and ultimately rejects) when the submitted value doesn't match any app password.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD ? [{ data: await argon2.hash("real-app-password") }] : [],
                );

                await expect(verify("user1", "wrong-app-password")).rejects.toThrow(/Invalid name or password/);
            });

            it("A real password is still rejected when requireMFA is true, unaffected by app-password support (existing behavior preserved).", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const shared = await import("../../src/auth/shared.js");
                const argon2 = await import("argon2");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
                const canonical = await shared.normalizePasswordSubmission(
                    "correct-password",
                    "user-uid-1",
                    new (await import("../../src/auth/types.js")).PasswordConfig(),
                );
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD ? [] : [{ data: await argon2.hash(canonical) }],
                );

                await expect(verify("user1", "correct-password")).rejects.toThrow(/Invalid name or password/);
            });

            it("Performs a dummy Argon2 verification when the account has no app-password secrets, to equalize response timing.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
                secretRepo.find.mockResolvedValue([]);
                const shared = await import("../../src/auth/shared.js");
                const verifyDummySpy = vi.spyOn(shared, "verifyDummyPassword");

                await expect(verify("user1", "some-value")).rejects.toThrow(/Invalid name or password/);

                // No userUid/config - app passwords have no client-hashing concept to equalize against.
                expect(verifyDummySpy).toHaveBeenCalledWith("some-value");
            });

            it("Does not check app passwords at all when appPasswordEnabled is false.", async () => {
                const { route, userUtils, secretRepo, verify } = await setupRoute();
                (route as any).appPasswordEnabled = false;
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });

                await expect(verify("user1", "some-value")).rejects.toThrow(/Invalid name or password/);

                expect(secretRepo.find).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: SecretType.APP_PASSWORD }),
                    expect.anything(),
                );
            });

            // Regression: disabling app passwords deployment-wide must stop an already-created one from
            // authenticating - it falls through to the normal password path, which correctly rejects it
            // since it's stored under SecretType.APP_PASSWORD, not SecretType.PASSWORD. Real-password auth
            // itself must be unaffected by the flag.
            it("Stops a previously-valid app password from authenticating once appPasswordEnabled is false, without affecting real-password auth.", async () => {
                const { route, userUtils, secretRepo, verify } = await setupRoute();
                (route as any).appPasswordEnabled = false;
                const argon2 = await import("argon2");
                const shared = await import("../../src/auth/shared.js");
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: false });
                const canonical = await shared.normalizePasswordSubmission(
                    "correct-password",
                    "user-uid-1",
                    new (await import("../../src/auth/types.js")).PasswordConfig(),
                );
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.PASSWORD ? [{ data: await argon2.hash(canonical) }] : [],
                );

                // The app password itself no longer authenticates...
                await expect(verify("user1", "ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567")).rejects.toThrow(
                    /Invalid name or password/,
                );
                // ...but the real password still does.
                const user = await verify("user1", "correct-password");
                expect(user).toEqual({ uid: "user-uid-1", requireMFA: false });
            });

            // lastUsedAt + auth.app_password.used - the single most security-relevant new signal this
            // feature adds (a match here means requireMFA was bypassed for this login).
            it("Touches only the matched app password's lastUsedAt, and records an auth.app_password.used event, on a successful match.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                const shared = await import("../../src/auth/shared.js");
                const touchSpy = vi.spyOn(shared, "touchSecretLastUsedAt").mockResolvedValue(undefined);
                const eventSpy = vi.spyOn(EventUtils, "record").mockResolvedValue(undefined);
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [
                              { uid: "app-pw-1", data: await argon2.hash("first-app-password") },
                              { uid: "app-pw-2", data: await argon2.hash("second-app-password") },
                          ]
                        : [],
                );
                const req: any = { path: "/auth/basic", socket: { remoteAddress: "1.2.3.4" }, headers: {} };

                const user = await verify("user1", "second-app-password", req);

                expect(user).toEqual({ uid: "user-uid-1" });
                // Only the matched secret (app-pw-2) is touched - not app-pw-1, which was never used.
                expect(touchSpy).toHaveBeenCalledTimes(1);
                expect(touchSpy).toHaveBeenCalledWith(secretRepo, "app-pw-2");
                expect(eventSpy).toHaveBeenCalledWith({
                    type: AuthEventType.APP_PASSWORD_USED,
                    userUid: "user-uid-1",
                    ip: expect.any(String),
                    secretUid: "app-pw-2",
                    path: "/auth/basic",
                });
            });

            it("Also records an auth.app_password.used entry via AuditLogUtils, and stashes authMethodUsed on the request, on a successful match.", async () => {
                const { userUtils, secretRepo, verify, route } = await setupRoute();
                const argon2 = await import("argon2");
                const auditLogUtils = { record: vi.fn().mockResolvedValue(undefined) };
                (route as any).auditLogUtils = auditLogUtils;
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ uid: "app-pw-1", data: await argon2.hash("app-password-value") }]
                        : [],
                );
                const req: any = { path: "/auth/basic", socket: { remoteAddress: "1.2.3.4" }, headers: {} };

                await verify("user1", "app-password-value", req);

                expect(auditLogUtils.record).toHaveBeenCalledWith({
                    type: AuthEventType.APP_PASSWORD_USED,
                    userUid: "user-uid-1",
                    ip: expect.any(String),
                    path: "/auth/basic",
                    data: { secretUid: "app-pw-1" },
                });
                expect(req.authMethodUsed).toBe("app-password");
            });

            it("Still resolves the user via a matching app password even when AuditLogUtils.record() itself rejects, and logs the failure loudly.", async () => {
                const { userUtils, secretRepo, verify, route } = await setupRoute();
                const argon2 = await import("argon2");
                const error = vi.fn();
                (route as any).logger = { error };
                (route as any).auditLogUtils = { record: vi.fn().mockRejectedValue(new Error("db down")) };
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ uid: "app-pw-1", data: await argon2.hash("app-password-value") }]
                        : [],
                );

                const user = await verify("user1", "app-password-value");

                expect(user).toEqual({ uid: "user-uid-1" });
                expect(error).toHaveBeenCalledTimes(1);
                expect(error.mock.calls[0][0]).toContain(AuthEventType.APP_PASSWORD_USED);
            });

            it("Does not record an auth.app_password.used event when the app password does not match.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                const eventSpy = vi.spyOn(EventUtils, "record").mockResolvedValue(undefined);
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: true });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD ? [{ data: await argon2.hash("real-app-password") }] : [],
                );

                await expect(verify("user1", "wrong-app-password")).rejects.toThrow(/Invalid name or password/);

                expect(eventSpy).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AuthEventType.APP_PASSWORD_USED }),
                );
            });

            it("Does not record an auth.app_password.used event when a real password authenticates instead.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                const shared = await import("../../src/auth/shared.js");
                const eventSpy = vi.spyOn(EventUtils, "record").mockResolvedValue(undefined);
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1", requireMFA: false });
                const canonical = await shared.normalizePasswordSubmission(
                    "correct-password",
                    "user-uid-1",
                    new (await import("../../src/auth/types.js")).PasswordConfig(),
                );
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.PASSWORD ? [{ data: await argon2.hash(canonical) }] : [],
                );

                const user = await verify("user1", "correct-password");

                expect(user).toEqual({ uid: "user-uid-1", requireMFA: false });
                expect(eventSpy).not.toHaveBeenCalledWith(
                    expect.objectContaining({ type: AuthEventType.APP_PASSWORD_USED }),
                );
            });

            it("Still resolves the user via a matching app password even when EventUtils.record() itself rejects.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                vi.spyOn(EventUtils, "record").mockRejectedValue(new Error("telemetry down"));
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ uid: "app-pw-1", data: await argon2.hash("app-password-value") }]
                        : [],
                );

                const user = await verify("user1", "app-password-value");

                expect(user).toEqual({ uid: "user-uid-1" });
            });

            it("Still resolves the user via a matching app password even when touchSecretLastUsedAt() itself rejects.", async () => {
                const { userUtils, secretRepo, verify } = await setupRoute();
                const argon2 = await import("argon2");
                const shared = await import("../../src/auth/shared.js");
                vi.spyOn(shared, "touchSecretLastUsedAt").mockRejectedValue(new Error("datastore unavailable"));
                userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
                secretRepo.find.mockImplementation(async (query: any) =>
                    query.type === SecretType.APP_PASSWORD
                        ? [{ uid: "app-pw-1", data: await argon2.hash("app-password-value") }]
                        : [],
                );

                const user = await verify("user1", "app-password-value");

                expect(user).toEqual({ uid: "user-uid-1" });
            });
        });

        it("Touches the matched password secret's lastUsedAt on a successful real-password login.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            const config = new (await import("../../src/auth/types.js")).PasswordConfig();
            const touchSpy = vi.spyOn(shared, "touchSecretLastUsedAt").mockResolvedValue(undefined);
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([
                { uid: "pw-1", data: await argon2.hash(await shared.normalizePasswordSubmission("another-password", "user-uid-1", config)) },
                { uid: "pw-2", data: await argon2.hash(await shared.normalizePasswordSubmission("correct-password", "user-uid-1", config)) },
            ]);

            const user = await verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
            // Only the matched secret (pw-2) is touched - not pw-1, which never matched.
            expect(touchSpy).toHaveBeenCalledTimes(1);
            expect(touchSpy).toHaveBeenCalledWith(secretRepo, "pw-2");
        });

        it("Still resolves the user via a matching real password even when touchSecretLastUsedAt() itself rejects.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            const shared = await import("../../src/auth/shared.js");
            const config = new (await import("../../src/auth/types.js")).PasswordConfig();
            vi.spyOn(shared, "touchSecretLastUsedAt").mockRejectedValue(new Error("datastore unavailable"));
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([
                { uid: "pw-1", data: await argon2.hash(await shared.normalizePasswordSubmission("correct-password", "user-uid-1", config)) },
            ]);

            const user = await verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
        });
    });

    describe("authenticate", () => {
        it("Passes authMethod 'password' to createAuthResult for a real password login.", async () => {
            const route = new TestAuthBasicRoute();
            const createAuthResult = vi.fn().mockResolvedValue({ token: "t", refresh: "r", user: {} });
            (route as any).tokenUtils = { createAuthResult };
            const user: any = { uid: "user-uid-1" };
            const req: any = { headers: {} };
            const res: any = {};

            await route.authenticate(user, req, res);

            expect(createAuthResult).toHaveBeenCalledWith(user, [], req, res, false, false, "password");
        });

        it("Passes authMethod 'app-password' when verify() stashed it on the request.", async () => {
            const route = new TestAuthBasicRoute();
            const createAuthResult = vi.fn().mockResolvedValue({ token: "t", refresh: "r", user: {} });
            (route as any).tokenUtils = { createAuthResult };
            const user: any = { uid: "user-uid-1" };
            const req: any = { headers: {}, authMethodUsed: "app-password" };
            const res: any = {};

            await route.authenticate(user, req, res);

            expect(createAuthResult).toHaveBeenCalledWith(user, [], req, res, false, false, "app-password");
        });
    });
});

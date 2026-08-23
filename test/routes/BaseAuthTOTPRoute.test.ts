///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthTOTPRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { TOTPStrategy } from "../../src/auth/TOTPStrategy.js";
import { BaseAuthTOTPRoute } from "../../src/routes/BaseAuthTOTPRoute.js";
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

class TestAuthTOTPRoute extends BaseAuthTOTPRoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(secretRepo: any, userUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            return secretRepo;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        if (type === TOTPStrategy) {
            return new TOTPStrategy(opts.args[0]);
        }
        return undefined;
    });
    return { newInstance };
}

describe("BaseAuthTOTPRoute Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthTOTPRoute();
        (route as any)._objectFactory = makeMockObjectFactory({}, {});

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthTOTPRoute();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate secretRepo/userUtils if initialize() runs again.", async () => {
        const route = new TestAuthTOTPRoute();
        (route as any).authMiddleware = { register: vi.fn() };
        (route as any)._objectFactory = makeMockObjectFactory({}, {});
        const existingSecretRepo = { find: vi.fn() };
        const existingUserUtils = { lookup: vi.fn() };
        (route as any).secretRepo = existingSecretRepo;
        (route as any).userUtils = existingUserUtils;

        await (route as any).initialize();

        expect((route as any).secretRepo).toBe(existingSecretRepo);
        expect((route as any).userUtils).toBe(existingUserUtils);
    });

    it("Registers a TOTPStrategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthTOTPRoute();
        (route as any).authMiddleware = { register };
        (route as any)._objectFactory = makeMockObjectFactory({}, {});

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("totp", expect.any(TOTPStrategy));
    });

    describe("getSecrets", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthTOTPRoute();
            await expect((route as any).getSecrets("user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns the .data of each matching secret, with the secret's own uid attached.", async () => {
            const route = new TestAuthTOTPRoute();
            const find = vi.fn().mockResolvedValue([
                { uid: "secret-1", data: { secret: "AAAA" } },
                { uid: "secret-2", data: { secret: "BBBB" } },
            ]);
            (route as any).secretRepo = { find };

            const result = await (route as any).getSecrets("user-1");

            expect(find).toHaveBeenCalledWith({ type: SecretType.TOTP, userUid: "user-1" }, { ignoreACL: true });
            // `uid` is attached so a successful verification can be traced back to the specific
            // record to persist replay-protection state onto (see updateSecretTimeStep).
            expect(result).toEqual([
                { secret: "AAAA", uid: "secret-1" },
                { secret: "BBBB", uid: "secret-2" },
            ]);
        });
    });

    describe("updateSecretTimeStep", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthTOTPRoute();
            await expect((route as any).updateSecretTimeStep("secret-1", 42)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthTOTPRoute();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's lastTimeStep when a matching secret is found.", async () => {
            const route = new TestAuthTOTPRoute();
            const secret = { uid: "secret-1", version: 1, data: { secret: "AAAA" } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateSecretTimeStep("secret-1", 42);

            expect(secret.data.lastTimeStep).toBe(42);
            expect(update).toHaveBeenCalledWith(
                { uid: "secret-1", version: 1, data: secret.data },
                secret,
                { ignoreACL: true, recordEvent: false },
            );
        });

        // Regression: two concurrent requests holding the same valid code both pass verification (against
        // their own, now-stale reads) before either one reaches this method - without re-checking against a
        // fresh read here, the second to arrive would silently overwrite with the same timeStep and let a
        // second session authenticate on an already-used code.
        it("Throws and does not persist when lastTimeStep has already been advanced to at least this timeStep (replay/race).", async () => {
            const route = new TestAuthTOTPRoute();
            const secret = { uid: "secret-1", version: 2, data: { secret: "AAAA", lastTimeStep: 42 } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await expect((route as any).updateSecretTimeStep("secret-1", 42)).rejects.toThrow(
                /already been used/,
            );

            expect(update).not.toHaveBeenCalled();
        });
    });

    describe("getUser", () => {
        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthTOTPRoute();
            await expect((route as any).getUser("user-1")).rejects.toThrow(/userUtils is not set/);
        });

        it("Delegates to userUtils.lookup().", async () => {
            const route = new TestAuthTOTPRoute();
            const lookup = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).userUtils = { lookup };

            const result = await (route as any).getUser("user-1");

            expect(lookup).toHaveBeenCalledWith("user-1");
            expect(result).toEqual({ uid: "user-1" });
        });
    });
});

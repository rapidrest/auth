///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthFIDO2Route — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { FIDO2Strategy } from "../../src/auth/FIDO2Strategy.js";
import { BaseAuthFIDO2Route } from "../../src/routes/BaseAuthFIDO2Route.js";
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

class TestAuthFIDO2Route extends BaseAuthFIDO2Route<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected secretClass: any = FakeSecretClass;
    protected userClass: any = FakeUserClass;
}

function makeMockObjectFactory(aliasRepo: any, secretRepo: any, userRepo: any, userUtils: any) {
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeSecretClass.name) return secretRepo;
            if (opts.name === FakeUserClass.name) return userRepo;
            return undefined;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        if (type === FIDO2Strategy) {
            return new FIDO2Strategy(opts.args[0]);
        }
        return undefined;
    });
    return { newInstance };
}

describe("BaseAuthFIDO2Route Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthFIDO2Route();
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthFIDO2Route();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate repos/utils if initialize() runs again.", async () => {
        const route = new TestAuthFIDO2Route();
        (route as any).authMiddleware = { register: vi.fn() };
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});
        const existingAliasRepo = { find: vi.fn() };
        const existingSecretRepo = { find: vi.fn() };
        const existingUserRepo = { find: vi.fn() };
        const existingUserUtils = { lookup: vi.fn() };
        (route as any).aliasRepo = existingAliasRepo;
        (route as any).secretRepo = existingSecretRepo;
        (route as any).userRepo = existingUserRepo;
        (route as any).userUtils = existingUserUtils;

        await (route as any).initialize();

        expect((route as any).aliasRepo).toBe(existingAliasRepo);
        expect((route as any).secretRepo).toBe(existingSecretRepo);
        expect((route as any).userRepo).toBe(existingUserRepo);
        expect((route as any).userUtils).toBe(existingUserUtils);
    });

    it("Registers a FIDO2Strategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthFIDO2Route();
        (route as any).authMiddleware = { register };
        (route as any)._objectFactory = makeMockObjectFactory({}, {}, {}, {});

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("fido2", expect.any(FIDO2Strategy));
    });

    describe("getCredentialById", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthFIDO2Route();
            await expect((route as any).getCredentialById("cred-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Returns undefined if no matching secret exists.", async () => {
            const route = new TestAuthFIDO2Route();
            const findOne = vi.fn().mockResolvedValue(undefined);
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(findOne).toHaveBeenCalledWith("cred-1", { ignoreACL: true });
            expect(result).toBeUndefined();
        });

        it("Returns undefined without querying the repo when credentialId is not a string (NoSQL operator injection guard).", async () => {
            const route = new TestAuthFIDO2Route();
            const findOne = vi.fn();
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById({ $ne: null });

            expect(result).toBeUndefined();
            expect(findOne).not.toHaveBeenCalled();
        });

        it("Returns the .data of a matching secret of type FIDO2.", async () => {
            const route = new TestAuthFIDO2Route();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.FIDO2, data: { id: "cred-1" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(result).toEqual({ id: "cred-1" });
        });

        // Regression: without this check, a credential id belonging to some other Secret type (e.g. a
        // `passkey` registration) would be handed to WebAuthn verification here unchecked, letting a
        // credential registered under one strategy be used to authenticate through the other.
        it("Returns undefined for a matching secret of a different type (e.g. PASSKEY).", async () => {
            const route = new TestAuthFIDO2Route();
            const findOne = vi.fn().mockResolvedValue({ type: SecretType.PASSKEY, data: { id: "cred-1" } });
            (route as any).secretRepo = { findOne };

            const result = await (route as any).getCredentialById("cred-1");

            expect(result).toBeUndefined();
        });
    });

    describe("getCredentials", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthFIDO2Route();
            (route as any).userUtils = { lookup: vi.fn() };
            await expect((route as any).getCredentials("user-1")).rejects.toThrow(/secretRepo is not set/);
        });

        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthFIDO2Route();
            (route as any).secretRepo = { find: vi.fn() };
            await expect((route as any).getCredentials("user-1")).rejects.toThrow(/userUtils is not set/);
        });

        it("Returns an empty array (not a throw) if the user cannot be found, to avoid leaking account existence.", async () => {
            const route = new TestAuthFIDO2Route();
            const find = vi.fn();
            (route as any).secretRepo = { find };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue(undefined) };

            await expect((route as any).getCredentials("unknown")).resolves.toEqual([]);
            expect(find).not.toHaveBeenCalled();
        });

        it("Returns the .data of all matching FIDO2 secrets for the user.", async () => {
            const route = new TestAuthFIDO2Route();
            const find = vi.fn().mockResolvedValue([{ data: { id: "cred-1" } }, { data: { id: "cred-2" } }]);
            (route as any).secretRepo = { find };
            (route as any).userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "user-uid-1" }) };

            const result = await (route as any).getCredentials("user-1");

            expect(find).toHaveBeenCalledWith(
                { type: SecretType.FIDO2, userUid: "user-uid-1" },
                { ignoreACL: true },
            );
            expect(result).toEqual([{ id: "cred-1" }, { id: "cred-2" }]);
        });
    });

    describe("getUser", () => {
        it("Throws if userUtils is not set.", async () => {
            const route = new TestAuthFIDO2Route();
            await expect((route as any).getUser("user-1")).rejects.toThrow(/userUtils is not set/);
        });

        it("Delegates to userUtils.lookup().", async () => {
            const route = new TestAuthFIDO2Route();
            const lookup = vi.fn().mockResolvedValue({ uid: "user-1" });
            (route as any).userUtils = { lookup };

            const result = await (route as any).getUser("user-1");

            expect(lookup).toHaveBeenCalledWith("user-1");
            expect(result).toEqual({ uid: "user-1" });
        });
    });

    describe("updateCredentialCounter", () => {
        it("Throws if secretRepo is not set.", async () => {
            const route = new TestAuthFIDO2Route();
            await expect((route as any).updateCredentialCounter("cred-1", 5)).rejects.toThrow(
                /secretRepo is not set/,
            );
        });

        it("Does nothing if no matching secret is found.", async () => {
            const route = new TestAuthFIDO2Route();
            const findOne = vi.fn().mockResolvedValue(undefined);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(update).not.toHaveBeenCalled();
        });

        it("Updates the secret's counter when a matching secret is found.", async () => {
            const route = new TestAuthFIDO2Route();
            const secret = { uid: "secret-1", version: 1, data: { id: "cred-1", counter: 1 } };
            const findOne = vi.fn().mockResolvedValue(secret);
            const update = vi.fn();
            (route as any).secretRepo = { findOne, update };

            await (route as any).updateCredentialCounter("cred-1", 5);

            expect(secret.data.counter).toBe(5);
            expect(update).toHaveBeenCalledWith(
                { uid: "secret-1", version: 1, data: secret.data },
                secret,
                { ignoreACL: true, recordEvent: false },
            );
        });
    });
});

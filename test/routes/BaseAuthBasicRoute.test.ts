///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthBasicRoute — no HTTP server, no database. ObjectFactory and
// AuthMiddleware are mocked directly so initialize() and the verify() closure it builds can be
// exercised (including their defensive "not set" guards) without a full Server/route-scan.
import { RepoUtils } from "@rapidrest/service-core";
import { BasicStrategy, BasicStrategyOptions } from "../../src/auth/BasicStrategy.js";
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
        (route as any).objectFactory = makeMockObjectFactory({}, {}).objectFactory;

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
        (route as any).objectFactory = objectFactory;
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
        (route as any).objectFactory = objectFactory;

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
            (route as any).objectFactory = objectFactory;

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

            expect(verifyDummySpy).toHaveBeenCalledWith("pass1");
        });

        it("Throws when none of the user's stored passwords match.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([{ data: await (await import("argon2")).hash("correct-password") }]);

            await expect(verify("user1", "wrong-password")).rejects.toThrow(/Invalid name or password/);
            expect(secretRepo.find).toHaveBeenCalledWith(
                { userUid: "user-uid-1", type: SecretType.PASSWORD },
                { ignoreACL: true },
            );
        });

        it("Resolves the user when at least one stored password matches.", async () => {
            const { userUtils, secretRepo, verify } = await setupRoute();
            const argon2 = await import("argon2");
            userUtils.lookup.mockResolvedValue({ uid: "user-uid-1" });
            secretRepo.find.mockResolvedValue([
                { data: await argon2.hash("another-password") },
                { data: await argon2.hash("correct-password") },
            ]);

            const user = await verify("user1", "correct-password");

            expect(user).toEqual({ uid: "user-uid-1" });
        });
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseAuthOIDCRoute — no HTTP server, no database.
import { RepoUtils } from "@rapidrest/service-core";
import { OIDCProfile, OIDCProvider, OIDCStrategy, OIDCStrategyOptions } from "../../src/auth/OIDCStrategy.js";
import { BaseAuthOIDCRoute } from "../../src/routes/BaseAuthOIDCRoute.js";
import { UserUtils } from "../../src/routes/UserUtils.js";
import { AliasType } from "../../src/models/types.js";
import { TokenUtils } from "../../src/auth/TokenUtils.js";

class FakeAliasClass {
    static readonly name = "FakeAlias";
}
class FakeProfileClass {
    static readonly name = "FakeProfile";
}
class FakeUserClass {
    static readonly name = "FakeUser";
}

const providerConfig: OIDCProvider = {
    name: "test-provider",
    authorizationURL: "https://example.com/authorize",
    clientID: "client-id",
    clientSecret: "client-secret",
};

class TestAuthOIDCRoute extends BaseAuthOIDCRoute<any, any, any> {
    protected aliasClass: any = FakeAliasClass;
    protected profileClass: any = FakeProfileClass;
    protected userClass: any = FakeUserClass;
    protected providerConfig: OIDCProvider = providerConfig;
}

function makeMockObjectFactory(aliasRepo: any, profileRepo: any, userRepo: any, userUtils: any) {
    let capturedOptions: OIDCStrategyOptions | undefined;
    const newInstance = vi.fn(async (type: any, opts: any) => {
        if (type === RepoUtils) {
            if (opts.name === FakeAliasClass.name) return aliasRepo;
            if (opts.name === FakeProfileClass.name) return profileRepo;
            if (opts.name === FakeUserClass.name) return userRepo;
            return undefined;
        }
        if (type === UserUtils) {
            return userUtils;
        }
        if (type === OIDCStrategy) {
            capturedOptions = opts.args[0];
            return new OIDCStrategy(capturedOptions);
        }
        return undefined;
    });
    return { objectFactory: { newInstance }, getOptions: () => capturedOptions };
}

describe("BaseAuthOIDCRoute Tests", () => {
    it("Throws during initialize() if authMiddleware was not injected.", async () => {
        const route = new TestAuthOIDCRoute();
        (route as any).objectFactory = makeMockObjectFactory({}, {}, {}, {}).objectFactory;

        await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
    });

    it("Throws during initialize() if objectFactory was not injected.", async () => {
        const route = new TestAuthOIDCRoute();
        (route as any).authMiddleware = { register: vi.fn() };

        await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
    });

    it("Does not recreate repos/utils if initialize() runs again.", async () => {
        const route = new TestAuthOIDCRoute();
        (route as any).authMiddleware = { register: vi.fn() };
        const { objectFactory } = makeMockObjectFactory({}, {}, {}, {});
        (route as any).objectFactory = objectFactory;
        const existingAliasRepo = { find: vi.fn() };
        const existingProfileRepo = { find: vi.fn() };
        const existingUserRepo = { find: vi.fn() };
        const existingUserUtils = { lookup: vi.fn() };
        (route as any).aliasRepo = existingAliasRepo;
        (route as any).profileRepo = existingProfileRepo;
        (route as any).userRepo = existingUserRepo;
        (route as any).userUtils = existingUserUtils;

        await (route as any).initialize();

        expect((route as any).aliasRepo).toBe(existingAliasRepo);
        expect((route as any).profileRepo).toBe(existingProfileRepo);
        expect((route as any).userRepo).toBe(existingUserRepo);
        expect((route as any).userUtils).toBe(existingUserUtils);
    });

    it("Registers an OIDCStrategy under its name once initialized.", async () => {
        const register = vi.fn();
        const route = new TestAuthOIDCRoute();
        (route as any).authMiddleware = { register };
        const { objectFactory } = makeMockObjectFactory({}, {}, {}, {});
        (route as any).objectFactory = objectFactory;

        await (route as any).initialize();

        expect(register).toHaveBeenCalledWith("oauth", expect.any(OIDCStrategy));
    });

    describe("options.getUser closure", () => {
        async function setupRoute(aliasRepo: any, profileRepo: any, userRepo: any, userUtils: any) {
            const register = vi.fn();
            const route = new TestAuthOIDCRoute();
            (route as any).authMiddleware = { register };
            const { objectFactory, getOptions } = makeMockObjectFactory(aliasRepo, profileRepo, userRepo, userUtils);
            (route as any).objectFactory = objectFactory;

            await (route as any).initialize();

            return { route, getUser: getOptions()!.getUser.bind(getOptions()) };
        }

        const baseProfile: OIDCProfile = {
            id: "provider-user-1",
            provider: "test-provider",
        };

        it("Throws if aliasRepo is not set when getUser() runs.", async () => {
            const { route, getUser } = await setupRoute({}, {}, {}, { lookup: vi.fn() });
            (route as any).aliasRepo = undefined;

            await expect(getUser("token", baseProfile)).rejects.toThrow(/aliasRepo is not set/);
        });

        it("Throws if profileRepo is not set when getUser() runs.", async () => {
            const { route, getUser } = await setupRoute({}, {}, {}, { lookup: vi.fn() });
            (route as any).profileRepo = undefined;

            await expect(getUser("token", baseProfile)).rejects.toThrow(/profileRepo is not set/);
        });

        it("Throws if userRepo is not set when getUser() runs.", async () => {
            const { route, getUser } = await setupRoute({}, {}, {}, { lookup: vi.fn() });
            (route as any).userRepo = undefined;

            await expect(getUser("token", baseProfile)).rejects.toThrow(/userRepo is not set/);
        });

        it("Throws if userUtils is not set when getUser() runs.", async () => {
            const { route, getUser } = await setupRoute({}, {}, {}, { lookup: vi.fn() });
            (route as any).userUtils = undefined;

            await expect(getUser("token", baseProfile)).rejects.toThrow(/userUtils is not set/);
        });

        it("Recognizes a returning user found via the provider-scoped oauth alias without creating a new alias.", async () => {
            const create = vi.fn();
            const userUtils = { lookup: vi.fn().mockResolvedValue({ uid: "existing-user" }) };
            const { getUser } = await setupRoute({ create }, { create: vi.fn() }, { create: vi.fn() }, userUtils);

            const user = await getUser("token", baseProfile);

            expect(userUtils.lookup).toHaveBeenCalledWith("test-provider:provider-user-1");
            expect(userUtils.lookup).toHaveBeenCalledTimes(1);
            expect(user).toEqual({ uid: "existing-user" });
            expect(create).not.toHaveBeenCalled();
        });

        it("Falls back to a verified email alias lookup, then persists the oauth alias since it wasn't found by it.", async () => {
            const aliasCreate = vi.fn();
            const lookup = vi.fn().mockResolvedValue(undefined);
            const aliasFindOne = vi.fn().mockResolvedValue({
                type: AliasType.EMAIL,
                verified: true,
                userUid: "existing-user",
            });
            const userFindOne = vi.fn().mockResolvedValue({ uid: "existing-user" });
            const { getUser } = await setupRoute(
                { create: aliasCreate, findOne: aliasFindOne },
                { create: vi.fn() },
                { create: vi.fn(), findOne: userFindOne },
                { lookup },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com", email_verified: true };

            const user = await getUser("token", profile);

            expect(lookup).toHaveBeenCalledWith("test-provider:provider-user-1");
            expect(lookup).toHaveBeenCalledTimes(1);
            expect(aliasFindOne).toHaveBeenCalledWith("user@example.com", { ignoreACL: true });
            expect(userFindOne).toHaveBeenCalledWith("existing-user", { ignoreACL: true });
            expect(user).toEqual({ uid: "existing-user" });
            expect(aliasCreate).toHaveBeenCalledWith(
                expect.objectContaining({ alias: "test-provider:provider-user-1", type: AliasType.OAUTH }),
                { ignoreACL: true },
            );
        });

        it("Falls back to a verified phone alias lookup when no email is present.", async () => {
            const aliasFindOne = vi.fn().mockResolvedValue({
                type: AliasType.PHONE,
                verified: true,
                userUid: "existing-user",
            });
            const userFindOne = vi.fn().mockResolvedValue({ uid: "existing-user" });
            const { getUser } = await setupRoute(
                { create: vi.fn(), findOne: aliasFindOne },
                { create: vi.fn() },
                { create: vi.fn(), findOne: userFindOne },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, phone: "+15551234567", phone_verified: true };

            const user = await getUser("token", profile);

            expect(aliasFindOne).toHaveBeenCalledWith("+15551234567", { ignoreACL: true });
            expect(user).toEqual({ uid: "existing-user" });
        });

        it("Does not attempt to link an existing account via an unverified email claim.", async () => {
            // The oauth-alias lookup finds no one, and the alias-lookup fallback must never even be
            // attempted since the provider didn't assert the email as verified — an attacker
            // asserting a victim's email with an unverified provider must not be able to log into the
            // victim's account.
            const lookup = vi.fn().mockResolvedValue(undefined);
            const aliasFindOne = vi.fn();
            const userRepo = { create: vi.fn().mockResolvedValue({ uid: "new-user" }) };
            const profileRepo = { create: vi.fn() };
            const aliasRepo = { create: vi.fn(), findOne: aliasFindOne };
            const { getUser } = await setupRoute(aliasRepo, profileRepo, userRepo, { lookup });
            const profile: OIDCProfile = { ...baseProfile, email: "victim@example.com", email_verified: false };

            const user = await getUser("token", profile);

            expect(aliasFindOne).not.toHaveBeenCalled();
            expect(user).toEqual({ uid: "new-user" });
            expect(userRepo.create).toHaveBeenCalled();
        });

        it("Rejects authentication when a verified email claim matches an existing but unverified local alias.", async () => {
            // The provider proved this caller owns the email, but the local alias record for that
            // same value was never itself verified — it could belong to an attacker who merely typed
            // the victim's email into their own unverified profile. Linking here would hand the real
            // owner's login to whoever registered that unverified alias first.
            const aliasFindOne = vi.fn().mockResolvedValue({
                type: AliasType.EMAIL,
                verified: false,
                userUid: "someone-else",
            });
            const userFindOne = vi.fn();
            const { getUser } = await setupRoute(
                { create: vi.fn(), findOne: aliasFindOne },
                { create: vi.fn() },
                { create: vi.fn(), findOne: userFindOne },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com", email_verified: true };

            await expect(getUser("token", profile)).rejects.toThrow(/has not been verified/);
            expect(userFindOne).not.toHaveBeenCalled();
        });

        it("Rejects authentication when a verified email claim collides with a same-valued alias of a different type.", async () => {
            // `alias` values are globally unique regardless of type, so a verified email claim could
            // in principle collide with a `name` (or other) alias holding the same string. That must
            // never be trusted for linking, verified or not.
            const aliasFindOne = vi.fn().mockResolvedValue({
                type: AliasType.NAME,
                verified: true,
                userUid: "someone-else",
            });
            const { getUser } = await setupRoute(
                { create: vi.fn(), findOne: aliasFindOne },
                { create: vi.fn() },
                { create: vi.fn(), findOne: vi.fn() },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com", email_verified: true };

            await expect(getUser("token", profile)).rejects.toThrow(/has not been verified/);
        });

        it("Creates a new account when no verified email/phone is present, without attempting any alias-value lookup.", async () => {
            const lookup = vi.fn().mockResolvedValue(undefined);
            const aliasFindOne = vi.fn();
            const userRepo = { create: vi.fn().mockResolvedValue({ uid: "new-user" }) };
            const profileRepo = { create: vi.fn() };
            const aliasRepo = { create: vi.fn(), findOne: aliasFindOne };
            const { getUser } = await setupRoute(aliasRepo, profileRepo, userRepo, { lookup });

            const user = await getUser("token", baseProfile);

            expect(aliasFindOne).not.toHaveBeenCalled();
            expect(user).toEqual({ uid: "new-user" });
        });

        it("Creates a new user and minimal profile when no existing user is found.", async () => {
            const userRepo = { create: vi.fn().mockResolvedValue({ uid: "new-user" }) };
            const profileRepo = { create: vi.fn() };
            const aliasRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(aliasRepo, profileRepo, userRepo, {
                lookup: vi.fn().mockResolvedValue(undefined),
            });

            const user = await getUser("token", baseProfile);

            expect(user).toEqual({ uid: "new-user" });
            expect(userRepo.create).toHaveBeenCalledWith(expect.objectContaining({ roles: [], scopes: [] }), {
                ignoreACL: true,
            });
            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({ avatar: "", givenName: "", familyName: "", uid: "new-user", contacts: [] }),
                { ignoreACL: true },
            );
            // Only the oauth alias should be created — no email/phone were provided.
            expect(aliasRepo.create).toHaveBeenCalledTimes(1);
            expect(aliasRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({ type: AliasType.OAUTH }),
                { ignoreACL: true },
            );
        });

        it("Uses profile avatar/birthdate/givenName/familyName when provided.", async () => {
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                { create: vi.fn() },
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = {
                ...baseProfile,
                avatar: "https://example.com/avatar.png",
                birthdate: "1990-01-01",
                givenName: "Jane",
                familyName: "Doe",
            };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    avatar: "https://example.com/avatar.png",
                    birthdate: new Date("1990-01-01"),
                    givenName: "Jane",
                    familyName: "Doe",
                }),
                { ignoreACL: true },
            );
        });

        it("Adds a verified email contact and email alias when the provider verifies the email.", async () => {
            const aliasRepo = { create: vi.fn(), findOne: vi.fn().mockResolvedValue(undefined) };
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                aliasRepo,
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com", email_verified: true };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "user@example.com", type: "email", verified: true }],
                }),
                { ignoreACL: true },
            );
            // Both the email alias and the oauth alias should have been created.
            expect(aliasRepo.create).toHaveBeenCalledTimes(2);
            expect(aliasRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({ alias: "user@example.com", type: AliasType.EMAIL, verified: true }),
                { ignoreACL: true },
            );
        });

        it("Adds an unverified email contact but does not create an email alias when unverified.", async () => {
            const aliasRepo = { create: vi.fn() };
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                aliasRepo,
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com", email_verified: false };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "user@example.com", type: "email", verified: false }],
                }),
                { ignoreACL: true },
            );
            // Only the oauth alias should have been created — no email alias since unverified.
            expect(aliasRepo.create).toHaveBeenCalledTimes(1);
        });

        it("Defaults an omitted email_verified to false on the profile contact.", async () => {
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                { create: vi.fn() },
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, email: "user@example.com" };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "user@example.com", type: "email", verified: false }],
                }),
                { ignoreACL: true },
            );
        });

        it("Defaults an omitted phone_verified to false on the profile contact.", async () => {
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                { create: vi.fn() },
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, phone: "+15551234567" };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "+15551234567", type: "phone", verified: false }],
                }),
                { ignoreACL: true },
            );
        });

        it("Adds a verified phone contact and phone alias when the provider verifies the phone.", async () => {
            const aliasRepo = { create: vi.fn(), findOne: vi.fn().mockResolvedValue(undefined) };
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                aliasRepo,
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, phone: "+15551234567", phone_verified: true };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "+15551234567", type: "phone", verified: true }],
                }),
                { ignoreACL: true },
            );
            expect(aliasRepo.create).toHaveBeenCalledTimes(2);
            expect(aliasRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({ alias: "+15551234567", type: AliasType.PHONE, verified: true }),
                { ignoreACL: true },
            );
        });

        it("Adds an unverified phone contact but does not create a phone alias when unverified.", async () => {
            const aliasRepo = { create: vi.fn() };
            const profileRepo = { create: vi.fn() };
            const { getUser } = await setupRoute(
                aliasRepo,
                profileRepo,
                { create: vi.fn().mockResolvedValue({ uid: "new-user" }) },
                { lookup: vi.fn().mockResolvedValue(undefined) },
            );
            const profile: OIDCProfile = { ...baseProfile, phone: "+15551234567", phone_verified: false };

            await getUser("token", profile);

            expect(profileRepo.create).toHaveBeenCalledWith(
                expect.objectContaining({
                    contacts: [{ contact: "+15551234567", type: "phone", verified: false }],
                }),
                { ignoreACL: true },
            );
            // Only the oauth alias should have been created — no phone alias since unverified.
            expect(aliasRepo.create).toHaveBeenCalledTimes(1);
        });
    });

    describe("login", () => {
        it("Returns an AuthResult containing a signed JWT for the authenticated user.", async () => {
            const route = new TestAuthOIDCRoute();
            (route as any).jwtConfig = { secret: "test-secret" };
            (route as any).tokenUtils = new TokenUtils();
            const res = { setHeader: vi.fn() } as any;

            const result = await route.login({ uid: "user-1" } as any, res);

            expect(result?.user).toEqual({ uid: "user-1" });
            expect(typeof result?.token).toBe("string");
            // Cookie issuance is disabled by default (`auth:cookie.enabled` defaults to `false`).
            expect(res.setHeader).not.toHaveBeenCalled();
        });

        it("Sets a `Set-Cookie` header when cookie issuance is enabled.", async () => {
            const route = new TestAuthOIDCRoute();
            (route as any).jwtConfig = { secret: "test-secret" };
            const tokenUtils = new TokenUtils();
            (tokenUtils as any).cookieConfig = { enabled: true };
            (route as any).tokenUtils = tokenUtils;
            const res = { setHeader: vi.fn() } as any;

            const result = await route.login({ uid: "user-1" } as any, res);

            expect(res.setHeader).toHaveBeenCalledWith("Set-Cookie", expect.stringContaining(`jwt=${result?.token}`));
        });
    });
});

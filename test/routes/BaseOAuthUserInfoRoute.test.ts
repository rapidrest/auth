///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Isolated unit tests for BaseOAuthUserInfoRoute — no HTTP server, no database.
import { JWTUser } from "@rapidrest/core";
import { RepoUtils } from "@rapidrest/service-core";
import { BaseOAuthUserInfoRoute } from "../../src/routes/BaseOAuthUserInfoRoute.js";
import { AccessTokenDenylist } from "../../src/auth/AccessTokenDenylist.js";
import { OAuthBearerStrategy } from "../../src/auth/OAuthBearerStrategy.js";
import { OAuthTokenUtils } from "../../src/auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../../src/auth/SigningKeyUtils.js";
import { ContactType, Profile } from "../../src/models/types.js";

class FakeProfileClass {
    static readonly name = "FakeProfile";
}
class FakeSigningKeyClass {
    static readonly name = "FakeSigningKey";
}

class TestOAuthUserInfoRoute extends BaseOAuthUserInfoRoute<any> {
    protected profileClass: any = FakeProfileClass;
    protected signingKeyClass: any = FakeSigningKeyClass;
}

function makeMockRepo<T>() {
    const store = new Map<string, T>();
    return {
        create: vi.fn(async (obj: Partial<T>) => obj),
        find: vi.fn(async () => []),
        findOne: vi.fn(async (id: string) => store.get(id)),
        update: vi.fn(async (obj: Partial<T>, existing: T) => ({ ...existing, ...obj })),
        _store: store,
    };
}

function makeProfile(overrides: Partial<Profile> = {}): Profile {
    return {
        uid: "user-1",
        dateCreated: new Date(),
        dateModified: new Date(),
        version: 0,
        contacts: [],
        preferences: { contact: ["all"] },
        ...overrides,
    };
}

function makeRoute() {
    const profileRepo = makeMockRepo<Profile>();
    const authMiddleware = { register: vi.fn() };

    const route = new TestOAuthUserInfoRoute();
    (route as any)._objectFactory = {
        newInstance: vi.fn(async (type: any, opts: any) => {
            if (type === RepoUtils) {
                if (opts.name === FakeProfileClass.name) return profileRepo;
                if (opts.name === FakeSigningKeyClass.name) return makeMockRepo<any>();
            }
            if (type === SigningKeyUtils) return {};
            if (type === OAuthTokenUtils) return {};
            if (type === AccessTokenDenylist) return {};
            if (type === OAuthBearerStrategy) return { name: opts.name };
            return undefined;
        }),
    };
    (route as any).authMiddleware = authMiddleware;
    (route as any).profileRepo = profileRepo;

    return { route, profileRepo, authMiddleware };
}

function makeUser(overrides: Partial<JWTUser> = {}): JWTUser {
    return { uid: "user-1", roles: [], scopes: ["openid"], ...overrides };
}

describe("BaseOAuthUserInfoRoute Tests", () => {
    describe("initialize", () => {
        it("Throws if authMiddleware was not injected.", async () => {
            const route = new TestOAuthUserInfoRoute();
            (route as any)._objectFactory = { newInstance: vi.fn() };
            await expect((route as any).initialize()).rejects.toThrow(/authMiddleware is not set/);
        });

        it("Throws if objectFactory was not set.", async () => {
            const route = new TestOAuthUserInfoRoute();
            (route as any).authMiddleware = { register: vi.fn() };
            await expect((route as any).initialize()).rejects.toThrow(/objectFactory is not set/);
        });

        it("Builds profileRepo/oauthTokenUtils and registers the oauth_bearer strategy via the object factory.", async () => {
            const profileRepo = makeMockRepo<Profile>();
            const signingKeyRepo = makeMockRepo<any>();
            const signingKeyUtils = {};
            const oauthTokenUtils = {};
            const accessTokenDenylist = {};
            const authMiddleware = { register: vi.fn() };

            const route = new TestOAuthUserInfoRoute();
            (route as any).authMiddleware = authMiddleware;
            (route as any)._objectFactory = {
                newInstance: vi.fn(async (type: any, opts: any) => {
                    if (type === RepoUtils) {
                        if (opts.name === FakeProfileClass.name) return profileRepo;
                        if (opts.name === FakeSigningKeyClass.name) return signingKeyRepo;
                    }
                    if (type === SigningKeyUtils) return signingKeyUtils;
                    if (type === OAuthTokenUtils) return oauthTokenUtils;
                    if (type === AccessTokenDenylist) return accessTokenDenylist;
                    if (type === OAuthBearerStrategy) return { name: opts.name };
                    return undefined;
                }),
            };

            await (route as any).initialize();

            expect((route as any).profileRepo).toBe(profileRepo);
            expect((route as any).oauthTokenUtils).toBe(oauthTokenUtils);
            expect(authMiddleware.register).toHaveBeenCalledWith("oauth_bearer", { name: "oauth_bearer" });
        });

        it("Does not recreate profileRepo/oauthTokenUtils if initialize() runs again.", async () => {
            const { route, profileRepo } = makeRoute();
            (route as any).oauthTokenUtils = {};

            await (route as any).initialize();

            expect((route as any).profileRepo).toBe(profileRepo);
        });
    });

    describe("userinfo", () => {
        it("Returns only sub when no profile/email/phone scope was granted.", async () => {
            const { route, profileRepo } = makeRoute();
            const result = await route.userinfo(makeUser({ scopes: ["openid"] }));
            expect(result).toEqual({ sub: "user-1" });
            expect(profileRepo.findOne).not.toHaveBeenCalled();
        });

        it("Returns only sub when the profile scope is granted but no Profile record exists.", async () => {
            const { route } = makeRoute();
            const result = await route.userinfo(makeUser({ scopes: ["openid", "profile"] }));
            expect(result).toEqual({ sub: "user-1" });
        });

        // Regression: `Profile.contacts`/`Profile.preferences` are individually gated by
        // `@RequiresScope("profile:contacts"/"profile:preferences")`, a field-level mechanism
        // `RepoUtils.findOne()` applies based on `options.user.scopes` regardless of `ignoreACL`. Without
        // explicitly granting those (unrelated, internal) scopes here, `findOne()` would silently strip
        // `contacts` from the real result, and `buildEmailClaims`/`buildPhoneClaims` calling `.find()` on
        // the now-`undefined` field would throw — a real 500 this mock-repo assertion is here to prevent
        // from silently regressing, since a naive mock `findOne()` that ignores its `options` argument
        // entirely (like this file's own `makeMockRepo()`) can't otherwise catch it.
        it("Requests the Profile with scopes that bypass the unrelated internal field-level ACL gate.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set("user-1", makeProfile());

            await route.userinfo(makeUser({ scopes: ["openid", "profile"] }));

            expect(profileRepo.findOne).toHaveBeenCalledWith("user-1", {
                ignoreACL: true,
                user: { uid: "user-1", roles: [], scopes: ["profile:contacts", "profile:preferences"] },
            });
        });

        it("Includes given_name/family_name/name/birthdate/picture for the profile scope.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set(
                "user-1",
                makeProfile({ givenName: "Ada", familyName: "Lovelace", birthdate: new Date("1815-12-10"), avatar: "https://example.com/a.png" }),
            );

            const result = await route.userinfo(makeUser({ scopes: ["openid", "profile"] }));

            expect(result).toEqual({
                sub: "user-1",
                given_name: "Ada",
                family_name: "Lovelace",
                name: "Ada Lovelace",
                birthdate: "1815-12-10",
                picture: "https://example.com/a.png",
            });
        });

        it("Omits given_name/family_name/name individually when the Profile has neither.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set("user-1", makeProfile());

            const result = await route.userinfo(makeUser({ scopes: ["openid", "profile"] }));

            expect(result).toEqual({ sub: "user-1" });
        });

        it("Builds name from givenName alone when familyName is absent.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set("user-1", makeProfile({ givenName: "Ada" }));

            const result = await route.userinfo(makeUser({ scopes: ["openid", "profile"] }));

            expect(result.name).toBe("Ada");
            expect(result.given_name).toBe("Ada");
            expect(result.family_name).toBeUndefined();
        });

        it("Includes email/email_verified for the email scope from the first EMAIL contact.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set(
                "user-1",
                makeProfile({ contacts: [{ contact: "ada@example.com", type: ContactType.EMAIL, verified: true }] }),
            );

            const result = await route.userinfo(makeUser({ scopes: ["openid", "email"] }));

            expect(result).toEqual({ sub: "user-1", email: "ada@example.com", email_verified: true });
        });

        it("Omits email claims when the Profile has no EMAIL contact.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set("user-1", makeProfile({ contacts: [{ contact: "555-1234", type: ContactType.PHONE, verified: false }] }));

            const result = await route.userinfo(makeUser({ scopes: ["openid", "email"] }));

            expect(result).toEqual({ sub: "user-1" });
        });

        it("Includes phone_number/phone_number_verified for the phone scope from the first PHONE contact.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set(
                "user-1",
                makeProfile({ contacts: [{ contact: "555-1234", type: ContactType.PHONE, verified: false }] }),
            );

            const result = await route.userinfo(makeUser({ scopes: ["openid", "phone"] }));

            expect(result).toEqual({ sub: "user-1", phone_number: "555-1234", phone_number_verified: false });
        });

        it("Omits phone claims when the Profile has no PHONE contact.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set("user-1", makeProfile({ contacts: [{ contact: "ada@example.com", type: ContactType.EMAIL, verified: true }] }));

            const result = await route.userinfo(makeUser({ scopes: ["openid", "phone"] }));

            expect(result).toEqual({ sub: "user-1" });
        });

        it("Combines every granted claim group in a single response.", async () => {
            const { route, profileRepo } = makeRoute();
            profileRepo._store.set(
                "user-1",
                makeProfile({
                    givenName: "Ada",
                    familyName: "Lovelace",
                    contacts: [
                        { contact: "ada@example.com", type: ContactType.EMAIL, verified: true },
                        { contact: "555-1234", type: ContactType.PHONE, verified: false },
                    ],
                }),
            );

            const result = await route.userinfo(makeUser({ scopes: ["openid", "profile", "email", "phone"] }));

            expect(result).toEqual({
                sub: "user-1",
                given_name: "Ada",
                family_name: "Lovelace",
                name: "Ada Lovelace",
                email: "ada@example.com",
                email_verified: true,
                phone_number: "555-1234",
                phone_number_verified: false,
            });
        });
    });
});

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { JWTUser, ObjectDecorators } from "@rapidrest/core";
import { AuthMiddleware, DocDecorators, ObjectFactory, RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { ContactType, Profile, SigningKey } from "../models/types.js";
import { AccessTokenDenylist } from "../auth/AccessTokenDenylist.js";
import { OAuthBearerStrategy } from "../auth/OAuthBearerStrategy.js";
import { OAuthTokenUtils } from "../auth/OAuthTokenUtils.js";
import { SigningKeyUtils } from "../auth/SigningKeyUtils.js";

const { Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, RequiresScope } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/** The fixed name `OAuthBearerStrategy` registers under — there is only ever one flavor of access token
 * this authorization server issues, so (unlike `BaseAuthOIDCRoute`'s multi-provider `strategyName`) this
 * never needs to vary per subclass. */
const STRATEGY_NAME = "oauth_bearer";

/**
 * Handles the OIDC `/userinfo` endpoint (OIDC Core §5.3). Authenticates via the OAuth access token itself
 * (`Authorization: Bearer <token>`, through `OAuthBearerStrategy` — registered here under the fixed name
 * `"oauth_bearer"`), not this library's own relying-party `@Auth(["jwt"])`/ACL model: a third-party OAuth
 * client presenting a resource owner's access token isn't an ACL-scoped "user" of this app, it's a
 * delegated caller entitled only to whatever claims the resource owner consented to share (the token's own
 * `scope`).
 *
 * `sub` is always present once `openid` scope is confirmed (enforced by `@RequiresScope(["openid"])`) —
 * every other claim is additive per OIDC Core §5.4's `profile`/`email`/`phone` claim groups. Deliberately
 * does not fetch the underlying `User` record: `sub`/`scope` already came from the verified token itself, so
 * only `Profile` (the source of every optional claim) is ever read, via the same `RepoUtils<Profile>` fetch
 * pattern used everywhere else in this library.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthUserInfoRoute<P extends Profile> {
    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    protected oauthTokenUtils?: OAuthTokenUtils;

    protected abstract profileClass: any;

    protected profileRepo?: RepoUtils<P>;

    protected abstract signingKeyClass: any;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize(): Promise<void> {
        if (!this.authMiddleware) {
            throw new Error("authMiddleware is not set.");
        }
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.profileRepo && this.profileClass) {
            this.profileRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }

        if (!this.oauthTokenUtils && this.signingKeyClass) {
            const signingKeyRepo: RepoUtils<SigningKey> = await this._objectFactory.newInstance(RepoUtils, {
                name: this.signingKeyClass.name,
                args: [this.signingKeyClass],
            });
            const signingKeyUtils: SigningKeyUtils = await this._objectFactory.newInstance(SigningKeyUtils, {
                name: "default",
                args: [signingKeyRepo],
            });
            this.oauthTokenUtils = await this._objectFactory.newInstance(OAuthTokenUtils, {
                name: "default",
                args: [signingKeyUtils],
            });
        }

        const accessTokenDenylist: AccessTokenDenylist = await this._objectFactory.newInstance(AccessTokenDenylist, {
            name: "default",
        });
        const strategy: OAuthBearerStrategy = await this._objectFactory.newInstance(OAuthBearerStrategy, {
            name: STRATEGY_NAME,
            args: [STRATEGY_NAME, this.oauthTokenUtils, accessTokenDenylist],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /** Maps `profile` scope claims (OIDC Core §5.4) from the given `Profile`. */
    private buildProfileClaims(profile: P): Record<string, any> {
        const claims: Record<string, any> = {};

        if (profile.givenName) {
            claims.given_name = profile.givenName;
        }
        if (profile.familyName) {
            claims.family_name = profile.familyName;
        }
        if (profile.givenName || profile.familyName) {
            claims.name = [profile.givenName, profile.familyName].filter(Boolean).join(" ");
        }
        if (profile.birthdate) {
            claims.birthdate = new Date(profile.birthdate).toISOString().slice(0, 10);
        }
        if (profile.avatar) {
            claims.picture = profile.avatar;
        }

        return claims;
    }

    /** Maps `email` scope claims (OIDC Core §5.4) from the given `Profile`'s first email `Contact`. */
    private buildEmailClaims(profile: P): Record<string, any> {
        const contact = profile.contacts.find((c) => c.type === ContactType.EMAIL);
        return contact ? { email: contact.contact, email_verified: contact.verified } : {};
    }

    /** Maps `phone` scope claims (OIDC Core §5.4) from the given `Profile`'s first phone `Contact`. */
    private buildPhoneClaims(profile: P): Record<string, any> {
        const contact = profile.contacts.find((c) => c.type === ContactType.PHONE);
        return contact ? { phone_number: contact.contact, phone_number_verified: contact.verified } : {};
    }

    /**
     * Returns claims about the authenticated resource owner, gated by the scope granted to the presented
     * access token. `sub` is always present; `profile`/`email`/`phone` scopes each add their own claim
     * group (OIDC Core §5.4), read from the owner's `Profile` — absent entirely if no such scope was
     * granted, or if the `Profile` carries nothing for that group.
     */
    @Summary("OIDC UserInfo")
    @Description(
        "Returns claims about the resource owner identified by the presented access token, gated by its " +
            "granted scope (OIDC Core §5.3).",
    )
    @Returns([Object])
    @Auth([STRATEGY_NAME])
    @RequiresScope(["openid"])
    @Get()
    @Post()
    public async userinfo(@AuthUser user: JWTUser): Promise<any> {
        const claims: Record<string, any> = { sub: user.uid };
        const scope = user.scopes;

        if (scope.includes("profile") || scope.includes("email") || scope.includes("phone")) {
            // `Profile.contacts`/`Profile.preferences` (see `ProfileMongo`/`ProfileSQL`) are individually
            // gated by `@RequiresScope("profile:contacts"/"profile:preferences")` — a field-level mechanism
            // `RepoUtils.findOne()` always applies based on `options.user.scopes`, entirely independent of
            // `ignoreACL`. Those internal app scopes have nothing to do with the OIDC `profile`/`email`/
            // `phone` scopes checked above (this token was never issued `options.user.scopes` in that
            // vocabulary at all), so without this, `contacts` would silently come back stripped
            // (`undefined`) for every access token — the actual OIDC-scope gate below is what decides what
            // this response reveals, so this read is deliberately granted full access to bypass the
            // unrelated, inapplicable field gate rather than be silently defeated by it.
            const profile: P | undefined = await this.profileRepo!.findOne(user.uid, {
                ignoreACL: true,
                user: { uid: user.uid, roles: [], scopes: ["profile:contacts", "profile:preferences"] },
            });
            if (profile) {
                if (scope.includes("profile")) {
                    Object.assign(claims, this.buildProfileClaims(profile));
                }
                if (scope.includes("email")) {
                    Object.assign(claims, this.buildEmailClaims(profile));
                }
                if (scope.includes("phone")) {
                    Object.assign(claims, this.buildPhoneClaims(profile));
                }
            }
        }

        return claims;
    }
}

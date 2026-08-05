///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { JWTUser, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import {
    RouteDecorators,
    DocDecorators,
    HttpResponse,
    RepoUtils,
    AuthMiddleware,
    ObjectFactory,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, ContactType, Profile, User } from "../models/types.js";
import { OIDCProfile, OIDCProvider, OIDCStrategy, OIDCStrategyOptions } from "../auth/OIDCStrategy.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import * as uuid from "uuid";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 *
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthOIDCRoute<U extends User, A extends Alias, P extends Profile> {
    protected abstract aliasClass: any;
    protected abstract profileClass: any;
    protected abstract userClass: any;

    protected aliasRepo?: RepoUtils<A>;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected jwtConfig?: any;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    protected profileRepo?: RepoUtils<P>;

    protected abstract providerConfig: OIDCProvider;

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    protected userRepo?: RepoUtils<U>;

    protected userUtils?: UserUtils<U, A>;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    private async initialize() {
        if (!this.authMiddleware) {
            throw new Error("authMiddleware is not set.");
        }
        if (!this.objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.profileRepo && this.profileClass) {
            this.profileRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }

        if (!this.userUtils && this.userClass && this.aliasClass) {
            this.userUtils = await this.objectFactory.newInstance(UserUtils, {
                name: "default",
                args: [this.userClass, this.aliasClass],
            });
        }

        const options: OIDCStrategyOptions = new OIDCStrategyOptions("oauth", this.providerConfig);
        options.getUser = async (token: string, profile: OIDCProfile): Promise<JWTUser | undefined> => {
            if (!this.aliasRepo) {
                throw new Error("aliasRepo is not set.");
            }
            if (!this.profileRepo) {
                throw new Error("profileRepo is not set.");
            }
            if (!this.userRepo) {
                throw new Error("userRepo is not set.");
            }
            if (!this.userUtils) {
                throw new Error("userUtils is not set.");
            }

            // The provider-scoped external id (`<provider>:<id>`) is the most reliable way to recognize
            // a returning user across logins — unlike email, it doesn't depend on the provider actually
            // returning a (verified) email address, it can't collide with another provider's namespace,
            // and it can't change if the user updates their email with the provider.
            const oauthAlias: string = `${profile.provider}:${profile.id}`;

            let user: U | undefined = await this.userUtils.lookup(oauthAlias);
            const foundByOAuthAlias: boolean = user !== undefined;

            // Fall back to the (verified) email alias — this recognizes an account that either
            // registered before this provider-id lookup existed, or was created via another method
            // (e.g. password) and is now authenticating with this provider for the first time. Only
            // trust the provider's email claim for this when it's actually asserted as verified —
            // otherwise any provider that lets a user set an arbitrary, unverified email would let an
            // attacker log into the account owning that email.
            if (!user && profile.email && profile.email_verified) {
                user = await this.userUtils.lookup(profile.email);
            }

            // Fall back to the provider-scoped profile id, which is safe to trust regardless of email
            // verification since it's not attacker-choosable.
            if (!user) {
                user = await this.userUtils.lookup(profile.id);
            }

            if (!user) {
                // Create a new user for the given profile
                const newUser: User = {
                    uid: uuid.v4(),
                    dateCreated: new Date(),
                    dateModified: new Date(),
                    version: 0,
                    roles: [],
                    scopes: [],
                };
                user = await this.userRepo.create(newUser as U, { ignoreACL: true });

                // Now create a profile for the user
                const newProfile: Profile = {
                    avatar: profile.avatar ?? "",
                    birthdate: profile.birthdate ? new Date(profile.birthdate) : undefined,
                    contacts: [],
                    givenName: profile.givenName ?? "",
                    familyName: profile.familyName ?? "",
                    preferences: {
                        contact: [],
                    },
                    uid: user.uid,
                    dateCreated: new Date(),
                    dateModified: new Date(),
                    version: 0,
                };
                if (profile.email) {
                    newProfile.contacts.push({
                        contact: profile.email,
                        type: ContactType.EMAIL,
                        verified: profile.email_verified ?? false,
                    });
                }
                if (profile.email && profile.email_verified) {
                    const newAlias: Alias = {
                        alias: profile.email,
                        type: AliasType.EMAIL,
                        userUid: user.uid,
                        verified: true,
                        uid: uuid.v4(),
                        dateCreated: new Date(),
                        dateModified: new Date(),
                        version: 0,
                    };
                    await this.aliasRepo.create(newAlias as A, { ignoreACL: true });
                }
                if (profile.phone) {
                    newProfile.contacts.push({
                        contact: profile.phone,
                        type: ContactType.PHONE,
                        verified: profile.phone_verified ?? false,
                    });
                }
                if (profile.phone && profile.phone_verified) {
                    const newAlias: Alias = {
                        alias: profile.phone,
                        type: AliasType.PHONE,
                        userUid: user.uid,
                        verified: true,
                        uid: uuid.v4(),
                        dateCreated: new Date(),
                        dateModified: new Date(),
                        version: 0,
                    };
                    await this.aliasRepo.create(newAlias as A, { ignoreACL: true });
                }
                await this.profileRepo.create(newProfile as P, { ignoreACL: true });
            }

            // Persist the provider-scoped alias so this user is recognized by it on future logins,
            // regardless of how they were resolved above. Skipped when that's exactly how `user` was
            // just found, since the alias is already there.
            if (!foundByOAuthAlias) {
                const newOAuthAlias: Alias = {
                    alias: oauthAlias,
                    type: AliasType.OAUTH,
                    userUid: user.uid,
                    verified: true,
                    uid: uuid.v4(),
                    dateCreated: new Date(),
                    dateModified: new Date(),
                    version: 0,
                };
                await this.aliasRepo.create(newOAuthAlias as A, { ignoreACL: true });
            }

            return user;
        };
        const strategy: OIDCStrategy = await this.objectFactory.newInstance(OIDCStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using OIDC and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Login OIDC")
    @Description(
        "Authenticates the user using OAuth 2.0 / OpenID Connect and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["oauth"])
    @Get()
    @Post()
    public async login(@AuthUser user: JWTUser, @Response res: HttpResponse): Promise<AuthResult | undefined> {
        const token: string = await this.tokenUtils!.createToken(this.jwtConfig, user, this.defaultScopes, res);
        return new AuthResult({
            token,
            user,
        });
    }
}

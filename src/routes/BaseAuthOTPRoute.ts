///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import {
    RouteDecorators,
    DocDecorators,
    HttpResponse,
    RepoUtils,
    AuthMiddleware,
    ObjectFactory,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, Secret, User } from "../models/types.js";
import { OTPStrategy, OTPStrategyOptions } from "../auth/OTPStrategy.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { OTPContact, OTPContactType } from "../auth/types.js";
import { TokenUtils } from "../auth/TokenUtils.js";
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
export abstract class BaseAuthOTPRoute<U extends User, A extends Alias, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
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

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected secretRepo?: RepoUtils<S>;

    /** The name of the messaging template to use for sending notifications. */
    protected template: string = "login-otp";

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    protected userRepo?: RepoUtils<U>;

    protected userUtils?: UserUtils<U, A>;

    /**
     * Called on server startup to initialize the route with any defaults.
     */
    @Init
    protected async initialize() {
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

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
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

        const options: OTPStrategyOptions = new OTPStrategyOptions();
        options.checkRateLimit = (identifier: string) => this.rateLimiter!.checkAndIncrement(identifier);
        options.getContact = this.getContact.bind(this);
        options.getContacts = this.getContacts.bind(this);
        options.getUser = this.getUser.bind(this);
        options.notifyContact = this.notifyContact.bind(this);
        const strategy: OTPStrategy = await this.objectFactory.newInstance(OTPStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using OTP and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Authenticate OTP")
    @Description(
        "Authenticates the user using TOTP and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["otp"])
    @Get()
    @Post()
    public async authenticate(
        @AuthUser user: JWTUser,
        @Response res: HttpResponse,
    ): Promise<AuthResult | undefined> {
        const token: string = await this.tokenUtils!.createToken(this.jwtConfig, user, this.defaultScopes, res);
        return new AuthResult({
            token,
            user,
        });
    }

    protected convertAliasType(type: AliasType): OTPContactType {
        switch (type) {
            case AliasType.EMAIL:
                return OTPContactType.EMAIL;
            case AliasType.PHONE:
                return OTPContactType.SMS;
            default:
                throw new Error("Unsupported type: " + type);
        }
    }

    /**
     * Retrieves the alias with the given unique id.
     * @param id The unique id of the alias to retrieve.
     * @returns The alias if found, otherwise `undefined`.
     */
    protected async getContact(id: string): Promise<OTPContact | undefined> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (typeof id !== "string") {
            return undefined;
        }
        const alias: Alias | undefined = await this.aliasRepo.findOne(id, { ignoreACL: true });

        return alias
            ? {
                  contact: alias.alias,
                  type: this.convertAliasType(alias.type),
                  verified: alias.verified,
              }
            : undefined;
    }

    /**
     * Retrieves all aliases for the user with the given id.
     *
     * @param id The unique id of the user to lookup.
     */
    protected async getContacts(id: string): Promise<OTPContact[]> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.userRepo) {
            throw new Error("userRepo is not set.");
        }
        if (typeof id !== "string") {
            return [];
        }

        // The provided id may be the user's uid or an alias itself. First attempt to retrieve a user
        // and if found use that id. Otherwise, try looking up the alias itself. Once at least one alias
        // is found we can use it to look-up all others for a given userUid.
        let user: U | undefined = await this.userRepo.findOne(id, { ignoreACL: true });
        let aliases: A[] = await this.aliasRepo.find(user ? { userUid: user.uid } : { alias: id }, {
            ignoreACL: true,
        });
        if (!user && aliases.length > 0) {
            aliases = await this.aliasRepo.find({ userUid: aliases[0].userUid }, { ignoreACL: true });
            user = aliases.length > 0 ? await this.userRepo.findOne(aliases[0].userUid) : undefined;
        }

        // Filter aliases to only those that can be notified
        aliases.filter((alias) => [AliasType.EMAIL, AliasType.PHONE].includes(alias.type));

        const results: OTPContact[] = [];
        for (const alias of aliases) {
            results.push({
                contact: alias.alias,
                type: this.convertAliasType(alias.type),
                verified: alias.verified,
            });
        }

        return results;
    }

    /**
     * Retrieves the user with the given unique id.
     * @param uid The unique id of the user to retrieve.
     * @returns The user if found, otherwise `undefined`.
     */
    protected async getUser(uid: string): Promise<JWTUser | undefined> {
        if (!this.userUtils) {
            throw new Error("userUtils is not set.");
        }
        return this.userUtils.lookup(uid);
    }

    protected async notifyContact(contact: OTPContact, totp: string): Promise<void> {
        switch (contact.type) {
            case OTPContactType.EMAIL:
                void this.messagingUtils?.sendEmail(
                    this.template,
                    { totp },
                    {
                        to: contact.contact,
                    },
                );
                break;
            case OTPContactType.SMS:
                void this.messagingUtils?.sendSMS(
                    this.template,
                    { totp },
                    {
                        to: contact.contact,
                    },
                );
                break;
        }
    }
}

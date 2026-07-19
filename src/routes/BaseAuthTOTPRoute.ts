///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, JWTUtils, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import { RouteDecorators, DocDecorators, RepoUtils, AuthMiddleware, ObjectFactory } from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { TOTPStrategy, TOTPStrategyOptions } from "../auth/TOTPStrategy.js";
import { TOTPSecret } from "../auth/types.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 *
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthTOTPRoute<U extends User, A extends Alias, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth")
    protected jwtConfig?: any;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    protected secretRepo?: RepoUtils<S>;

    /** The name of the messaging template to use for sending notifications. */
    protected template: string = "login-otp";

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

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userUtils && this.userClass && this.aliasClass) {
            this.userUtils = await this.objectFactory.newInstance(UserUtils, {
                name: "default",
                args: [this.userClass, this.aliasClass],
            });
        }

        const options: TOTPStrategyOptions = new TOTPStrategyOptions();
        options.getSecrets = this.getSecrets.bind(this);
        options.getUser = this.getUser.bind(this);
        const strategy: TOTPStrategy = await this.objectFactory.newInstance(TOTPStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using TOTP and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Authenticate TOTP")
    @Description(
        "Authenticates the user using TTOTP and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["totp"])
    @Get()
    @Post()
    public async authenticate(@AuthUser user: JWTUser): Promise<AuthResult | undefined> {
        const token: string = await JWTUtils.createToken(this.jwtConfig, user);
        return new AuthResult({
            token,
            user,
        });
    }

    protected async getSecrets(uid: string): Promise<TOTPSecret[]> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }

        const results: TOTPSecret[] = [];
        const secrets: Secret[] = await this.secretRepo.find(
            { type: SecretType.TOTP, userUid: uid },
            { ignoreACL: true },
        );

        for (const secret of secrets) {
            results.push(secret.data);
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
        return await this.userUtils.lookup(uid);
    }
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, JWTUtils, ObjectDecorators } from "@rapidrest/core";
import { RouteDecorators, DocDecorators, RepoUtils, AuthMiddleware, ObjectFactory } from "@rapidrest/service-core";
import { Alias, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { BasicStrategy, BasicStrategyOptions } from "../auth/BasicStrategy.js";
import { importArgon2 } from "../auth/shared.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 *
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthBasicRoute<U extends User, S extends Secret, A extends Alias> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth")
    protected jwtConfig?: any;

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

    protected secretRepo?: RepoUtils<S>;

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

        const options: BasicStrategyOptions = new BasicStrategyOptions();
        options.verify = async (name: string, password: string): Promise<JWTUser | undefined> => {
            if (!this.secretRepo) {
                throw new Error("Secret repository not set.");
            }
            if (!this.userUtils) {
                throw new Error("User repository not set.");
            }

            const user: User | undefined = await this.userUtils.lookup(name);
            if (!user) {
                throw new Error("Invalid name or password");
            }

            let secrets: Secret[] = await this.secretRepo.find(
                {
                    userUid: user.uid,
                    type: SecretType.PASSWORD,
                },
                {
                    ignoreACL: true,
                },
            );

            // Try all known passwords until at least one succeeds
            let success: boolean = false;
            for (const secret of secrets) {
                const argon = await importArgon2();
                success = await argon.verify(secret.data, password);
                if (success) {
                    break;
                }
            }
            if (!success) {
                throw new Error("Invalid name or password");
            }

            return user;
        };
        const strategy: BasicStrategy = await this.objectFactory.newInstance(BasicStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using HTTP Basic and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Authenticate Password")
    @Description(
        "Authenticates the user using HTTP Basic and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["basic"])
    @Get()
    public async authenticate(@AuthUser user: JWTUser): Promise<AuthResult | undefined> {
        const token: string = await JWTUtils.createToken(this.jwtConfig, user);
        return new AuthResult({
            token,
            user,
        });
    }
}

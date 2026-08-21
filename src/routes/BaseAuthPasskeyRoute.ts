///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { JWTUser, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import {
    RouteDecorators,
    DocDecorators,
    HttpResponse,
    RepoUtils,
    AuthMiddleware,
    ObjectFactory,
    HttpRequest,
} from "@rapidrest/service-core";
import { Alias, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { PasskeyStrategy, PasskeyStrategyOptions } from "../auth/PasskeyStrategy.js";
import { PasskeyConfig, StoredPasskeyCredential } from "../auth/types.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, Request, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 *
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthPasskeyRoute<U extends User, A extends Alias, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    protected aliasRepo?: RepoUtils<A>;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected jwtConfig?: any;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected secretRepo?: RepoUtils<S>;

    @Config("auth:passkey")
    protected passkeyConfig: PasskeyConfig = {
        rpName: "rapidrest",
        rpID: "rapidrest",
        origin: "http://localhost:3000",
    };

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
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }

        if (!this.userUtils && this.userClass && this.aliasClass) {
            this.userUtils = await this._objectFactory.newInstance(UserUtils, {
                name: "default",
                args: [this.userClass, this.aliasClass],
            });
        }

        const options: PasskeyStrategyOptions = new PasskeyStrategyOptions(this.passkeyConfig);
        options.checkRateLimit = (identifier: string) => this.rateLimiter!.checkAndIncrement(identifier);
        options.getCredentialById = this.getCredentialById.bind(this);
        options.getCredentials = this.getCredentials.bind(this);
        options.updateCredentialCounter = this.updateCredentialCounter.bind(this);
        options.getUser = this.getUser.bind(this);
        const strategy: PasskeyStrategy = await this._objectFactory.newInstance(PasskeyStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using Passkey and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Authenticate Passkey")
    @Description(
        "Authenticates the user using Passkey and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["passkey"])
    @Get()
    @Post()
    public async authenticate(
        @AuthUser user: JWTUser,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
    ): Promise<AuthResult | undefined> {
        return await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req, res);
    }

    protected async getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (typeof credentialId !== "string") {
            return undefined;
        }
        const secret: Secret | undefined = await this.secretRepo.findOne(credentialId, { ignoreACL: true });
        if (secret && secret.type !== SecretType.PASSKEY) {
            // A credential id is only meaningful within the strategy that registered it - without this
            // check, a credential id belonging to some other Secret type (e.g. a `fido2` registration)
            // would be handed to WebAuthn verification here unchecked.
            return undefined;
        }
        return secret?.data;
    }

    protected async getCredentials(id: string): Promise<StoredPasskeyCredential[]> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (!this.userUtils) {
            throw new Error("userUtils is not set.");
        }

        const user: U | undefined = await this.userUtils.lookup(id);
        if (!user) {
            throw new Error("Invalid authentication request.");
        }

        // Retrieve all passkey secrets associated with this user
        const secrets: Secret[] = await this.secretRepo.find(
            { type: SecretType.PASSKEY, userUid: user.uid },
            { ignoreACL: true },
        );

        // Extract the passkey credential data from the secrets and return
        const results: StoredPasskeyCredential[] = [];
        secrets.forEach((secret) => results.push(secret.data));
        return results;
    }

    /**
     * Retrieve the user associated with a given uid or alias.
     *
     * @param id The unqique id of the user or alias to lookup.
     */
    protected async getUser(id: string): Promise<JWTUser | undefined> {
        if (!this.userUtils) {
            throw new Error("userUtils is not set.");
        }
        return await this.userUtils.lookup(id);
    }

    protected async updateCredentialCounter(credentialId: string, newCounter: number): Promise<void> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }

        const secret: S | undefined = await this.secretRepo.findOne(credentialId, { ignoreACL: true });
        if (secret) {
            (secret.data as StoredPasskeyCredential).counter = newCounter;
            await this.secretRepo.update(
                {
                    uid: secret.uid,
                    version: secret.version,
                    data: secret.data,
                } as S,
                secret,
                { ignoreACL: true, recordEvent: false },
            );
        }
    }
}

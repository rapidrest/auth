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
import { Alias, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { FIDO2Strategy, FIDO2StrategyOptions } from "../auth/FIDO2Strategy.js";
import { PasskeyConfig, StoredPasskeyCredential } from "../auth/types.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 * Authenticates users via a registered FIDO2 hardware security key (e.g. a YubiKey) using
 * WebAuthn/CTAP2. See `BaseAuthPasskeyRoute` for the software/synced-credential ("Passkey")
 * counterpart of this route — both share the same underlying WebAuthn ceremony, but look up
 * credentials stored as `SecretType.FIDO2` rather than `SecretType.PASSKEY`.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthFIDO2Route<U extends User, A extends Alias, S extends Secret> {
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

    protected secretRepo?: RepoUtils<S>;

    /**
     * The relying party configuration to use for this FIDO2 strategy. Kept separate from the Passkey
     * strategy's configuration since a hardware key deployment commonly wants a different
     * `authenticatorAttachment`/`residentKey` policy (see `BaseSecretRoute.fido2Config`).
     */
    @Config("auth:fido2")
    protected fido2Config: PasskeyConfig = {
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

        const options: FIDO2StrategyOptions = new FIDO2StrategyOptions(this.fido2Config);
        options.getCredentialById = this.getCredentialById.bind(this);
        options.getCredentials = this.getCredentials.bind(this);
        options.updateCredentialCounter = this.updateCredentialCounter.bind(this);
        options.getUser = this.getUser.bind(this);
        const strategy: FIDO2Strategy = await this.objectFactory.newInstance(FIDO2Strategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using a FIDO2 hardware security key and returns a JSON Web Token access
     * token to be used with future API requests.
     */
    @Summary("Authenticate FIDO2")
    @Description(
        "Authenticates the user using a FIDO2 hardware security key and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["fido2"])
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

    protected async getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (typeof credentialId !== "string") {
            return undefined;
        }
        const secret: Secret | undefined = await this.secretRepo.findOne(credentialId, { ignoreACL: true });
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

        // Retrieve all FIDO2 secrets associated with this user
        const secrets: Secret[] = await this.secretRepo.find(
            { type: SecretType.FIDO2, userUid: user.uid },
            { ignoreACL: true },
        );

        // Extract the credential data from the secrets and return
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

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
    HttpRequest,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { MFAMethod, MFAMethodType, MFAStrategy, MFAStrategyOptions } from "../auth/MFAStrategy.js";
import { OTPContact, OTPContactType, PasskeyConfig, StoredPasskeyCredential, TOTPSecret } from "../auth/types.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { importArgon2, verifyDummyPassword } from "../auth/shared.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, Request, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 *
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthMFARoute<U extends User, S extends Secret, A extends Alias> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    protected aliasRepo?: RepoUtils<A>;

    @Inject(AuthMiddleware)
    protected authMiddleware?: AuthMiddleware;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    /**
     * The relying party configuration to use for the FIDO2 secondary authentication method. See
     * `BaseAuthFIDO2Route`/`BaseSecretRoute.fido2Config` for the primary-auth/registration
     * counterparts of this configuration.
     */
    @Config("auth:fido2")
    protected fido2Config: PasskeyConfig = {
        rpName: "rapidrest",
        rpID: "rapidrest",
        origin: "http://localhost:3000",
    };

    @Config("auth")
    protected jwtConfig?: any;

    @Logger
    protected logger: any;

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

        const options: MFAStrategyOptions = new MFAStrategyOptions();
        options.checkRateLimit = (identifier: string) => this.rateLimiter!.checkAndIncrement(identifier);
        options.fidoConfig = this.fido2Config;
        options.getCredentialById = this.getCredentialById.bind(this);
        options.getMethod = this.getMethod.bind(this);
        options.getMethods = this.getMethods.bind(this);
        options.getUser = this.getUser.bind(this);
        options.notifyContact = this.notifyContact.bind(this);
        options.updateCredentialCounter = this.updateCredentialCounter.bind(this);
        options.updateSecretTimeStep = this.updateSecretTimeStep.bind(this);
        options.verify = this.verify.bind(this);
        const strategy: MFAStrategy = await this.objectFactory.newInstance(MFAStrategy, {
            name: "default",
            args: [options],
        });
        this.authMiddleware.register(strategy.name, strategy);
    }

    /**
     * Authenticates the user using HTTP MFA and returns a JSON Web Token access token to be used with future API requests.
     */
    @Summary("Authenticate MFA")
    @Description(
        "Authenticates the user using HTTP MFA and returns a JSON Web Token access token to be used with future API requests.",
    )
    @Returns([AuthResult, undefined])
    @Auth(["mfa"])
    @Get()
    @Post()
    public async authenticate(
        @AuthUser user: JWTUser,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
    ): Promise<AuthResult | undefined> {
        return await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req, res);
    }

    protected convertAliasToMethod(alias: Alias, obfuscate?: boolean): MFAMethod | undefined {
        // A 2FA method must already be a proven point of contact. Without this, any caller holding a mere
        // (possibly stolen) password could add a brand-new, self-controlled, unverified email/phone alias to
        // their own account via BaseAliasRoute.create().
        if (!alias.verified) {
            return undefined;
        }

        switch (alias.type) {
            case AliasType.EMAIL:
                return {
                    id: alias.uid,
                    data: {
                        contact: obfuscate ? this.obfuscateAlias(alias.alias, alias.type) : alias.alias,
                        type: OTPContactType.EMAIL,
                        verified: alias.verified,
                    },
                    type: MFAMethodType.OTP,
                };
            case AliasType.PHONE:
                return {
                    id: alias.uid,
                    data: {
                        contact: obfuscate ? this.obfuscateAlias(alias.alias, alias.type) : alias.alias,
                        type: OTPContactType.SMS,
                        verified: alias.verified,
                    },
                    type: MFAMethodType.OTP,
                };
        }

        return undefined;
    }

    protected convertSecretToMethod(secret: S): MFAMethod | undefined {
        switch (secret.type) {
            case SecretType.FIDO2:
                return {
                    id: secret.uid,
                    data: secret.data,
                    type: MFAMethodType.FIDO2,
                };
            case SecretType.TOTP:
                return {
                    id: secret.uid,
                    data: secret.data,
                    type: MFAMethodType.TOTP,
                };
        }

        return undefined;
    }

    /**
     * Retrieves a previously-registered FIDO2 credential by its ID, for verifying a FIDO2 secondary
     * authentication challenge response.
     * @param credentialId The unique id of the FIDO2 credential to retrieve.
     */
    protected async getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (typeof credentialId !== "string") {
            return undefined;
        }
        const secret: S | undefined = await this.secretRepo.findOne(credentialId, { ignoreACL: true });
        if (secret && secret.type !== SecretType.FIDO2) {
            // A credential id is only meaningful for a FIDO2 secret - without this check, a
            // credential id belonging to some other Secret type would be handed to WebAuthn
            // verification here unchecked.
            return undefined;
        }
        return secret?.data;
    }

    /**
     * Retrieves the user's secondary authentication method for a given id. Only returns a method that actually
     * belongs to `uid` — this is what stops one user's 2FA challenge from being triggered/consumed using
     * another user's authentication method.
     * @param id The unique id of the secondary auth method to retrieve.
     * @param userUid The unique id of the user the method must belong to.
     */
    protected async getMethod(id: string, userUid: string): Promise<MFAMethod | undefined> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (typeof id !== "string" || typeof userUid !== "string") {
            return undefined;
        }

        // The 2fa auth method may be a secret or an alias (OTP). First look for a secret
        // with the matching id. If not found, look for an alias.
        const secret: S | undefined = await this.secretRepo.findOne(id, { ignoreACL: true });
        if (secret) {
            return secret.userUid === userUid ? this.convertSecretToMethod(secret) : undefined;
        }

        // It's not a secret, let's try alias
        const alias: A | undefined = await this.aliasRepo.findOne(id, { ignoreACL: true });
        if (alias) {
            return alias.userUid === userUid ? this.convertAliasToMethod(alias) : undefined;
        }

        return undefined;
    }

    /**
     * Retrieves the list of secondary authentication methods for the user with the given id. This list is sent to
     * the user and so should be obfuscated where reasonable so as to limit discovery when a password has been
     * compromised.
     * @param uid The unique identifier of the user.
     */
    protected async getMethods(uid: string): Promise<MFAMethod[]> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }
        if (!this.userRepo) {
            throw new Error("userRepo is not set.");
        }

        const results: MFAMethod[] = [];

        // Search for secrets for the user and add each to our list of methods. Not all secrets
        // will be added, only those that are valid for MFA.
        const secrets: S[] = await this.secretRepo.find({ userUid: uid }, { ignoreACL: true });
        for (const secret of secrets) {
            const method: MFAMethod | undefined = this.convertSecretToMethod(secret);
            if (method) {
                results.push(method);
            }
        }

        // Now search for the user's aliases that serve as OTP contacts
        const allAliases: A[] = await this.aliasRepo.find(
            { userUid: uid },
            {
                ignoreACL: true,
            },
        );

        // Filter aliases to only those that can be notified
        const aliases = allAliases.filter((alias) => [AliasType.EMAIL, AliasType.PHONE].includes(alias.type));

        // Now add all eligible aliases to our list of methods (e.g. email, phone).
        for (const alias of aliases) {
            const method: MFAMethod | undefined = this.convertAliasToMethod(alias, true);
            if (method) {
                results.push(method);
            }
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
            throw new Error("userRepo is not set.");
        }
        return this.userUtils.lookup(uid);
    }

    protected async notifyContact(contact: OTPContact, totp: string): Promise<void> {
        switch (contact.type) {
            case OTPContactType.EMAIL:
                this.messagingUtils
                    ?.sendEmail(this.template, { totp }, { to: contact.contact })
                    .catch((err) =>
                        this.logger?.debug(`[BaseAuthMFARoute] Failed to send verification e-mail: ${err}`),
                    );
                break;
            case OTPContactType.SMS:
                this.messagingUtils
                    ?.sendSMS(this.template, { totp }, { to: contact.contact })
                    .catch((err) =>
                        this.logger?.debug(`[BaseAuthMFARoute] Failed to send verification SMS: ${err}`),
                    );
                break;
        }
    }

    /**
     * Obfuscates the given alias and returns the obfuscated value.
     * @param contact The contact to obfuscate.
     */
    protected obfuscateAlias(alias: string, type: AliasType): string {
        let result: string = alias;

        switch (type) {
            case AliasType.EMAIL:
                result = result.replace(/^(.).*(.{2})(@)/, "$1***$2$3");
                break;
            case AliasType.NAME:
                result = result.replace(/.(?=.{3})/g, "*");
                break;
            case AliasType.PHONE:
                result = result.replace(/.(?=.{4})/g, "*");
                break;
        }

        return result;
    }

    /**
     * Persists the updated signature counter for the given FIDO2 credential after a successful MFA
     * challenge. Called on every successful FIDO2 secondary authentication to guard against cloned
     * authenticators.
     * @param credentialId The unique id of the credential to update.
     * @param newCounter The new signature counter value to persist.
     */
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

    /**
     * Persists the given time step as the last one successfully used for the identified TOTP
     * secret, so a captured/replayed token can't be reused within its validity window.
     * @param uid The unique id of the stored secret that was verified.
     * @param timeStep The RFC 6238 time step at which the token was verified.
     */
    protected async updateSecretTimeStep(uid: string, timeStep: number): Promise<void> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }

        const secret: S | undefined = await this.secretRepo.findOne(uid, { ignoreACL: true });
        if (secret) {
            (secret.data as TOTPSecret).lastTimeStep = timeStep;
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

    protected async verify(name: string, password: string): Promise<JWTUser | undefined> {
        if (!this.secretRepo) {
            throw new Error("Secret repository not set.");
        }
        if (!this.userUtils) {
            throw new Error("User repository not set.");
        }

        const user: U | undefined = await this.userUtils.lookup(name);
        if (!user) {
            // Burn an equivalent amount of time to the real verification path below so a nonexistent
            // user can't be distinguished from a wrong password via response timing.
            await verifyDummyPassword(password);
            throw new Error("Invalid authorization request.");
        }

        let secrets: S[] = await this.secretRepo.find(
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
        if (secrets.length === 0) {
            // No password secret to check against — burn the same amount of time as a real
            // verification so this case isn't distinguishable via timing from a wrong password.
            await verifyDummyPassword(password);
        } else {
            for (const secret of secrets) {
                const argon = await importArgon2();
                success = await argon.verify(secret.data, password);
                if (success) {
                    break;
                }
            }
        }
        if (!success) {
            throw new Error("Invalid authorization request.");
        }

        return user;
    }
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUser, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import {
    ApiErrors,
    RouteDecorators,
    DocDecorators,
    HttpResponse,
    RepoUtils,
    AuthMiddleware,
    ObjectFactory,
    HttpRequest,
} from "@rapidrest/service-core";
import { Alias, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { TOTPStrategy, TOTPStrategyOptions } from "../auth/TOTPStrategy.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import { TOTPConfig, TOTPSecret } from "../auth/types.js";
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
export abstract class BaseAuthTOTPRoute<U extends User, A extends Alias, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

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

    /** The name of the messaging template to use for sending notifications. */
    protected template: string = "login-otp";

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    protected userUtils?: UserUtils<U, A>;

    /**
     * Only `encryption_key` is read here — the rest of `TOTPConfig` (digits/period/algorithm/etc.) is
     * captured onto each `TOTPSecret` at registration time by `BaseSecretRoute`, not re-read at login.
     */
    @Config("auth:totp")
    protected totpConfig: TOTPConfig = { issuer: "rapidrest" };

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

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userUtils && this.userClass && this.aliasClass) {
            this.userUtils = await this._objectFactory.newInstance(UserUtils, {
                name: "default",
                args: [this.userClass, this.aliasClass],
            });
        }

        const options: TOTPStrategyOptions = new TOTPStrategyOptions();
        options.checkRateLimit = (identifier: string, req: HttpRequest) =>
            this.rateLimiter!.checkAndIncrement(identifier, req);
        options.encryptionKey = this.totpConfig.encryption_key;
        options.getSecrets = this.getSecrets.bind(this);
        options.getUser = this.getUser.bind(this);
        options.updateSecretTimeStep = this.updateSecretTimeStep.bind(this);
        const strategy: TOTPStrategy = await this._objectFactory.newInstance(TOTPStrategy, {
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
    public async authenticate(
        @AuthUser user: JWTUser,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
    ): Promise<AuthResult | undefined> {
        return await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req, res);
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
            // The underlying secret's own uid is attached so a successful verification can be
            // traced back to the specific record to persist replay-protection state onto.
            results.push({ ...secret.data, uid: secret.uid });
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

    /**
     * Persists the given time step as the last one successfully used for the identified TOTP
     * secret, so a captured/replayed token can't be reused within its validity window.
     *
     * Closes a TOCTOU race between two concurrent requests both holding the same valid code: each
     * independently reads the secret and verifies the submitted token *before* either one reaches this
     * method, so verification alone can't tell them apart. Re-checking `lastTimeStep` against a fresh
     * read here - combined with `RepoUtils.update()`'s existing optimistic-locking `version` check, which
     * still protects the case where both readers see the same pre-update state - means at most one of the
     * two ever succeeds in claiming this time step; the loser throws instead of silently letting a second
     * session authenticate on an already-used code.
     * @param uid The unique id of the stored secret that was verified.
     * @param timeStep The RFC 6238 time step at which the token was verified.
     */
    protected async updateSecretTimeStep(uid: string, timeStep: number): Promise<void> {
        if (!this.secretRepo) {
            throw new Error("secretRepo is not set.");
        }

        const secret: S | undefined = await this.secretRepo.findOne(uid, { ignoreACL: true });
        if (secret) {
            const totpData = secret.data as TOTPSecret;
            if (totpData.lastTimeStep !== undefined && totpData.lastTimeStep >= timeStep) {
                throw new ApiError(ApiErrors.AUTH_FAILED, 401, "This code has already been used.");
            }
            totpData.lastTimeStep = timeStep;
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

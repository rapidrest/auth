///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUser, MessagingUtils, ObjectDecorators } from "@rapidrest/core";
import {
    ApiErrorMessages,
    ApiErrors,
    RouteDecorators,
    DocDecorators,
    HttpResponse,
    RepoUtils,
    ObjectFactory,
    HttpRequest,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, Secret, SecretType, User } from "../models/types.js";
import { MFAMethod, MFAMethodType } from "../auth/MFAStrategy.js";
import { OTPContact, OTPContactType, PasskeyConfig, StoredPasskeyCredential, TOTPSecret } from "../auth/types.js";
import { RateLimiter } from "../auth/RateLimiter.js";
import {
    generateOTP,
    generatePasskeyChallenge,
    importArgon2,
    isOTPResponse,
    isPasskeyResponse,
    verifyDummyPassword,
    verifyOTP,
    verifyPasskeyChallenge,
    verifyTOTP,
} from "../auth/shared.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { UserUtils } from "./UserUtils.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Get, Post, Request, Response } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 * Issues an elevated access token (see `TokenUtils.createAccessToken`'s `elevated` argument, and the
 * `@RequiresElevation` decorator in `@rapidrest/service-core`) once the caller — who must already hold a
 * valid, non-elevated access token — has freshly re-proven their identity. Only an elevated token carries
 * the caller's trusted roles — a normal, non-elevated token never does — so this route is what turns a
 * plain "I'm logged in" session into "I've recently confirmed I'm still me" for the specific request(s)
 * that need it.
 *
 * This is deliberately a lightweight, single-factor "prove you're still you" check, NOT a full
 * re-authentication: the caller already proved their identity once to obtain their current access token
 * (see `@Auth(["jwt"])` below), so this route only asks for one additional method:
 *
 * * A caller who has enrolled at least one secondary method (OTP/TOTP/FIDO2) must complete exactly one of
 * them — `GET` lists the caller's own available methods, and `POST` both begins and completes a
 * challenge for a selected one (mirroring `BaseAuthMFARoute`'s phase 2/3, but scoped to the caller's own
 * uid throughout since identity is already established via the JWT, never taken from the request body).
 * * A caller with *no* secondary method enrolled (most commonly a freshly bootstrapped default admin
 * account, which typically only has a password) elevates by resubmitting their password instead. Without
 * this, such an account could never satisfy `@RequiresElevation`-gated actions at all, since it has no
 * second factor to prove — a permanent lockout, not a security improvement. Password resubmission is
 * only accepted when zero secondary methods are enrolled — once a real second factor exists, it must be
 * used, since re-supplying the same password used to obtain the current token proves nothing new.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAuthElevationRoute<U extends User, S extends Secret, A extends Alias> {
    protected abstract aliasClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    protected aliasRepo?: RepoUtils<A>;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    /**
     * The relying party configuration to use for the FIDO2 elevation method. See
     * `BaseAuthFIDO2Route`/`BaseSecretRoute.fido2Config` for the primary-auth/registration counterparts of
     * this configuration.
     */
    @Config("auth:fido2")
    protected fido2Config: PasskeyConfig = {
        rpName: "rapidrest",
        rpID: "rapidrest",
        origin: "http://localhost:3000",
    };

    @Logger
    protected logger: any;

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
    }

    /**
     * Returns the authenticated caller's own available secondary methods for elevating — see `elevate()`.
     * An empty list means the caller has none enrolled and must elevate via password instead.
     */
    @Summary("List Elevation Methods")
    @Description(
        "Returns the authenticated caller's available secondary methods for elevating (see POST). An " +
            "empty list means the caller must elevate via password instead.",
    )
    @Returns([[Array, Object]])
    @Auth(["jwt"])
    @Get()
    public async listMethods(@AuthUser user: JWTUser): Promise<MFAMethod[]> {
        return await this.getMethods(user.uid);
    }

    /**
     * Re-verifies the caller's identity using exactly one additional method beyond their existing access
     * token, and on success returns a fresh elevated access token (and refresh token) for them to use with
     * the specific request(s) that require it. Accepts, in the request body:
     *
     * * `{ methodId }` — begins a challenge for one of the caller's own methods (from `listMethods()`).
     * For FIDO2 this returns a WebAuthn assertion challenge; for OTP this sends a code to the associated
     * contact; for TOTP this returns an empty body (the caller's authenticator app already has the
     * current code).
     * * `{ token }` (OTP/TOTP) or a WebAuthn assertion response (FIDO2) — completes the challenge begun
     * above.
     * * `{ password }` — only accepted when the caller has zero secondary methods enrolled.
     */
    @Summary("Elevate")
    @Description(
        "Re-verifies the caller's identity using exactly one additional method (a secondary method if one " +
            "is enrolled, otherwise password) and returns an elevated JSON Web Token access token, for use " +
            "with endpoints that require recently-confirmed identity (see `@RequiresElevation`).",
    )
    @Returns([AuthResult, Object])
    @Auth(["jwt"])
    @Post()
    public async elevate(
        obj: any,
        @AuthUser user: JWTUser,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
    ): Promise<AuthResult | any> {
        if (!this.tokenUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }
        if (!req.session) {
            throw new Error(
                "BaseAuthElevationRoute requires session support. Configure the `session` config " +
                    "block so the session middleware is registered.",
            );
        }

        if (this.rateLimiter) {
            // Keyed on the already-authenticated caller's own uid, not anything client-supplied — unlike
            // login-time rate limiting, this key is fully trustworthy since the caller is already
            // authenticated, so there's no risk of an attacker bucketing an innocent uid.
            await this.rateLimiter.checkAndIncrement(`elevate:${user.uid}`);
        }

        // Never trust a client-supplied `id` here — every method below is scoped to the identity already
        // proven by the caller's existing access token, not anything the request body claims.
        const payload: any = { ...obj, id: user.uid };

        if (typeof payload.methodId === "string") {
            return await this.beginChallenge(payload.methodId, user, req);
        }

        let verifiedUser: JWTUser | undefined;
        if (isOTPResponse(payload)) {
            verifiedUser = req.session.mfaMethodId
                ? await this.verifyTOTPChallenge(payload, req)
                : await this.verifyOTPChallenge(payload, req);
        } else if (isPasskeyResponse(payload)) {
            verifiedUser = await this.verifyFIDOChallenge(payload, req);
        } else if (typeof payload.password === "string") {
            verifiedUser = await this.verifyPasswordOnly(user, payload.password);
        } else {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Invalid elevation request.");
        }

        if (!verifiedUser) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 401, ApiErrorMessages.AUTH_FAILED);
        }

        return await this.tokenUtils.createAuthResult(verifiedUser, this.defaultScopes, req, res, true);
    }

    /**
     * Begins a challenge for one of the caller's own elevation methods. Scoped to `user.uid` throughout via
     * `getMethod()` — the same authorization boundary `BaseAuthMFARoute` relies on — so a `methodId`
     * belonging to another user can never be used here.
     */
    protected async beginChallenge(methodId: string, user: JWTUser, req: HttpRequest): Promise<any> {
        const method: MFAMethod | undefined = await this.getMethod(methodId, user.uid);
        if (!method) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Invalid secondary authentication method.");
        }

        switch (method.type) {
            case MFAMethodType.FIDO2: {
                const credential = method.data as StoredPasskeyCredential;
                const result = await generatePasskeyChallenge(this.fido2Config, req, [
                    { id: credential.id, transports: credential.transports },
                ]);
                req.session!.elevateUid = user.uid;
                req.session!.mfaMethodId = method.id;
                return result;
            }
            case MFAMethodType.OTP: {
                // Clear any stale `mfaMethodId` left over from a previous TOTP/FIDO2 challenge selection
                // in this session — otherwise the OTP submission below would be misrouted to TOTP
                // verification, which always fails.
                delete req.session!.mfaMethodId;
                const totp: string = await generateOTP(req, { id: user.uid });
                await this.notifyContact(method.data, totp);
                req.session!.elevateUid = user.uid;
                return {};
            }
            case MFAMethodType.TOTP: {
                // No challenge or notification is needed — the client's authenticator app already has the
                // current code. Record which secret was selected so the submission below is verified
                // against the right one, and so it's routed to TOTP rather than OTP verification (both
                // share the same `{id, token}` shape).
                req.session!.elevateUid = user.uid;
                req.session!.mfaMethodId = method.id;
                return {};
            }
            default:
                throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Unsupported elevation method.");
        }
    }

    protected async verifyOTPChallenge(payload: any, req: HttpRequest): Promise<JWTUser | undefined> {
        const valid: boolean = await verifyOTP(req, payload);

        // Single-use regardless of outcome — cleared as soon as it's read. This is a route-local field
        // (`elevateUid`), deliberately distinct from the shared `session.userUid` that `TokenUtils`/
        // `BaseAuthRefreshRoute` use to track the caller's actual logged-in identity — clearing *that*
        // field on a failed elevation attempt would break the caller's ability to refresh their still
        // otherwise-valid session.
        const userUid: string | undefined = req.session?.elevateUid;
        delete req.session?.elevateUid;

        if (!valid || !userUid) {
            return undefined;
        }
        return await this.getUser(userUid);
    }

    protected async verifyTOTPChallenge(payload: any, req: HttpRequest): Promise<JWTUser | undefined> {
        const userUid: string | undefined = req.session?.elevateUid;
        const methodId: string | undefined = req.session?.mfaMethodId;
        delete req.session?.elevateUid;
        delete req.session?.mfaMethodId;

        if (!userUid || !methodId || payload.id !== userUid) {
            return undefined;
        }

        // Re-fetch the specific secret selected during the challenge — this also re-confirms it still
        // belongs to the caller and is actually a TOTP method.
        const method: MFAMethod | undefined = await this.getMethod(methodId, userUid);
        if (!method || method.type !== MFAMethodType.TOTP) {
            return undefined;
        }

        const result: any = await verifyTOTP(payload.token, method.data);
        if (!result || !result.valid) {
            return undefined;
        }

        await this.updateSecretTimeStep(methodId, result.timeStep);

        return await this.getUser(userUid);
    }

    protected async verifyFIDOChallenge(payload: any, req: HttpRequest): Promise<JWTUser | undefined> {
        const userUid: string | undefined = req.session?.elevateUid;
        const methodId: string | undefined = req.session?.mfaMethodId;
        const expectedChallenge: string | undefined = req.session?.challenge;
        delete req.session?.elevateUid;
        delete req.session?.mfaMethodId;
        delete req.session?.challenge;

        if (!userUid || !methodId || !expectedChallenge) {
            return undefined;
        }

        const credential: StoredPasskeyCredential | undefined = await this.getCredentialById(payload.id);
        // Only the specific credential selected during the challenge, and only if it belongs to the
        // caller, may complete this challenge.
        if (!credential || credential.id !== methodId || credential.uid !== userUid) {
            return undefined;
        }

        const result = await verifyPasskeyChallenge(credential, this.fido2Config, expectedChallenge, payload);
        if (!result.verified) {
            return undefined;
        }

        // Counter regression check — see PasskeyStrategy/FIDO2Strategy for the same guard against cloned
        // authenticators.
        const newCounter: number = result.authenticationInfo.newCounter;
        if (newCounter !== 0 && newCounter <= credential.counter) {
            return undefined;
        }
        await this.updateCredentialCounter(credential.id, newCounter);

        return await this.getUser(userUid);
    }

    /**
     * Verifies the caller's password as their sole proof of elevation. Only valid when the caller has no
     * secondary method enrolled — once a real second factor exists it must be used instead, since
     * resubmitting the same password used to obtain the current access token proves nothing new.
     */
    protected async verifyPasswordOnly(user: JWTUser, password: string): Promise<JWTUser | undefined> {
        const methods: MFAMethod[] = await this.getMethods(user.uid);
        if (methods.length > 0) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "A secondary elevation method is enrolled and must be used instead of a password.",
            );
        }

        try {
            return await this.verify(user.uid, password);
        } catch (err: any) {
            return undefined;
        }
    }

    protected convertAliasToMethod(alias: Alias, obfuscate?: boolean): MFAMethod | undefined {
        // An elevation method must already be a proven point of contact. Without this, any caller
        // holding a mere (possibly stolen, non-elevated) access token could add a brand-new,
        // self-controlled, unverified email/phone alias to their own account via BaseAliasRoute.create()
        // — which requires no elevation — then use it to receive and submit a real OTP code, obtaining a
        // fully elevated token without ever proving anything beyond possession of that access token.
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
     * Retrieves a previously-registered FIDO2 credential by its ID, for verifying a FIDO2 elevation
     * challenge response.
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
     * Retrieves the user's elevation method for a given id. Only returns a method that actually belongs to
     * `uid` — this is what stops one user's elevation challenge from being triggered/consumed using another
     * user's authentication method.
     * @param id The unique id of the elevation method to retrieve.
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

        // The elevation method may be a secret or an alias (OTP). First look for a secret with the
        // matching id. If not found, look for an alias.
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
     * Retrieves the list of elevation methods for the user with the given id. This list is sent to the
     * user and so should be obfuscated where reasonable so as to limit discovery when a password has been
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
        // will be added, only those that are valid for elevation.
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
                        this.logger?.debug(`[BaseAuthElevationRoute] Failed to send verification e-mail: ${err}`),
                    );
                break;
            case OTPContactType.SMS:
                this.messagingUtils
                    ?.sendSMS(this.template, { totp }, { to: contact.contact })
                    .catch((err) =>
                        this.logger?.debug(`[BaseAuthElevationRoute] Failed to send verification SMS: ${err}`),
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
     * Persists the updated signature counter for the given FIDO2 credential after a successful elevation
     * challenge. Called on every successful FIDO2 elevation to guard against cloned authenticators.
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

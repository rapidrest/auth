////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { ApiError, MessagingUtils, ObjectDecorators, ValidationUtils } from "@rapidrest/core";
import {
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { Alias, AliasType, AuthResult, User } from "../models/types.js";
import { generateOTP, verifyOTP } from "../auth/shared.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { RateLimiter } from "../auth/RateLimiter.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Summary, Description } = DocDecorators;
const { Post, Request, Response } = RouteDecorators;

interface StartBody {
    email?: string;
    phone?: string;
}

interface VerifyBody {
    email?: string;
    phone?: string;
    token?: string;
}

/**
 * Provides a simple account registration flow that verifies an e-mail or phone number using OTP authentication before
 * creating the account.
 *
 * The registration flow:
 * 1. Client calls `POST /start` with either an e-mail address of phone number to verify.
 * 2. Sends an OTP code to the provided email or phone number in step 1.
 * 3. Client calls `POST /verify` with the email or phone number and OTP code.
 * 4. If OTP code is verified, creates a new `User` and `Alias`, returns a valid JWT token.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseRegistrationRoute<U extends User, A extends Alias> {
    protected abstract aliasClass: any;
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected jwtConfig?: any;

    @Logger
    protected logger: any;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected aliasRepo?: RepoUtils<A>;
    protected userRepo?: RepoUtils<U>;

    @Init
    protected async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * Sends a one-time verification code to the provided e-mail address or phone number.
     */
    @Summary("Begin account registration")
    @Description("Sends a one-time verification code to the provided e-mail address or phone number.")
    @Post("/start")
    public async start(body: StartBody, @Request req: HttpRequest): Promise<Record<string, never>> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!req.session) {
            throw new Error("Registration requires session support. Configure the `session` config block.");
        }

        const email = (body?.email ?? "").trim().toLowerCase();
        const phone = (body?.phone ?? "").trim();
        try {
            if (email) {
                ValidationUtils.checkEmail(email);
            }
            if (phone) {
                ValidationUtils.checkPhone(phone);
            }
        } catch (err) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A valid e-mail address or phone number is required.");
        }

        if (email) {
            // Rate limit unconditionally, before the "already registered" check below, so that an
            // existing identifier and a non-existing one are throttled identically — otherwise the two
            // branches are distinguishable by request-rate tolerance alone, defeating the point of the
            // identical `{}` response used for both.
            await this.rateLimiter?.checkAndIncrement(email);

            const existing = await this.aliasRepo.find(
                {
                    alias: email,
                    type: AliasType.EMAIL,
                },
                { ignoreACL: true },
            );
            if (existing.some((a) => a.verified)) {
                // An account for this identifier already exists. We do not throw an error here so that this cannot
                // be used to discover registered accounts.
                return {};
            }

            const token = await generateOTP(req, { id: email });
            this.messagingUtils?.sendEmail("register-otp", { totp: token }, { to: email }).catch((err) => {
                this.logger.debug(`Failed to send verification e-mail: ${err}`);
            });
            if (process.env.environment !== "production") {
                this.logger.debug(`Verification code for ${email}: ${token}`);
            }
        } else if (phone) {
            // See the email branch above for why this runs unconditionally, before the "already
            // registered" check.
            await this.rateLimiter?.checkAndIncrement(phone);

            const existing = await this.aliasRepo.find(
                {
                    alias: phone,
                    type: AliasType.PHONE,
                },
                { ignoreACL: true },
            );
            if (existing.some((a) => a.verified)) {
                // An account for this identifier already exists. We do not throw an error here so that this cannot
                // be used to discover registered accounts.
                return {};
            }

            const token = await generateOTP(req, { id: phone });
            this.messagingUtils?.sendSMS("register-otp", { totp: token }, { to: phone }).catch((err) => {
                this.logger.debug(`Failed to send verification SMS: ${err}`);
            });
            if (process.env.environment !== "production") {
                this.logger.debug(`Verification code for ${phone}: ${token}`);
            }
        }

        return {};
    }

    /**
     * Verifies the one-time code sent by `start()`. On success, creates a new `User` and verified `Alias`
     * and returns an JWT token.
     */
    @Summary("Verify registration e-mail code")
    @Description("Verifies the one-time code sent to the claimed e-mail address so that registration can be completed.")
    @Post("/verify")
    public async verify(body: VerifyBody, @Request req: HttpRequest, @Response res: HttpResponse): Promise<AuthResult> {
        if (!this.aliasRepo) {
            throw new Error("aliasRepo is not set.");
        }
        if (!this.userRepo) {
            throw new Error("userRepo is not set.");
        }
        if (!req.session) {
            throw new Error("Registration requires session support. Configure the `session` config block.");
        }

        const email = (body?.email ?? "").trim().toLowerCase();
        const phone = (body?.phone ?? "").trim();
        const id = email || phone;
        const token = body?.token ?? "";
        if (!id || !token) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "An id and verification code are required.");
        }

        await this.rateLimiter?.checkAndIncrement(id);

        let valid: boolean;
        try {
            valid = await verifyOTP(req, { id, token });
        } catch (err) {
            valid = false;
        }
        if (!valid) {
            throw new ApiError(ApiErrors.AUTH_FAILED, 400, "The verification code is invalid or has expired.");
        }

        // `RepoUtils.create()` only grants the new record's owner permission over it via `options.user` — but
        // there's no authenticated actor to supply here, since the account being created *is* the actor and
        // doesn't exist as an authenticatable principal until this call returns. Passing plain `{verified:
        // true}` would leave the per-record ACL grant with nobody in it, locking the new user out of their
        // own account. `uid` is generated client-side in the entity constructor (see `BaseEntity`), so it's
        // known before either `create()` call below is made — pre-instantiate the object and pass it as
        // `options.user` for both, so the new user is recognized as their own owner.
        //
        // The alias is created *before* the user (rather than after, as it more naturally reads) so that a
        // uniqueness collision on the alias - whether from a squatted `name` alias planted ahead of time, or a
        // genuine race between two concurrent registration attempts for the same identifier - fails before any
        // `User` row is ever written. Creating the user first would leave that row orphaned (unusable, and
        // permanently blocking this identifier from ever completing registration) whenever the alias creation
        // that follows it fails.
        const newUser = new this.userClass({ verified: true });
        const options = { ignoreACL: true, user: newUser };
        // This bypasses `BaseAliasRoute.validateCreate()` (it calls the repo directly, since there's no
        // authenticated actor yet to route the request through), so it must repeat that method's own
        // displacement of stale *unverified* alias claims for the same value here - otherwise an attacker who
        // squatted this e-mail/phone as an unverified alias (see `BaseAliasRoute.validateCreate()`) would
        // permanently block this legitimate, just-OTP-verified registration on the DB's uniqueness constraint.
        if (email) {
            const existing = await this.aliasRepo.find({ alias: email }, { ignoreACL: true });
            for (const e of existing) {
                if (!e.verified) {
                    await this.aliasRepo.delete(e.uid, { ignoreACL: true });
                }
            }
            await this.aliasRepo.create(
                { alias: email, type: AliasType.EMAIL, userUid: newUser.uid, verified: true } as any,
                options,
            );
        }
        if (phone) {
            const existing = await this.aliasRepo.find({ alias: phone }, { ignoreACL: true });
            for (const e of existing) {
                if (!e.verified) {
                    await this.aliasRepo.delete(e.uid, { ignoreACL: true });
                }
            }
            await this.aliasRepo.create(
                { alias: phone, type: AliasType.PHONE, userUid: newUser.uid, verified: true } as any,
                options,
            );
        }
        const user = await this.userRepo.create(newUser, {
            ignoreACL: true,
            user: newUser,
        });

        // New accounts always get an elevated token in order to ensure that they can safely create
        // secrets (e.g. MFA setup) needed to maintain account access.
        return await this.tokenUtils!.createAuthResult(user, this.defaultScopes, req, res, true);
    }
}

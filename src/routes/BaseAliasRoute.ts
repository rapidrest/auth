///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    ApiErrorMessages,
    ApiErrors,
    CRUDRoute,
    DocDecorators,
    HttpRequest,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { ApiError, JWTUser, MessagingUtils, ObjectDecorators, UserUtils, ValidationUtils } from "@rapidrest/core";
import { Alias, AliasType, ContactType, Profile } from "../models/types.js";
import { generateOTP, verifyOTP } from "../auth/shared.js";
import { RateLimiter } from "../auth/RateLimiter.js";

const { Config, Init, Inject } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Auth, Get, Param, Post, Query, Request, RequiresElevation, User } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAliasRoute<T extends Alias> extends CRUDRoute<T> {
    /** The concrete `Profile` model class for this datastore — set by the SQL/Mongo binding subclass. */
    protected abstract profileClass: any;

    protected profileRepo?: RepoUtils<Profile>;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Init
    protected async init(): Promise<void> {
        if (!this.profileRepo && this.profileClass && this._objectFactory) {
            this.profileRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }
    }

    /**
     * Validates that the given string is a `name`. This is a variation of `ValidationUtils.checkName` as it
     * rejects any value that looks like an e-mail address or phone number.
     */
    private checkName(value: string) {
        ValidationUtils.checkName(value);

        const passesFormatCheck = function (value: string, check: (val: string) => string): boolean {
            try {
                check(value);
                return true;
            } catch {
                return false;
            }
        };

        // Each format check must live in its own try/catch, separate from the `throw` that acts on its
        // result — `ValidationUtils.checkEmail`/`checkPhone` throw on invalid input rather than returning a
        // boolean, so a `throw` placed inside the same `try` as a *successful* check would immediately be
        // swallowed by that block's own `catch`, silently defeating the rejection entirely.
        if (passesFormatCheck(value, ValidationUtils.checkEmail)) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A 'name' may not resemble an e-mail address.");
        }
        if (passesFormatCheck(value, ValidationUtils.checkPhone)) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A 'name' may not resemble a phone number.");
        }
    }

    protected async validateCreate(obj: Partial<T>, user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateCreate(obj, user);

        if (!obj.userUid) {
            obj.userUid = user.uid;
        } else if (obj.userUid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        // Make sure the alias is unique. An *unverified* alias is only a pending, unproven claim on the
        // value. It must not let anyone permanently reserve (squat) an e-mail/phone they don't control and
        // block the real owner's later registration/claim (see `BaseRegistrationRoute.verify()`). Only an
        // already-verified alias is a real conflict; stale unverified claims for the same value are displaced
        // so that whoever actually proves ownership via OTP is the one who ends up with the alias.
        const existing: T[] | undefined = await this.repoUtils?.find({ alias: obj.alias }, { ignoreACL: true });
        if (existing && existing.length > 0) {
            if (existing.some((e) => e.verified)) {
                throw new ApiError(ApiErrors.IDENTIFIER_EXISTS, 403, ApiErrorMessages.IDENTIFIER_EXISTS);
            }
            for (const e of existing) {
                await this.repoUtils?.delete(e.uid, { ignoreACL: true });
            }
        }

        if (obj.type === AliasType.NAME) {
            // A `name` alias is a free-form, self-verified identifier. We reject anything that could pass as an
            // e-mail address or phone number. The uniqueness constraint on `alias` spans all types, so without
            // this an attacker could squat a victim's future e-mail/phone as a `name` alias before the victim
            // ever registers it, blocking their registration and colliding with the `email`/`phone` alias
            // record `BaseRegistrationRoute` later tries to create for them.
            if (typeof obj.alias === "string") {
                this.checkName(obj.alias);
            }

            // Names are always considered verified
            obj.verified = true;
        } else if (obj.type === AliasType.EMAIL || obj.type === AliasType.PHONE) {
            // An alias is always considered unverified unless it already exists as verified in the user's Profile
            // contacts list.
            obj.verified = await this.isVerifiedContact(user, obj.alias!, obj.type);
        }
    }

    @RequiresElevation(60)
    public async create(obj: T | T[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T | Array<T>> {
        const result = await super.create(obj, req, user);

        // If the `type` is email or phone and unverified, send an OTP request to allow for verification.
        const arr: T[] = Array.isArray(result) ? result : [result];
        for (const alias of arr) {
            if (!alias.verified) {
                await this.sendVerificationCode(alias, req);
            }
        }

        return result;
    }

    @RequiresElevation(60)
    public delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<void> {
        return super.delete(id, version, purge, req, user);
    }

    public async find(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<T[]> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        if (!user || UserUtils.hasRoles(user, this.trustedRoles)) {
            return super.find(params, query, user);
        }

        return await this.repoUtils.find(
            { ...params, ...query, userUid: user.uid },
            { limit: query?.limit, page: query?.page, ignoreACL: true, user },
        );
    }

    private async isVerifiedContact(
        user: JWTUser,
        alias: string,
        type: AliasType.EMAIL | AliasType.PHONE,
    ): Promise<boolean> {
        if (!this.profileRepo) {
            return false;
        }

        // skipCache: true is required here as this is a security-relevant read (does the
        // caller's Profile actually have this contact verified?). `user` must also be passed here, not just
        // `ignoreACL`/`skipCache` because RepoUtils.findOne() strips any @RequiresScope-gated property
        // (Profile.contacts requires the `profile:contacts` scope) whenever no `user` is given. Without this,
        // `contacts` silently comes back undefined and every claim looks unproven regardless of the caller's
        // actual Profile state.
        const profile = await this.profileRepo.findOne(user.uid, { skipCache: true, ignoreACL: true, user });
        const contactType = type === AliasType.EMAIL ? ContactType.EMAIL : ContactType.PHONE;
        return !!profile?.contacts?.some((c) => c.contact === alias && c.type === contactType && c.verified);
    }

    /**
     * Requests a verification code be sent for the alias with the given id.
     * @param id The unique identifier of the alias to send a verification code to.
     * @param req The HTTP request being processed.
     * @param user The authenticated user making the request.
     */
    @Summary("Request Verification Code")
    @Description("Requests a verification code be sent to the alias with the given id.")
    @Auth(["jwt"])
    @Get(":id/sendCode")
    public async requestVerificationCode(
        @Param("id") id: string,
        @Request req: HttpRequest,
        @User user: JWTUser,
    ): Promise<void> {
        const alias: Alias | undefined = await this.repoUtils?.findOne(id, { user });
        if (alias) {
            await this.sendVerificationCode(alias, req);
        }
    }

    /**
     * Sends a one-time verification code to the unverified contact.
     */
    protected async sendVerificationCode(alias: Alias, req: HttpRequest): Promise<void> {
        if (alias.verified) {
            return;
        }

        await this.rateLimiter?.checkAndIncrement(alias.alias);
        const token = await generateOTP(req, { id: alias.alias });

        if (alias.type === AliasType.EMAIL) {
            this.messagingUtils?.sendEmail("verify-contact-otp", { totp: token }, { to: alias.alias }).catch((err) => {
                this.logger?.debug(`[BaseAliasRoute] Failed to send verification e-mail: ${err}`);
            });
        } else if (alias.type === AliasType.PHONE) {
            this.messagingUtils?.sendSMS("verify-contact-otp", { totp: token }, { to: alias.alias }).catch((err) => {
                this.logger?.debug(`[BaseAliasRoute] Failed to send verification SMS: ${err}`);
            });
        }

        if (process.env.environment !== "production") {
            this.logger?.debug(`[BaseAliasRoute] verification code for ${alias.alias}: ${token}`);
        }
    }

    // Note: We intentionallty do not allow updating. If a change is required, an alias should be removed and
    // re-added new.
    public update(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<T> {
        throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
    }

    // Note: We intentionallty do not allow updating. If a change is required, an alias should be removed and
    // re-added new.
    public updateBulk(obj: UpdateObject<T>[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T[]> {
        throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
    }

    // Note: We intentionallty do not allow updating. If a change is required, an alias should be removed and
    // re-added new.
    public updateProperty(
        @Param("id") id: string,
        @Param("propertyName") propertyName: string,
        obj: any,
        @User user?: JWTUser,
    ): Promise<T> {
        throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
    }

    /**
     * Verifies the alias using the one-time code sent automatically when it was created (see
     * `sendVerificationCode`), flipping its `verified` flag to `true`.
     */
    @Summary("Verify an Alias")
    @Description("Verifies an alias' contact using its previously-sent one-time code.")
    @Returns([Object])
    @Post("/:id/verify")
    public async verifyContact(
        @Param("id") id: string,
        obj: { token?: string },
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<T> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        // `user` must be passed here — without it, RepoUtils.findOne()'s ACL check runs as an anonymous
        // request. Alias's class-level ACL deliberately does not grant READ to `.*` (see the comment on
        // `find()` above), so an anonymous-context lookup always 403s here even for the record's own owner.
        const alias = await this.repoUtils.findOne(id, { user });
        if (!alias) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }

        await this.rateLimiter?.checkAndIncrement(alias.alias);

        let valid = false;
        try {
            valid = await verifyOTP(req, { id: alias.alias, token: obj?.token });
        } catch {
            valid = false;
        }
        if (!valid) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Invalid or expired verification code.");
        }

        return await this.repoUtils.update({ uid: alias.uid, version: alias.version, verified: valid } as any, alias, {
            user,
        });
    }
}

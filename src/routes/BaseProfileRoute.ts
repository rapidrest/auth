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
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { Contact, ContactType, Profile } from "../models/types.js";
import { ApiError, JWTUser, MessagingUtils, ObjectDecorators, UserUtils } from "@rapidrest/core";
import { generateOTP, verifyOTP } from "../auth/shared.js";
import { RateLimiter } from "../auth/RateLimiter.js";

const { Config, Inject, Logger } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Auth, Delete, Get, Param, Post, Put, Query, Request, User, Validate } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseProfileRoute<T extends Profile> extends CRUDRoute<T> {
    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Logger
    protected logger: any;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    public async create(obj: T | T[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T | T[]> {
        const result = await super.create(obj, req, user);
        const results: T[] = Array.isArray(result) ? result : [result];
        for (const r of results) {
            if (r.contacts) {
                try {
                    await this.sendContactsVerification(req, [], r.contacts);
                } catch (err) {
                    this.logger?.debug(`[BaseProfileRoute] Failed to send contact verification: ${err}`);
                }
            }
        }
        return result;
    }

    /**
     * This function is overridden because a `Profile`'s `uid` is intentionally the same value as its owning
     * `User`'s `uid`. The generic per-document ACL system keys `AccessControlList` rows by bare `uid` with no
     * per-class namespace, so a `User` and its own `Profile` permanently collide on the same ACL row: whichever
     * one creates it first "owns" that row's `parentUid`, and the other's owner-grant can never actually take
     * effect. A `Profile` is never shared with a third party, ownership is always exactly "is this the
     * caller's own uid, or a trusted role". So operation verifies that directly (via `resolveOwnedUid`) and then
     * bypasses the generic ACL check with `ignoreACL`.
     */
    @Summary("Delete Profile by ID")
    @Description("Deletes a single Profile that the caller owns, or any Profile if the caller holds a trusted role.")
    public async delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<void> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const targetUid = this.resolveOwnedUid(id, user);
        const existing = await this.repoUtils.findOne(targetUid, { version, user, ignoreACL: true });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }
        await this.repoUtils.delete(existing.uid, { user, ignoreACL: true, purge: purge === "true", version });
    }

    /**
     * This function is overridden for the same reason as `delete()`/`findById()`/`update()`: a `Profile`'s
     * `uid` collides with its owning `User`'s `uid` on the shared per-record ACL system, so it can't be relied
     * on here either. Non-trusted callers are scoped directly to their own uid (`Profile` is never shared with
     * a third party, so that's always exactly the caller's entire result set) and the generic ACL check is
     * bypassed with `ignoreACL`.
     */
    @Summary("Find Profiles")
    @Description("Returns the caller's own Profile, or all Profiles if the caller holds a trusted role.")
    public async find(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<T[]> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        const searchQuery: any = { ...query, ...params };
        if (!UserUtils.hasRoles(user, this.trustedRoles)) {
            searchQuery.uid = user.uid;
        }
        return await this.repoUtils.find(searchQuery, {
            limit: query?.limit,
            page: query?.page,
            version: params?.version || query?.version,
            user,
            ignoreACL: true,
        });
    }

    /**
     * This function is overridden because a `Profile`'s `uid` is intentionally the same value as its owning
     * `User`'s `uid`. The generic per-document ACL system keys `AccessControlList` rows by bare `uid` with no
     * per-class namespace, so a `User` and its own `Profile` permanently collide on the same ACL row: whichever
     * one creates it first "owns" that row's `parentUid`, and the other's owner-grant can never actually take
     * effect. A `Profile` is never shared with a third party, ownership is always exactly "is this the
     * caller's own uid, or a trusted role". So operation verifies that directly (via `resolveOwnedUid`) and then
     * bypasses the generic ACL check with `ignoreACL`.
     */
    @Summary("Find Profile by ID")
    @Description("Returns a single Profile that the caller owns, or any Profile if the caller holds a trusted role.")
    public async findById(@Param("id") id: string, @Query() query: any, @User user?: JWTUser): Promise<T | null> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const targetUid = this.resolveOwnedUid(id, user);
        const result = await this.repoUtils.findOne(targetUid, {
            version: query?.version,
            user,
            ignoreACL: true,
        });
        if (!result) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }
        return result;
    }

    /**
     * Requests a verification code be sent for the contact with the given value.
     * @param id The unique identifier of the Profile the contact belongs to.
     * @param contactId The contact value (e-mail/phone) to send a verification code to.
     * @param req The HTTP request being processed.
     * @param user The authenticated user making the request.
     */
    @Summary("Request Verification Code")
    @Description("Requests a verification code be sent to the contact with the given value.")
    @Auth(["jwt"])
    @Get(":id/contacts/sendCode")
    public async requestVerificationCode(
        @Param("id") id: string,
        @Query("contact") contactId: string,
        @Query() query: any,
        @Request req: HttpRequest,
        @User user: JWTUser,
    ): Promise<void> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const targetUid = this.resolveOwnedUid(id, user);
        const existing = await this.repoUtils.findOne(targetUid, {
            version: query?.version,
            user,
            ignoreACL: true,
        });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }

        for (const contact of existing.contacts) {
            if (contact.contact === contactId) {
                await this.sendVerificationCode(contact, req);
            }
        }
    }

    /**
     * Resolves `id` (handling the `"me"` keyword) and verifies the caller either owns the targeted Profile
     * (`targetUid === user.uid`) or holds a trusted role. Throws `401`/`403` otherwise.
     */
    protected resolveOwnedUid(id: string, user?: JWTUser): string {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }
        const targetUid: string = id.toLowerCase() === "me" ? user.uid : id;
        if (targetUid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }
        return targetUid;
    }

    /**
     * Sends a one-time verification code to any contact in `next` that is unverified and wasn't already
     * present (by `contact`+`type`) in `previous` — i.e. a genuinely new, unverified addition, not a
     * resave of an unrelated profile field. Mirrors `BaseRegistrationRoute.start()`'s OTP issuance.
     *
     * NOTE: `generateOTP`'s session state (`req.session.id/secret/token`) is a single unnamespaced slot
     * shared with login-OTP and registration-OTP — if `next` contains more than one newly-added unverified
     * contact, only the last one processed remains verifiable in this session. Callers are expected to add
     * one contact at a time (matches this session's existing framework-wide limitation, not fixed here).
     */
    protected async sendContactsVerification(req: HttpRequest, previous: Contact[], next: Contact[]): Promise<void> {
        const isNew = (c: Contact): boolean => !previous.some((p) => p.contact === c.contact && p.type === c.type);

        for (const contact of next) {
            if (contact.verified || !isNew(contact)) {
                continue;
            }

            await this.sendVerificationCode(contact, req);
        }
    }

    /**
     * Sends a one-time verification code to the unverified contact.
     */
    protected async sendVerificationCode(contact: Contact, req: HttpRequest): Promise<void> {
        if (contact.verified) {
            return;
        }

        await this.rateLimiter?.checkAndIncrement(contact.contact, req);
        const token = await generateOTP(req, { id: contact.contact });

        if (contact.type === ContactType.EMAIL) {
            this.messagingUtils
                ?.sendEmail("verify-contact-otp", { totp: token }, { to: contact.contact })
                .catch((err) => {
                    this.logger?.debug(`[BaseProfileRoute] Failed to send verification e-mail: ${err}`);
                });
        } else if (contact.type === ContactType.PHONE) {
            this.messagingUtils
                ?.sendSMS("verify-contact-otp", { totp: token }, { to: contact.contact })
                .catch((err) => {
                    this.logger?.debug(`[BaseProfileRoute] Failed to send verification SMS: ${err}`);
                });
        }

        if (process.env.environment !== "production") {
            this.logger?.debug(`[BaseProfileRoute] verification code for ${contact.contact}: ${token}`);
        }
    }

    /**
     * This function is overridden because a `Profile`'s `uid` is intentionally the same value as its owning
     * `User`'s `uid`. The generic per-document ACL system keys `AccessControlList` rows by bare `uid` with no
     * per-class namespace, so a `User` and its own `Profile` permanently collide on the same ACL row: whichever
     * one creates it first "owns" that row's `parentUid`, and the other's owner-grant can never actually take
     * effect. A `Profile` is never shared with a third party, ownership is always exactly "is this the
     * caller's own uid, or a trusted role". So operation verifies that directly (via `resolveOwnedUid`) and then
     * bypasses the generic ACL check with `ignoreACL`.
     */
    @Summary("Update Profile by ID")
    @Description("Updates a single Profile that the caller owns, or any Profile if the caller holds a trusted role.")
    public async update(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<T> {
        // validateUpdate() (via @Validate above) has already verified ownership. `this.repoUtils` is used
        // directly rather than `super.doUpdate()` because the latter's internal `findOne()` pre-fetch is
        // itself ACL-gated and would hit the same collision this override exists to avoid.
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }
        const targetUid = user && id.toLowerCase() === "me" ? user.uid : id;
        const existing = await this.repoUtils.findOne(targetUid, { skipCache: true, user, ignoreACL: true });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }
        const updated = await this.repoUtils.update(obj, existing, { user, ignoreACL: true });

        // Only fires for genuinely new, unverified contacts (see sendContactsVerification) — a save
        // that doesn't touch `contacts` at all, or only touches already-verified/pre-existing ones, is a
        // no-op here. Failure to send (e.g. rate-limited) must not fail the profile update itself.
        if (obj.contacts) {
            try {
                await this.sendContactsVerification(req, existing.contacts ?? [], obj.contacts);
            } catch (err) {
                this.logger?.debug(`[BaseProfileRoute] Failed to send contact verification: ${err}`);
            }
        }

        return updated;
    }

    /**
     * Verifies a pending contact using the one-time code sent automatically when it was added (see
     * `sendContactsVerification`), flipping its `verified` flag to `true`. There is no separate
     * "start"/resend endpoint — a caller who needs a fresh code removes and re-adds the contact via
     * `PUT /:id` instead, which re-triggers the same send.
     *
     * The contact value is taken from the request body rather than a `:contact` path segment
     * deliberately: the uWS HTTP adapter's route-parameter extraction (`getParameter()`) does not
     * URL-decode path segments the way this framework's query-string/cookie parsing does, so a contact
     * containing `@`/`+`/etc. (i.e. every email or phone number) would arrive at the handler still
     * percent-encoded and never match the stored value. Query/body values don't have this problem.
     */
    @Summary("Verify a Profile contact")
    @Description("Verifies a pending contact using its previously-sent one-time code.")
    @Returns([Object])
    @Post("/:id/contacts/verify")
    public async verifyContact(
        @Param("id") id: string,
        obj: { contact?: string; token?: string },
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<T> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const contact = obj?.contact;
        if (!contact) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A 'contact' is required.");
        }

        const targetUid = this.resolveOwnedUid(id, user);
        const existing = await this.repoUtils.findOne(targetUid, { skipCache: true, user, ignoreACL: true });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }

        const contacts: Contact[] = existing.contacts ?? [];
        const index = contacts.findIndex((c) => c.contact === contact);
        if (index < 0) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, "No such contact on this Profile.");
        }

        await this.rateLimiter?.checkAndIncrement(contact, req);

        let valid = false;
        try {
            valid = await verifyOTP(req, { id: contact, token: obj?.token });
        } catch {
            valid = false;
        }
        if (!valid) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Invalid or expired verification code.");
        }

        const updatedContacts = contacts.map((c, i) => (i === index ? { ...c, verified: true } : c));
        return await this.repoUtils.update(
            { uid: existing.uid, version: existing.version, contacts: updatedContacts } as any,
            existing,
            { user, ignoreACL: true },
        );
    }

    protected async validateCreate(obj: Partial<T>, user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateCreate(obj, user);

        if (!obj.uid) {
            obj.uid = user.uid;
        } else if (obj.uid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        // Same reasoning as the `contacts[].verified` reconciliation in `validateUpdate()` below: a contact's
        // `verified` flag must only ever flip via `verifyContact()`'s real OTP check, never via a
        // client-supplied value here. There's no pre-existing record to reconcile against on create (it's
        // brand new), so every contact simply starts unverified.
        if (obj.contacts) {
            obj.contacts = obj.contacts.map((c) => ({ ...c, verified: false }));
        }
    }

    protected async validateUpdate(id: string, obj: UpdateObject<T>, user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateUpdate(id, obj, user);

        // Compare against `id` (the record actually being targeted), not `obj.uid`. Checking `obj.uid` only
        // caught a caller trying to reassign ownership, but did nothing when the payload simply omitted
        // `uid` entirely (e.g. `PUT /profile/:id/:property`, which never includes it) - letting anyone
        // modify any other field of a profile they don't own.
        const targetUid = this.resolveOwnedUid(id, user);

        // A contact's `verified` flag must only ever flip via `verifyContact()`'s real OTP check (or
        // stay whatever it already was) - never via a client-supplied value here, which would let anyone
        // self-verify an email/phone they don't own and pre-empt the real owner's registration (see
        // `BaseAliasRoute.isVerifiedContact()` / `BaseRegistrationRoute.start()`). Reconcile rather than
        // reject the whole request so a legitimate update (e.g. adding a genuinely new, unverified
        // contact) still goes through.
        if (obj.contacts) {
            const existing = await this.repoUtils?.findOne(targetUid, { ignoreACL: true, user, skipCache: true });
            const existingContacts = existing?.contacts ?? [];
            obj.contacts = obj.contacts.map((c) => {
                const match = existingContacts.find((e) => e.contact === c.contact && e.type === c.type);
                return { ...c, verified: match ? match.verified : false };
            });
        }
    }

    // Note: We intentionallty do not allow updating properties directly.
    public updateProperty(
        @Param("id") id: string,
        @Param("propertyName") propertyName: string,
        obj: any,
        @User user?: JWTUser,
    ): Promise<T> {
        throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
    }
}

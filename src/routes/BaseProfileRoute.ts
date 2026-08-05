///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
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
import { Profile } from "../models/types.js";
import { ApiError, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";

const { Config } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Delete, Get, Param, Put, Query, Request, User, Validate } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseProfileRoute<T extends Profile> extends CRUDRoute<T> {
    /**
     * The set of roles that are trusted to create an Alias on behalf of another user (i.e. specify a
     * `userUid` that differs from their own). Matches the `trusted_roles` convention used elsewhere in the
     * framework (see `@rapidrest/service-core`'s `ACLUtils`/`ModelRoute`/`RepoUtils`).
     */
    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

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
    @Returns([null])
    @Delete("/:id")
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
    @Returns([[Array, Object]])
    @Get()
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
    @Returns([Object])
    @Get("/:id")
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
    @Returns([Object])
    @Put("/:id")
    @Validate("validateUpdate")
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
        return await this.repoUtils.update(obj, existing, { user, ignoreACL: true });
    }

    protected async validateCreate(obj: Partial<T> | Partial<T>[], user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateCreate(obj, user);

        const objs: Partial<T>[] = Array.isArray(obj) ? obj : [obj];
        for (const o of objs) {
            if (!o.uid) {
                o.uid = user.uid;
            } else if (o.uid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
                throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
            }
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
        this.resolveOwnedUid(id, user);
    }
}

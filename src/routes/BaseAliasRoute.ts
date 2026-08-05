///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ApiErrorMessages,
    ApiErrors,
    CRUDRoute,
    DocDecorators,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { ApiError, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";
import { Alias } from "../models/types.js";

const { Config } = ObjectDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAliasRoute<T extends Alias> extends CRUDRoute<T> {
    /**
     * The set of roles that are trusted to create an Alias on behalf of another user (i.e. specify a
     * `userUid` that differs from their own). Matches the `trusted_roles` convention used elsewhere in the
     * framework (see `@rapidrest/service-core`'s `ACLUtils`/`ModelRoute`/`RepoUtils`).
     */
    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    protected async validateCreate(obj: Partial<T> | Partial<T>[], user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateCreate(obj, user);

        const objs: Partial<T>[] = Array.isArray(obj) ? obj : [obj];
        for (const o of objs) {
            if (!o.userUid) {
                o.userUid = user.uid;
            } else if (o.userUid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
                throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
            }
        }
    }

    protected async validateUpdate(id: string, obj: UpdateObject<T>, user?: JWTUser): Promise<void> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, ApiErrorMessages.AUTH_REQUIRED);
        }

        await super.validateUpdate(id, obj, user);

        if (UserUtils.hasRoles(user, this.trustedRoles)) {
            return;
        }

        // Unlike Profile, an alias's `id` (its own identifier) isn't the owning user's uid, so we can't tell
        // who owns it from `id`/`obj` alone. Look up the existing record so a caller can't dodge the
        // ownership check simply by leaving `userUid` out of the update payload (e.g. via
        // `PUT /alias/:id/:property`, which updates a single field without ever including it).
        const existing: Partial<T> | undefined = await this.repoUtils?.findOne(id, { ignoreACL: true });
        if (existing && existing.userUid !== user.uid) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        if ("userUid" in obj && obj.userUid !== user.uid) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }
    }
}

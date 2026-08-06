///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ACLAction,
    ApiErrorMessages,
    ApiErrors,
    CRUDRoute,
    DocDecorators,
    HttpRequest,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { ApiError, JWTUser, UserUtils } from "@rapidrest/core";
import { User } from "../models/types.js";

const { Param, Request, User: AuthUser } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseUserRoute<T extends User> extends CRUDRoute<T> {
    // This function is overridden because `RepoUtils.create()`'s automatic per-record owner grant is keyed
    // off the *acting* caller (`options.user`) and is deliberately skipped whenever that caller holds a
    // trusted role. That's fine for Alias/Secret/Profile, which are normally self-service created by their
    // own eventual owner, but a `User` provisioned by an admin has no such self-service creator: the acting
    // admin is (correctly) excluded from the grant, but nobody else ever gets one either, so the newly
    // provisioned user would be locked out of their own account until an admin manually fixed their ACL.
    public async create(obj: T | T[], @Request req: HttpRequest, @AuthUser user?: JWTUser): Promise<T | Array<T>> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        if (Array.isArray(obj)) {
            const results: T[] = [];
            for (const o of obj) {
                results.push((await this.create(o, req, user)) as T);
            }
            return results;
        }

        const newUser: T = this.repoUtils.instantiateObject(obj);
        return await super.doCreate(newUser, {
            req,
            user,
            acl: {
                uid: newUser.uid,
                records: [
                    {
                        userOrRoleId: newUser.uid,
                        actions: [
                            ACLAction.COUNT,
                            ACLAction.CREATE,
                            ACLAction.DELETE,
                            ACLAction.EXISTS,
                            ACLAction.READ,
                            ACLAction.LIST,
                            ACLAction.TRUNCATE,
                            ACLAction.UPDATE,
                        ],
                    },
                ],
            },
        });
    }

    protected async validateCreate(obj: Partial<T>, user?: JWTUser): Promise<void> {
        await super.validateCreate(obj, user);

        // Only trusted users can set a user's roles
        if ("roles" in obj && !UserUtils.hasRoles(user, this.trustedRoles)) {
            obj.roles = [];
        }
    }

    protected async validateUpdate(id: string, obj: UpdateObject<T>, user?: JWTUser): Promise<void> {
        await super.validateUpdate(id, obj, user);

        // Only trusted users can modify a user's roles
        if ("roles" in obj && !UserUtils.hasRoles(user, this.trustedRoles)) {
            const targetUid = user && id.toLowerCase() === "me" ? user.uid : id;
            const existing = await this.repoUtils?.findOne(targetUid, { ignoreACL: true });
            obj.roles = existing?.roles;
        }
    }

    // Note: We intentionallty do not allow updating properties directly.
    public updateProperty(
        @Param("id") id: string,
        @Param("propertyName") propertyName: string,
        obj: any,
        @AuthUser user?: JWTUser,
    ): Promise<T> {
        throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
    }
}

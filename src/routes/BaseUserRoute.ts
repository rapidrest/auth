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
} from "@rapidrest/service-core";
import { ApiError, JWTUser } from "@rapidrest/core";
import { User } from "../models/types.js";

const { Description, Returns, Summary } = DocDecorators;
const { Post, Request, User: AuthUser, Validate } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseUserRoute<T extends User> extends CRUDRoute<T> {
    /**
     * This function is overridden because `RepoUtils.create()`'s automatic per-record owner grant is keyed
     * off the *acting* caller (`options.user`) and is deliberately skipped whenever that caller holds a
     * trusted role. That's fine for Alias/Secret/Profile, which are normally self-service created by their
     * own eventual owner, but a `User` provisioned by an admin has no such self-service creator: the acting
     * admin is (correctly) excluded from the grant, but nobody else ever gets one either, so the newly
     * provisioned user would be locked out of their own account until an admin manually fixed their ACL —
     * the same failure mode `BaseRegistrationRoute.verify()` had for self-registration. `uid` is generated
     * client-side by the entity constructor (see `BaseEntity`), so the new object's `uid` is known before
     * `create()` is called and is used here to seed its own owner grant directly.
     */
    @Summary("Create {{model}}(s)")
    @Description("Create a new {{model}}.")
    @Returns([Object])
    @Post()
    @Validate("validateCreateBulk")
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
}

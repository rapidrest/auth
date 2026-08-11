///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ACLAction,
    ApiErrorMessages,
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ModelRoute,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { ApiError, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";
import { AuthResult, User } from "../models/types.js";
import { TokenUtils } from "../auth/TokenUtils.js";

const { Description, Returns, Summary } = DocDecorators;
const { Config, Inject } = ObjectDecorators;
const {
    Auth,
    Delete,
    Get,
    Head,
    Param,
    Post,
    Put,
    Query,
    RequiresElevation,
    Request,
    Response,
    User: AuthUser,
    Validate,
} = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseUserRoute<T extends User> extends ModelRoute<T> {
    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected authConfig?: any;

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    @Summary("Count Users")
    @Description(
        "Returns the total count of Users in the datastore based on the given criteria " +
            "in the header as `Content-Length`.",
    )
    @Returns([null])
    @Auth(["jwt"])
    @Head()
    public async count(
        @Param() params: any,
        @Query() query: any,
        @Response res: HttpResponse,
        @AuthUser user?: JWTUser,
    ): Promise<any> {
        return await super.doCount({ params, query, res, user });
    }

    protected async validateCreate(obj: Partial<T>, user?: JWTUser): Promise<void> {
        await super.validate(obj, { user });

        // Only trusted users can set a user's roles
        if ("roles" in obj && !UserUtils.hasRoles(user, this.trustedRoles)) {
            obj.roles = [];
        }

        // Only trusted users can modify a user's verified status
        if ("verified" in obj && !UserUtils.hasRoles(user, this.trustedRoles)) {
            obj.verified = false;
        }

        // If the server requires MFA for all accounts, make sure it is set/enforced
        obj.requireMFA = this.authConfig.require_mfa ?? obj.requireMFA;
    }

    @Summary("Create User")
    @Description("Create a new User.")
    @Returns([Object])
    @Post()
    public async create(
        obj: T,
        @Request req: HttpRequest,
        @Response res: HttpResponse,
        @AuthUser user?: JWTUser,
    ): Promise<AuthResult> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }
        if (!this.tokenUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        await this.validateCreate(obj, user);

        const newUser: T = this.repoUtils.instantiateObject(obj);
        const result: T = (await super.doCreate(newUser, {
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
        })) as T;

        // When creation is being performed by another user (e.g. an admin) we don't need to generate
        // an access token. So just return an empty result.
        if (user) {
            return {
                refresh: "",
                token: "",
                user: result,
            };
        } else {
            // New accounts always get an elevated token in order to ensure that they can safely create
            // secrets (e.g. MFA setup) needed to maintain account access.
            return await this.tokenUtils.createAuthResult(result, this.defaultScopes, req, res, true);
        }
    }

    @Summary("Delete {{name}} by ID")
    @Description("Deletes the {{name}} from the service.")
    @Returns([null])
    @Auth(["jwt"])
    @Delete("/:id")
    @RequiresElevation(60)
    public async delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @AuthUser user?: JWTUser,
    ): Promise<void> {
        return await super.doDelete(id, { user, req, version, purge: purge === "true" });
    }

    @Summary("Exists")
    @Description(
        "Returns the total count of {{name}}s in the datastore based on the given criteria " +
            "in the header as `Content-Length`.",
    )
    @Returns([null])
    @Auth(["jwt"])
    @Head("/:id")
    public async exists(
        @Param("id") id: string,
        @Query() query: any,
        @Response res: HttpResponse,
        @AuthUser user?: JWTUser,
    ): Promise<any> {
        return await super.doExists(id, { query, res, user });
    }

    @Summary("Find All Users")
    @Description("Returns all Users from the system that the user has access to.")
    @Returns([[Array, Object]])
    @Auth(["jwt"])
    @Get()
    public async find(@Param() params: any, @Query() query: any, @AuthUser user?: JWTUser): Promise<Array<T>> {
        return await super.doFind({ params, query, user });
    }

    @Summary("Find User by ID")
    @Description("Returns a single User from the system that the user has access to.")
    @Returns([Object])
    @Auth(["jwt"])
    @Get("/:id")
    public async findById(@Param("id") id: string, @Query() query: any, @AuthUser user?: JWTUser): Promise<T | null> {
        return await super.doFindById(id, { query, user });
    }

    @Summary("Truncate Users")
    @Description("Deletes all Users from the datastore that the user has access to.")
    @Returns([null])
    @Auth(["jwt"])
    @Delete()
    @RequiresElevation(60)
    public async truncate(@Param() params: any, @Query() query: any, @AuthUser user?: JWTUser): Promise<void> {
        return await super.doTruncate({ params, query, user });
    }

    protected async validateUpdate(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @AuthUser user?: JWTUser,
    ): Promise<void> {
        await this.validate(obj, { user });

        const isTrusted = UserUtils.hasRoles(user, this.trustedRoles);
        const targetUid = user && id.toLowerCase() === "me" ? user.uid : id;
        const existing = await this.repoUtils!.findOne(targetUid, { ignoreACL: true });

        // Only trusted users can modify a user's roles
        if ("roles" in obj && !isTrusted) {
            obj.roles = existing?.roles ?? [];
        }

        // Only trusted users can flip a user's verified status from false to true. Lowering it (or
        // resubmitting a value that already matches what's persisted) isn't privilege-escalating and is
        // left alone.
        if ("verified" in obj && !isTrusted && !!obj.verified && !existing?.verified) {
            obj.verified = false;
        }

        if ("requireMFA" in obj) {
            if (existing && obj.requireMFA !== existing.requireMFA) {
                // If the server requires MFA for all accounts, don't allow this to be changed, unless its by an admin
                if (this.authConfig.require_mfa) {
                    obj.requireMFA = isTrusted ? obj.requireMFA : existing.requireMFA;
                }
            }
        }
    }

    @Summary("Update User by ID")
    @Description("Updates a single User.")
    @Returns([Object])
    @Auth(["jwt"])
    @Put("/:id")
    @Validate("validateUpdate")
    @RequiresElevation(60)
    public async update(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @Request req: HttpRequest,
        @AuthUser user?: JWTUser,
    ): Promise<T> {
        return await super.doUpdate(id, obj, { user });
    }
}

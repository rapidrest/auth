///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ModelRoute,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { Secret, SecretType } from "../models/types.js";
import { ApiError, JWTUser } from "@rapidrest/core";
import { importArgon2, importOTPLib } from "../auth/shared.js";

const { Description, Returns, Summary } = DocDecorators;
const { Delete, Get, Head, Param, Post, Query, Request, Response, User, Validate } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseSecretRoute<T extends Secret> extends ModelRoute<T> {
    protected readonly repoUtilsClass: any = RepoUtils;

    /**
     * Removes the `data` property from the secret(s) to protect sensitive information.
     */
    protected cleanData(obj: T | T[]) {
        const objs: Array<T> = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            delete obj.data;
        }
    }

    @Summary("Count secrets")
    @Description(
        "Returns the total count of secrets in the datastore based on the given criteria " +
            "in the header as `Content-Length`.",
    )
    @Returns([null])
    @Head()
    public async count(
        @Param() params: any,
        @Query() query: any,
        @Response res: HttpResponse,
        @User user?: JWTUser,
    ): Promise<any> {
        return super.doCount({ params, query, res, user });
    }

    protected async validateCreate(obj: Partial<T> | Partial<T>[], user?: JWTUser): Promise<void> {
        const objs: Partial<T>[] = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            switch (obj.type) {
                case SecretType.FIDO2:
                case SecretType.OPENID:
                case SecretType.PASSKEY:
                case SecretType.PASSWORD:
                    {
                        if (typeof obj.data === "string") {
                            const argon = await importArgon2();
                            obj.data = await argon.hash(obj.data);
                        } else {
                            throw new ApiError(
                                ApiErrors.INVALID_REQUEST,
                                400,
                                "A secret of type 'password' must specify string data.",
                            );
                        }
                    }
                    break;
                case SecretType.TOTP:
                    {
                        // Allow the client to specify their own secret or we can generate one for them.
                        const { generateSecret } = await importOTPLib();
                        const secret: string = (typeof obj.data === "string" && obj.data) || generateSecret();
                        obj.data = {
                            secret,
                        };
                    }
                    break;
            }
        }
    }

    @Summary("Create Secret(s)")
    @Description("Create a new Secret.")
    @Returns([Object])
    @Post()
    @Validate("validateCreate")
    public async create(obj: T | T[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T | Array<T>> {
        const result: T | Array<T> = await super.doCreate(obj, { req, user });

        // Selectively clean data from certain types of secrets. Some secret types require the data needs to be
        // returned back to the client.
        const objs: Array<T> = Array.isArray(result) ? result : [result];
        for (const obj of objs) {
            if ([SecretType.PASSWORD].includes(obj.type)) {
                delete obj.data;
            }
        }

        return result;
    }

    @Summary("Delete secret by ID")
    @Description("Deletes the secret from the service.")
    @Returns([null])
    @Delete("/:id")
    public async delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<void> {
        return super.doDelete(id, { user, req, version, purge: purge === "true" });
    }

    @Summary("Exists")
    @Description(
        "Returns the total count of secrets in the datastore based on the given criteria " +
            "in the header as `Content-Length`.",
    )
    @Returns([null])
    @Head("/:id")
    public async exists(
        @Param("id") id: string,
        @Query() query: any,
        @Response res: HttpResponse,
        @User user?: JWTUser,
    ): Promise<any> {
        return super.doExists(id, { query, res, user });
    }

    @Summary("Find All Secrets")
    @Description("Returns all Secrets from the system that the user has access to.")
    @Returns([[Array, Object]])
    @Get()
    public async find(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<Array<T>> {
        const results: Array<T> = await super.doFind({ params, query, user });
        this.cleanData(results);
        return results;
    }

    @Summary("Find Secret by ID")
    @Description("Returns a single Secret from the system that the user has access to.")
    @Returns([Object])
    @Get("/:id")
    public async findById(@Param("id") id: string, @Query() query: any, @User user?: JWTUser): Promise<T | null> {
        const result: T | null = await super.doFindById(id, { query, user });
        if (result) {
            this.cleanData(result);
        }
        return result;
    }

    @Summary("Truncate Secrets")
    @Description("Deletes all Secrets from the datastore that the user has access to.")
    @Returns([null])
    @Delete()
    public async truncate(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<void> {
        return super.doTruncate({ params, query, user });
    }
}

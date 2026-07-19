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
import { ApiError, JWTUser, ObjectDecorators } from "@rapidrest/core";
import {
    generatePasskeyRegistrationOptions,
    importArgon2,
    importOTPLib,
    isPasskeyRegistrationResponse,
    verifyPasskeyRegistrationResponse,
} from "../auth/shared.js";
import { PasskeyConfig, StoredPasskeyCredential } from "../auth/types.js";

const { Config } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Delete, Get, Head, Param, Post, Query, Request, Response, User, Validate } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseSecretRoute<T extends Secret> extends ModelRoute<T> {
    protected readonly repoUtilsClass: any = RepoUtils;

    /**
     * The relying party configuration used for validating and generating passkey (WebAuthn) registration data.
     */
    @Config("auth:passkey")
    protected passkeyConfig: PasskeyConfig = {
        rpName: "rapidrest",
        rpID: "rapidrest",
        origin: "http://localhost:3000",
    };

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

    protected async validateCreate(
        obj: Partial<T> | Partial<T>[],
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<void> {
        const objs: Partial<T>[] = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            switch (obj.type) {
                case SecretType.FIDO2:
                case SecretType.OPENID:
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
                case SecretType.PASSKEY:
                    await this.validatePasskeyCreate(obj, req);
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

    /**
     * Verifies a client-submitted WebAuthn `RegistrationResponseJSON` (as produced by
     * `navigator.credentials.create()` using the options from `generatePasskeyRegistrationOptions()`) against
     * the challenge stored in the session, and replaces `obj.data` with the resulting `StoredPasskeyCredential`.
     *
     * Per the WebAuthn registration ceremony (https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential),
     * the credential ID must be unique across all accounts known to this relying party. Rather than duplicate that
     * check here, the credential ID is used directly as this secret's own `uid` so that `ModelRoute`'s existing
     * create-time identifier check rejects the request should the ID already be registered to any account. This
     * also lets a login ceremony, which only has the credential ID to go on, look the secret up directly by its
     * primary key (see `BaseAuthPasskeyRoute.getCredentialById`/`updateCredentialCounter`).
     *
     * @param obj The secret being created. Its `data` property must be a `RegistrationResponseJSON`.
     * @param req The source HTTP request, used to retrieve the challenge stored in the session by a prior call to
     * `generatePasskeyRegistrationOptions()`.
     */
    protected async validatePasskeyCreate(obj: Partial<T>, req: HttpRequest): Promise<void> {
        if (!req.session) {
            throw new Error(
                "Passkey secrets require session support. Configure the `session` config " +
                    "block so the session middleware is registered.",
            );
        }
        if (!req.session.challenge) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "No passkey registration ceremony in progress for this session.",
            );
        }
        if (typeof obj.userUid !== "string" || obj.userUid.length === 0) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A secret of type 'passkey' must specify a 'userUid'.");
        }

        // The challenge is single-use regardless of outcome — cleared as soon as it's read, before
        // verification is even attempted.
        const expectedChallenge: string = req.session.challenge;
        delete req.session.challenge;

        if (!isPasskeyRegistrationResponse(obj.data)) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "A secret of type 'passkey' must specify a valid WebAuthn registration response.",
            );
        }

        const result = await verifyPasskeyRegistrationResponse(this.passkeyConfig, expectedChallenge, obj.data);
        if (!result.verified || !result.registrationInfo) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Passkey registration could not be verified.");
        }

        const { credential } = result.registrationInfo;

        const storedCredential: StoredPasskeyCredential = {
            id: credential.id,
            uid: obj.userUid,
            publicKey: credential.publicKey,
            counter: credential.counter,
            transports: credential.transports,
        };

        obj.uid = credential.id;
        obj.data = storedCredential;
    }

    /**
     * Begins a WebAuthn passkey registration ceremony for the authenticated user: generates a set of
     * `PublicKeyCredentialCreationOptions` (RFC/spec compliant per https://www.w3.org/TR/webauthn-2/), scoped
     * to exclude any credentials the user already has registered, and stores the challenge in the session for
     * verification by `validatePasskeyCreate()` once the client completes the ceremony and submits a new
     * `passkey` secret.
     */
    @Summary("Generate Passkey Registration Options")
    @Description(
        "Begins a WebAuthn passkey registration ceremony for the authenticated user and returns the " +
            "`PublicKeyCredentialCreationOptions` to pass to `navigator.credentials.create()`. Submit the " +
            "resulting attestation response as the `data` of a new `passkey` secret to finish the ceremony.",
    )
    @Returns([Object])
    @Get("/passkey/register")
    public async passkeyRegistrationOptions(@Request req: HttpRequest, @User user?: JWTUser): Promise<any> {
        if (!user) {
            throw new ApiError(
                ApiErrors.AUTH_REQUIRED,
                401,
                "Authentication is required to register a passkey.",
            );
        }
        if (!this.repoUtils) {
            throw new Error("repoUtils is not set.");
        }

        const existing: T[] = await this.repoUtils.find(
            { type: SecretType.PASSKEY, userUid: user.uid },
            { ignoreACL: true, user },
        );
        const excludeCredentials = existing.map((secret) => {
            const credential: StoredPasskeyCredential = secret.data;
            return { id: credential.id, transports: credential.transports };
        });

        return await generatePasskeyRegistrationOptions(
            this.passkeyConfig,
            req,
            { id: user.uid, name: user.uid },
            excludeCredentials,
        );
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
            if ([SecretType.PASSKEY, SecretType.PASSWORD].includes(obj.type)) {
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

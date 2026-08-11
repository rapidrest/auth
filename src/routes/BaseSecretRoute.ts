///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ApiErrorMessages,
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ModelRoute,
    RepoUtils,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { Secret, SecretType } from "../models/types.js";
import { ApiError, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";
import {
    generatePasskeyRegistrationOptions,
    generateTOTPURI,
    importArgon2,
    importOTPLib,
    isPasskeyRegistrationResponse,
    isValidTOTPSecret,
    verifyPasskeyRegistrationResponse,
} from "../auth/shared.js";
import { PasskeyConfig, PasswordConfig, StoredPasskeyCredential, TOTPConfig, TOTPSecret } from "../auth/types.js";

const { Config, Init } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Auth, Delete, Get, Head, Param, Post, Put, Query, Request, RequiresElevation, Response, User, Validate } =
    RouteDecorators;

const REGEX_LOWERCASE = new RegExp("^.*[a-z]+.*$");
const REGEX_NUMERAL = new RegExp("^.*[0-9]+.*$");
const REGEX_UPPERCASE = new RegExp("^.*[A-Z]+.*$");

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseSecretRoute<T extends Secret> extends ModelRoute<T> {
    protected readonly repoUtilsClass: any = RepoUtils;
    protected regexSpecialChars: RegExp = new RegExp("^.*[" + new PasswordConfig().special_chars + "]+.*$");

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
     * The relying party configuration used for validating and generating FIDO2 hardware security key
     * (WebAuthn) registration data. Kept separate from `passkeyConfig` since a hardware key deployment
     * commonly wants a different `authenticatorAttachment`/`residentKey` policy — a hardware key is
     * typically registered as a `"cross-platform"`, non-discoverable credential tied to a known
     * account, rather than a discoverable, possibly-synced passkey.
     */
    @Config("auth:fido2")
    protected fido2Config: PasskeyConfig = {
        rpName: "rapidrest",
        rpID: "rapidrest",
        origin: "http://localhost:3000",
        authenticatorAttachment: "cross-platform",
        residentKey: "discouraged",
    };

    /**
     * The issuer configuration used for validating and generating TOTP (RFC 6238) registration data.
     */
    @Config("auth:totp")
    protected totpConfig: TOTPConfig = {
        issuer: "rapidrest",
        digits: 6,
        period: 30,
        algorithm: "sha1",
        epochTolerance: [1, 1],
    };

    /**
     * The minimum required length for a new `password` secret's plaintext value.
     */
    @Config("auth:password", new PasswordConfig())
    protected passwordConfig: PasswordConfig = new PasswordConfig();

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Init
    private init() {
        this.regexSpecialChars = new RegExp("^.*[" + this.passwordConfig.special_chars + "]+.*$");
    }

    /**
     * Ensures the `userUid` of a secret being created belongs to the authenticated caller, defaulting it to
     * their own uid when unset. Prevents any authenticated user from self-service registering a password,
     * passkey, FIDO2 key, or TOTP secret on another user's account. Callers with one of `trustedRoles` (e.g.
     * an administrator provisioning an account) are exempt.
     */
    protected enforceOwnership(obj: Partial<T>, user?: JWTUser): void {
        if (!user) {
            return;
        }
        if (!obj.userUid) {
            obj.userUid = user.uid;
        } else if (obj.userUid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }
    }

    /**
     * Removes the `data` property from the secret(s) to protect sensitive information.
     */
    protected cleanData(obj: T | T[]) {
        const objs: Array<T> = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            delete obj.data;
        }
    }

    @Auth(["jwt"])
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
        @User user: JWTUser,
    ): Promise<any> {
        return super.doCount({ params, query, res, user });
    }

    protected async validateCreate(obj: Partial<T>, @Request req: HttpRequest, @User user?: JWTUser): Promise<void> {
        await super.validate(obj, { user });

        this.enforceOwnership(obj, user);

        switch (obj.type) {
            case SecretType.FIDO2:
                await this.validateWebAuthnCreate(obj, req, this.fido2Config);
                break;
            case SecretType.PASSKEY:
                await this.validateWebAuthnCreate(obj, req, this.passkeyConfig);
                break;
            case SecretType.PASSWORD:
                {
                    if (typeof obj.data === "string") {
                        this.validatePassword(obj.data);
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
                await this.validateTOTPCreate(obj);
                break;
        }
    }

    private validatePassword(password: string) {
        if (password.length < this.passwordConfig.min_length) {
            throw new ApiError(
                ApiErrorMessages.INVALID_REQUEST,
                400,
                `Password must have a minimum length of: ${this.passwordConfig.min_length}`,
            );
        }

        if (this.passwordConfig.require_lowercase && !password.match(REGEX_LOWERCASE)) {
            throw new ApiError(
                ApiErrorMessages.INVALID_REQUEST,
                400,
                `Password must have at least one lowercase letter`,
            );
        }

        if (this.passwordConfig.require_uppercase && !password.match(REGEX_UPPERCASE)) {
            throw new ApiError(
                ApiErrorMessages.INVALID_REQUEST,
                400,
                `Password must have at least one uppercase letter`,
            );
        }

        if (this.passwordConfig.require_numeral && !password.match(REGEX_NUMERAL)) {
            throw new ApiError(ApiErrorMessages.INVALID_REQUEST, 400, `Password must have at least one number`);
        }

        if (this.passwordConfig.require_special && !password.match(this.regexSpecialChars)) {
            throw new ApiError(
                ApiErrorMessages.INVALID_REQUEST,
                400,
                `Password must have at least one special character: ${this.passwordConfig.special_chars}`,
            );
        }
    }

    /**
     * Verifies a client-submitted WebAuthn `RegistrationResponseJSON` (as produced by
     * `navigator.credentials.create()` using the options from `generatePasskeyRegistrationOptions()`) against
     * the challenge stored in the session, and replaces `obj.data` with the resulting `StoredPasskeyCredential`.
     *
     * Shared by both `passkey` and `fido2` secrets — the two differ only in relying party configuration
     * (see `passkeyConfig`/`fido2Config`) and which `SecretType` they're persisted under, not in the
     * underlying WebAuthn ceremony.
     *
     * Per the WebAuthn registration ceremony (https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential),
     * the credential ID must be unique across all accounts known to this relying party. Rather than duplicate that
     * check here, the credential ID is used directly as this secret's own `uid` so that `ModelRoute`'s existing
     * create-time identifier check rejects the request should the ID already be registered to any account. This
     * also lets a login ceremony, which only has the credential ID to go on, look the secret up directly by its
     * primary key (see `BaseAuthPasskeyRoute`/`BaseAuthFIDO2Route`'s `getCredentialById`/`updateCredentialCounter`).
     *
     * @param obj The secret being created. Its `data` property must be a `RegistrationResponseJSON`.
     * @param req The source HTTP request, used to retrieve the challenge stored in the session by a prior call to
     * `generatePasskeyRegistrationOptions()`.
     * @param config The relying party configuration to verify the response against.
     */
    protected async validateWebAuthnCreate(obj: Partial<T>, req: HttpRequest, config: PasskeyConfig): Promise<void> {
        if (!req.session) {
            throw new Error(
                "This secret type requires session support. Configure the `session` config " +
                    "block so the session middleware is registered.",
            );
        }
        if (!req.session.challenge) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "No WebAuthn registration ceremony in progress for this session.",
            );
        }
        if (typeof obj.userUid !== "string" || obj.userUid.length === 0) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "This secret type must specify a 'userUid'.");
        }

        // The challenge is single-use regardless of outcome — cleared as soon as it's read, before
        // verification is even attempted.
        const expectedChallenge: string = req.session.challenge;
        delete req.session.challenge;

        if (!isPasskeyRegistrationResponse(obj.data)) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "This secret type must specify a valid WebAuthn registration response.",
            );
        }

        const result = await verifyPasskeyRegistrationResponse(config, expectedChallenge, obj.data);
        if (!result.verified || !result.registrationInfo) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "WebAuthn registration could not be verified.");
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
     * Validates (or generates) the secret for a new `totp` secret per RFC 6238/RFC 4226.
     *
     * The client may either bring their own Base32-encoded secret (e.g. one generated on a
     * different server for migration purposes) or, more commonly, omit `data` entirely and have one
     * generated here. Either way, the secret's token parameters (`digits`/`period`/`algorithm`) are
     * captured onto the stored `TOTPSecret` alongside it, rather than left to always defer to
     * `totpConfig`, so verification keeps working for this secret even if the configured defaults
     * change later.
     *
     * @param obj The secret being created. If `data` is a string, it's used as the caller-supplied
     * secret; otherwise a new one is generated.
     */
    protected async validateTOTPCreate(obj: Partial<T>): Promise<void> {
        const { generateSecret } = await importOTPLib();

        let secret: string;
        if (obj.data !== undefined) {
            if (typeof obj.data !== "string" || !(await isValidTOTPSecret(obj.data))) {
                throw new ApiError(
                    ApiErrors.INVALID_REQUEST,
                    400,
                    "A secret of type 'totp' must be a Base32-encoded string of at least 128 bits.",
                );
            }
            secret = obj.data;
        } else {
            secret = generateSecret();
        }

        const totpSecret: TOTPSecret = {
            secret,
            digits: this.totpConfig.digits,
            period: this.totpConfig.period,
            algorithm: this.totpConfig.algorithm,
            epochTolerance: this.totpConfig.epochTolerance,
        };
        obj.data = totpSecret;
    }

    /**
     * Begins a WebAuthn registration ceremony for the authenticated user: generates a set of
     * `PublicKeyCredentialCreationOptions` (RFC/spec compliant per https://www.w3.org/TR/webauthn-2/), scoped
     * to exclude any credentials of the given type the user already has registered, and stores the challenge
     * in the session for verification by `validateWebAuthnCreate()` once the client completes the ceremony
     * and submits a new secret of that type. Shared by both the `passkey` and `fido2` registration endpoints.
     *
     * @param req The source HTTP request. Used to persist the generated challenge in the session.
     * @param user The authenticated user the new credential will be associated with.
     * @param type The secret type being registered — `passkey` or `fido2`.
     * @param config The relying party configuration to generate options with.
     */
    private async beginWebAuthnRegistration(
        req: HttpRequest,
        user: JWTUser,
        type: SecretType,
        config: PasskeyConfig,
    ): Promise<any> {
        if (!this.repoUtils) {
            throw new Error("repoUtils is not set.");
        }

        const existing: T[] = await this.repoUtils.find({ type, userUid: user.uid }, { ignoreACL: true, user });
        const excludeCredentials = existing.map((secret) => {
            const credential: StoredPasskeyCredential = secret.data;
            return { id: credential.id, transports: credential.transports };
        });

        return await generatePasskeyRegistrationOptions(
            config,
            req,
            { id: user.uid, name: user.uid },
            excludeCredentials,
        );
    }

    @Auth(["jwt"])
    @Summary("Generate Passkey Registration Options")
    @Description(
        "Begins a WebAuthn passkey registration ceremony for the authenticated user and returns the " +
            "`PublicKeyCredentialCreationOptions` to pass to `navigator.credentials.create()`. Submit the " +
            "resulting attestation response as the `data` of a new `passkey` secret to finish the ceremony.",
    )
    @Returns([Object])
    @Get("/passkey/register")
    @RequiresElevation()
    public async passkeyRegistrationOptions(@Request req: HttpRequest, @User user: JWTUser): Promise<any> {
        if (!user) {
            throw new ApiError(ApiErrors.AUTH_REQUIRED, 401, "Authentication is required to register a passkey.");
        }

        return this.beginWebAuthnRegistration(req, user, SecretType.PASSKEY, this.passkeyConfig);
    }

    @Summary("Password Requirements")
    @Description("Returns the requirements for creating passwords")
    @Returns([Object])
    @Get("/password")
    public async getPasswordConfig(): Promise<any> {
        return this.passwordConfig;
    }

    @Auth(["jwt"])
    @Summary("Generate FIDO2 Registration Options")
    @Description(
        "Begins a WebAuthn registration ceremony for the authenticated user's FIDO2 hardware security key and " +
            "returns the `PublicKeyCredentialCreationOptions` to pass to `navigator.credentials.create()`. Submit " +
            "the resulting attestation response as the `data` of a new `fido2` secret to finish the ceremony.",
    )
    @Returns([Object])
    @Get("/fido2/register")
    @RequiresElevation()
    public async fido2RegistrationOptions(@Request req: HttpRequest, @User user: JWTUser): Promise<any> {
        if (!user) {
            throw new ApiError(
                ApiErrors.AUTH_REQUIRED,
                401,
                "Authentication is required to register a FIDO2 security key.",
            );
        }

        return this.beginWebAuthnRegistration(req, user, SecretType.FIDO2, this.fido2Config);
    }

    @Auth(["jwt"])
    @Summary("Create Secret(s)")
    @Description("Create a new Secret.")
    @Returns([Object])
    @Post()
    @Validate("validateCreate")
    @RequiresElevation()
    public async create(obj: T | T[], @Request req: HttpRequest, @User user: JWTUser): Promise<T | Array<T>> {
        const result: T | Array<T> = await super.doCreate(obj, { req, user });

        // Selectively clean data from certain types of secrets. Some secret types require the data needs to be
        // returned back to the client.
        const objs: Array<T> = Array.isArray(result) ? result : [result];
        for (const obj of objs) {
            await this.sanitizeSecretForResponse(obj);
        }

        return result;
    }

    /**
     * Strips or augments the `data` field of a persisted secret before it is returned to the client. Shared
     * by `create()` and `update()` so that a response for either operation never leaks a `password` hash or
     * raw WebAuthn/TOTP credential material back over the wire.
     */
    private async sanitizeSecretForResponse(obj: T): Promise<T> {
        if ([SecretType.FIDO2, SecretType.PASSKEY, SecretType.PASSWORD].includes(obj.type)) {
            delete obj.data;
        } else if (obj.type === SecretType.TOTP && obj.data) {
            // The `otpauth://` provisioning URI is derived from the persisted secret rather than
            // stored itself, so it's computed fresh here for the response only.
            (obj.data as TOTPSecret & { uri: string }).uri = await generateTOTPURI(
                this.totpConfig,
                obj.userUid,
                obj.data as TOTPSecret,
            );
        }
        return obj;
    }

    @Auth(["jwt"])
    @Summary("Delete secret by ID")
    @Description("Deletes the secret from the service.")
    @Returns([null])
    @Delete("/:id")
    @RequiresElevation(60)
    public async delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @User user: JWTUser,
    ): Promise<void> {
        return super.doDelete(id, { user, req, version, purge: purge === "true" });
    }

    @Auth(["jwt"])
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
        @User user: JWTUser,
    ): Promise<any> {
        return super.doExists(id, { query, res, user });
    }

    /**
     * `Secret`'s class-level ACL intentionally does NOT grant `LIST` to `.*` — per-record ACL narrowing in
     * `RepoUtils.find()` falls back to the *parent* (class-level) ACL when a specific record has no direct
     * grant for the caller, so a class-level `.*: LIST` wildcard would make every record's per-record check
     * pass for every caller via that fallback, leaking every user's secrets to every other user. Instead,
     * self-service "list my own secrets" is handled here directly: scope the query to the caller's own
     * `userUid` (discarding any client-supplied `userUid` filter, which would otherwise let a caller probe
     * another user's secrets) and bypass ACL entirely with `ignoreACL` for that already-scoped lookup — the
     * same pattern already used internally by `beginWebAuthnRegistration()` above. A trusted role keeps the
     * normal, unscoped behavior.
     */
    @Auth(["jwt"])
    @Summary("Find All Secrets")
    @Description("Returns all Secrets the caller owns, or all Secrets if the caller holds a trusted role.")
    @Returns([[Array, Object]])
    @Get()
    public async find(@Param() params: any, @Query() query: any, @User user: JWTUser): Promise<Array<T>> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        let results: Array<T>;
        if (user && !UserUtils.hasRoles(user, this.trustedRoles)) {
            results = await this.repoUtils.find(
                { ...params, ...query, userUid: user.uid },
                { limit: query?.limit, page: query?.page, ignoreACL: true, user },
            );
        } else {
            results = await super.doFind({ params, query, user });
        }
        this.cleanData(results);
        return results;
    }

    @Auth(["jwt"])
    @Summary("Find Secret by ID")
    @Description("Returns a single Secret from the system that the user has access to.")
    @Returns([Object])
    @Get("/:id")
    public async findById(@Param("id") id: string, @Query() query: any, @User user: JWTUser): Promise<T | null> {
        const result: T | null = await super.doFindById(id, { query, user });
        if (result) {
            this.cleanData(result);
        }
        return result;
    }

    @Auth(["jwt"])
    @Summary("Truncate Secrets")
    @Description("Deletes all Secrets from the datastore that the user has access to.")
    @Returns([null])
    @Delete()
    @RequiresElevation(60)
    public async truncate(@Param() params: any, @Query() query: any, @User user: JWTUser): Promise<void> {
        return super.doTruncate({ params, query, user });
    }

    protected async validateUpdate(obj: UpdateObject<T>, existing: T, user: JWTUser) {
        await this.validate(obj, { user });

        // Do not allow changing of a secret type
        if ("type" in obj && obj.type !== existing.type) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Cannot modify the `type` of a secret.");
        }

        // Do not allow re-assignment of a secret
        if ("userUid" in obj && obj.userUid !== existing.userUid) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Cannot re-assign secrets to a different owner.");
        }

        if ("data" in obj) {
            // Switches on `existing.type` rather than `obj.type`: a client updating only `data` is not
            // required to also send `type`, and falling back to `obj.type` here would leave it `undefined`
            // for such a request, silently skipping every type-specific check below (password hashing,
            // FIDO2/Passkey immutability, TOTP secret validation) and persisting `obj.data` completely
            // unvalidated.
            switch (existing.type) {
                case SecretType.FIDO2:
                    // Do not allow changing FIDO2 data. FIDO2 secrets must be re-created.
                    throw new ApiError(
                        ApiErrors.INVALID_REQUEST,
                        400,
                        "FIDO2 secrets cannot be modified. Create a new secret.",
                    );
                case SecretType.PASSKEY:
                    // Do not allow changing Passkey data. Passkey secrets must be re-created.
                    throw new ApiError(
                        ApiErrors.INVALID_REQUEST,
                        400,
                        "Passkey secrets cannot be modified. Create a new secret.",
                    );
                case SecretType.PASSWORD:
                    {
                        if (typeof obj.data === "string") {
                            this.validatePassword(obj.data);
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
                    await this.validateTOTPCreate(obj);
                    break;
            }
        }
    }

    @Auth(["jwt"])
    @Summary("Update Secret by ID")
    @Description("Updates a single Secret.")
    @Returns([Object])
    @Put("/:id")
    @RequiresElevation(60)
    public async update(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @Request req: HttpRequest,
        @User user: JWTUser,
    ): Promise<T> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const existing: T | undefined = await this.repoUtils.findOne(id, { skipCache: true, user });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }

        await this.validateUpdate(obj, existing, user);

        const result: T = await super.doUpdate(id, obj, { user });
        return await this.sanitizeSecretForResponse(result);
    }
}

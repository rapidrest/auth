///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    ACLAction,
    ApiErrorMessages,
    ApiErrors,
    DocDecorators,
    HttpRequest,
    HttpResponse,
    ModelRoute,
    NetUtils,
    RepoUtils,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { Secret, SecretType } from "../models/types.js";
import { ApiError, EventUtils, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";
import {
    decryptTOTPSecret,
    encryptTOTPSecret,
    generateAppPassword,
    generatePasskeyRegistrationOptions,
    generateRecoveryCodes,
    generateTOTPURI,
    importArgon2,
    importOTPLib,
    isClientHashedFormat,
    isPasskeyRegistrationResponse,
    isValidTOTPSecret,
    normalizePasswordSubmission,
    verifyPasskeyRegistrationResponse,
    WeakClientHashError,
} from "../auth/shared.js";
import { AuditLogUtils } from "../auth/AuditLogUtils.js";
import { SystemSettingsUtils } from "./SystemSettingsUtils.js";
import { AuthEventType } from "../auth/events.js";
import {
    PasskeyConfig,
    PasswordConfig,
    RecoveryCodesSecret,
    StoredPasskeyCredential,
    TOTPConfig,
    TOTPSecret,
} from "../auth/types.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Description, Returns, Summary } = DocDecorators;
const { Auth, Delete, Get, Head, Param, Post, Put, Query, Request, RequiresElevation, Response, User, Validate } =
    RouteDecorators;

/** How recently (in seconds) a token must have been elevated to update a secret — what `@RequiresElevation(60)` meant. */
const ELEVATION_WINDOW_SECONDS = 60;

/** What `allowUserChange=true` gives an account holder on a password an administrator set for them. */
const OWNER_PASSWORD_ACTIONS = [ACLAction.EXISTS, ACLAction.READ, ACLAction.UPDATE];

const REGEX_LOWERCASE =new RegExp("^.*[a-z]+.*$");
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

    /**
     * Set to `false` to disable app passwords (see `SecretType.APP_PASSWORD`) deployment-wide. Turning
     * this off refuses creation of new app passwords (see `validateAppPasswordCreate()`) and stops any
     * existing app-password secret from authenticating (see `BaseAuthBasicRoute`) - it does not delete
     * any already-created app password, so re-enabling this restores them exactly as they were.
     */
    @Config("auth:app_password:enabled", true)
    protected appPasswordEnabled: boolean = true;

    @Config("trusted_proxies", [])
    protected trustedProxies: string[] = [];

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Logger
    protected logger: any;

    @Inject(AuditLogUtils)
    protected auditLogUtils?: AuditLogUtils;

    /**
     * The `User` model class (e.g. `UserMongo`), used to clear `passwordChangeRequired` once the account holder
     * changes their password. Optional: a subclass that leaves it unset simply never clears the flag.
     */
    protected userClass?: any;

    protected userRepo?: RepoUtils<any>;

    /**
     * The `SystemSettings` model class (e.g. `SystemSettingsMongo`), used to read the `allowMultiplePasswords` policy.
     * Optional: a subclass that leaves it unset has no policy to consult, and so doesn't enforce one.
     */
    protected systemSettingsClass?: any;

    protected systemSettingsUtils?: SystemSettingsUtils;

    @Init
    private init() {
        this.regexSpecialChars = new RegExp("^.*[" + this.passwordConfig.special_chars + "]+.*$");
    }

    @Init
    private async initSystemSettings(): Promise<void> {
        if (!this.systemSettingsUtils && this.systemSettingsClass && this._objectFactory) {
            this.systemSettingsUtils = await this._objectFactory.newInstance(SystemSettingsUtils, {
                name: this.systemSettingsClass.name,
                args: [this.systemSettingsClass],
            });
        }
    }

    @Init
    private async initUserRepo(): Promise<void> {
        if (!this.userRepo && this.userClass && this._objectFactory) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * Builds the ACL to create a new secret with when a trusted user (e.g. an administrator) provisions a
     * `password` for *another* account and asks, via the `allowUserChange=true` query parameter, for the account
     * holder to be able to change it themselves.
     *
     * Without this the new secret's ACL is empty: the creator is a trusted role, which is exempt from the usual
     * implicit creator grant, and the account holder — who is not the creator — has no rights on it at all, so their
     * own `PUT /secrets/:id` to change the password is refused. Only `READ`, `EXISTS` and `UPDATE` are granted;
     * removing a password remains an administrator's call.
     *
     * @returns The ACL to pass to `doCreate()`, or `undefined` when the caller didn't ask for it or isn't entitled to.
     */
    protected buildOwnerACL(obj: T | T[], req: HttpRequest, user?: JWTUser): { records: any[] } | undefined {
        if (Array.isArray(obj) || this.ownerAccessRequest(obj.type, obj.userUid, req, user) !== "grant") {
            return undefined;
        }
        return { records: [{ userOrRoleId: obj.userUid, actions: [...OWNER_PASSWORD_ACTIONS] }] };
    }

    /**
     * What a trusted user is asking for, via the `allowUserChange` query parameter, about whether the account holder
     * can change a `password` secret they're provisioning or resetting for that account: `"grant"` for
     * `allowUserChange=true`, `"revoke"` for `allowUserChange=false`, and `undefined` when it isn't given (leave it as
     * it is) or the caller isn't entitled to ask. Never for another secret type, for a caller who isn't a trusted user,
     * or for one acting on their own secret (who has the ordinary creator grant already).
     */
    protected ownerAccessRequest(
        type: SecretType,
        userUid: string | undefined,
        req: HttpRequest,
        user?: JWTUser,
    ): "grant" | "revoke" | undefined {
        if (
            type !== SecretType.PASSWORD ||
            !userUid ||
            !user ||
            user.uid === userUid ||
            !UserUtils.hasRoles(user, this.trustedRoles)
        ) {
            return undefined;
        }
        const requested = req.query?.allowUserChange;
        return requested === "true" ? "grant" : requested === "false" ? "revoke" : undefined;
    }

    /**
     * The `update()` counterpart of `buildOwnerACL()`: a secret that already exists has an ACL already, and what the
     * account holder can do with it depends on how it got there — a password an administrator created earlier gives
     * them nothing, one they set themselves gives them everything. So an administrator resetting it says which they
     * want, with `allowUserChange`:
     * - `true` adds `OWNER_PASSWORD_ACTIONS` for the holder (creating the ACL first if the record somehow has none),
     * so a password they couldn't change becomes one they can;
     * - `false` removes the holder's record from it altogether, so a password they could change — including one they
     * chose themselves — becomes one only an administrator can. That's how an administrator keeps control of it.
     */
    protected async syncOwnerAccess(existing: T, req: HttpRequest, user?: JWTUser): Promise<void> {
        const request = this.ownerAccessRequest(existing.type, existing.userUid, req, user);
        if (!this.aclUtils?.enabled || !request) {
            return;
        }
        const acl = await this.aclUtils.findACL(existing.uid, [], { skipCache: true, skipParents: true });
        if (request === "revoke") {
            const records = (acl?.records ?? []).filter((r: any) => r.userOrRoleId !== existing.userUid);
            if (acl && records.length !== acl.records.length) {
                await this.aclUtils.saveACL({ ...acl, records });
            }
            return;
        }
        if (!acl) {
            await this.aclUtils.saveACL(
                {
                    uid: existing.uid,
                    parentUid: this.defaultACLUid,
                    records: [{ userOrRoleId: existing.userUid, actions: [...OWNER_PASSWORD_ACTIONS] }],
                },
                { createOnly: true },
            );
            return;
        }
        const records = acl.records.map((r: any) => ({ ...r, actions: [...r.actions] }));
        const record = records.find((r: any) => r.userOrRoleId === existing.userUid);
        if (record) {
            record.actions = [...new Set([...record.actions, ...OWNER_PASSWORD_ACTIONS])];
        } else {
            records.push({ userOrRoleId: existing.userUid, actions: [...OWNER_PASSWORD_ACTIONS] });
        }
        await this.aclUtils.saveACL({ ...acl, records });
    }

    /**
     * Enforces the `SystemSettings.allowMultiplePasswords` policy on a new `password`: unless it's on, an account that
     * already has one can't be given another — by anyone, an administrator included, who changes the existing one
     * instead. Sign-in accepts *any* of an account's password secrets, so this is also what makes "the one password"
     * mean something: whoever controls it (see `syncOwnerAccess()`) controls signing in by password, and the holder
     * can't sidestep an administrator by adding a password of their own.
     *
     * Not enforced by a route with no `systemSettingsClass`, which has no policy to consult.
     */
    protected async assertPasswordAllowed(obj: Partial<T>): Promise<void> {
        if (!this.systemSettingsUtils || !this.repoUtils || !obj.userUid) {
            return;
        }
        if ((await this.systemSettingsUtils.get()).allowMultiplePasswords) {
            return;
        }
        const existing: T[] = await this.repoUtils.find(
            { type: SecretType.PASSWORD, userUid: obj.userUid },
            { ignoreACL: true },
        );
        if (existing.length > 0) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "This account already has a password, and this server allows only one password per account.",
            );
        }
    }

    /**
     * The elevation check `@RequiresElevation(60)` would make on `update()` — the caller's token must have been
     * elevated within the last 60 seconds — except that it's waived for an account holder changing their own
     * `password` while their account is flagged `passwordChangeRequired`.
     *
     * That flag means they were just sent here to choose a new password, having signed in with a temporary one. Asking
     * them to prove the password they typed a moment ago again, to replace it, is an empty ceremony; and an elevated
     * sign-in token wouldn't fix it — elevation lapses after 60 seconds, which is easily less than the time it takes to
     * choose a password, and an elevated token also carries trusted roles (an administrator recovering their own
     * account would be handed an elevated admin token). Waiving the requirement for this one action has neither problem.
     * Nothing else about the caller is loosened: it applies only to their own password, only to a change of its `data`,
     * and only while the flag is set.
     */
    protected async assertElevatedOrForcedPasswordChange(existing: T, obj: UpdateObject<T>, user: JWTUser): Promise<void> {
        if (user?.elevated && user.elevated > 0 && Date.now() - user.elevated < ELEVATION_WINDOW_SECONDS * 1000) {
            return;
        }
        if (
            existing.type === SecretType.PASSWORD &&
            "data" in obj &&
            user?.uid === existing.userUid &&
            (await this.isPasswordChangeRequired(existing.userUid))
        ) {
            return;
        }
        throw new ApiError(
            ApiErrors.AUTH_REQUIRES_ELEVATION,
            403,
            ApiErrorMessages.AUTH_REQUIRES_ELEVATION,
        );
    }

    /** Whether the given account is flagged `passwordChangeRequired`. `false` when there's no user repo to ask. */
    protected async isPasswordChangeRequired(userUid: string): Promise<boolean> {
        const account = await this.userRepo?.findOne(userUid, { ignoreACL: true, skipCache: true });
        return account?.passwordChangeRequired === true;
    }

    /**
     * Clears the `passwordChangeRequired` flag on the given account, after its holder set a new password. A
     * failure is logged rather than thrown: the password change itself has already been persisted, and the worst
     * case is the account being asked to change it once more.
     */
    protected async clearPasswordChangeRequired(userUid: string): Promise<void> {
        if (!this.userRepo) {
            return;
        }
        try {
            const account = await this.userRepo.findOne(userUid, { ignoreACL: true, skipCache: true });
            if (account?.passwordChangeRequired) {
                await this.userRepo.update(
                    { uid: account.uid, version: account.version, passwordChangeRequired: false },
                    account,
                    { ignoreACL: true, recordEvent: false },
                );
            }
        } catch (err) {
            this.logger?.error(`Failed to clear passwordChangeRequired for '${userUid}': ${err}`);
        }
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
            case SecretType.APP_PASSWORD:
                await this.validateAppPasswordCreate(obj, req);
                break;
            case SecretType.FIDO2:
                await this.validateWebAuthnCreate(obj, req, this.fido2Config);
                break;
            case SecretType.PASSKEY:
                await this.validateWebAuthnCreate(obj, req, this.passkeyConfig);
                break;
            case SecretType.PASSWORD:
                await this.assertPasswordAllowed(obj);
                obj.data = await this.processPasswordSecret(obj.data, obj.userUid!);
                break;
            case SecretType.RECOVERY_CODES:
                await this.validateRecoveryCodesCreate(obj, req);
                break;
            case SecretType.TOTP:
                await this.validateTOTPCreate(obj);
                break;
        }
    }

    /**
     * Builds the argon2 hashing options from `passwordConfig`. `argon2.verify()` doesn't need these - the
     * cost parameters are embedded in the hash string itself - so this is only ever passed to `argon2.hash()`.
     */
    private argon2Options(): { memoryCost: number; timeCost: number; parallelism: number } {
        return {
            memoryCost: this.passwordConfig.hash_memory_cost,
            timeCost: this.passwordConfig.hash_time_cost,
            parallelism: this.passwordConfig.hash_parallelism,
        };
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
     * Validates a `password`-type secret's submitted `data` — either a plaintext password or a value
     * already hashed client-side (see `isClientHashedFormat()`/`normalizePasswordSubmission()` in
     * shared.ts) — and returns the server-side Argon2id hash to persist as `Secret.data`.
     *
     * A submission already in client-hashed form skips `validatePassword()`'s plaintext strength rules
     * (meaningless against a hash) but must still meet `passwordConfig`'s minimum cost-parameter floor.
     * A plaintext submission is validated as today, then normalized (hashed with the same fixed
     * salt/parameters a capable client would have used) before the server's own hash is computed on top
     * — so the one resulting stored hash accepts a login submitted either way (see
     * `BaseAuthBasicRoute`/`BaseAuthElevationRoute`).
     */
    private async processPasswordSecret(data: unknown, userUid: string): Promise<string> {
        if (typeof data !== "string") {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "A secret of type 'password' must specify string data.");
        }

        if (isClientHashedFormat(data)) {
            if (!this.passwordConfig.allow_client_hashing) {
                throw new ApiError(
                    ApiErrors.INVALID_REQUEST,
                    400,
                    "This server does not accept client-hashed passwords.",
                );
            }
        } else if (this.passwordConfig.require_client_hashing) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "This server requires passwords to be hashed client-side before submission.",
            );
        } else {
            this.validatePassword(data);
        }

        try {
            const canonical = await normalizePasswordSubmission(data, userUid, this.passwordConfig);
            const argon = await importArgon2();
            return await argon.hash(canonical, this.argon2Options());
        } catch (err) {
            if (err instanceof WeakClientHashError) {
                throw new ApiError(ApiErrors.INVALID_REQUEST, 400, err.message);
            }
            throw err;
        }
    }

    /**
     * Validates a new `app-password` secret's `hint` and generates the credential itself, discarding any
     * client-supplied `data` entirely - like recovery codes, there's no legitimate reason for a caller to
     * bring their own value here; accepting one would let an attacker who can currently write to this
     * secret type plant a known credential for later use. A `hint` is required (not merely optional, as it
     * is for other secret types) since an account may accumulate several app passwords over time - the
     * label is the only way a user tells them apart again later, once the plaintext itself is gone.
     *
     * Only the generated password's argon2 hash is persisted; the plaintext is stashed on `req` so
     * `sanitizeSecretForResponse()` can return it to the caller exactly once, in the `create()` response -
     * it can never be retrieved again after that, since it's never written to the datastore.
     *
     * @param obj The secret being created.
     * @param req The source HTTP request, used to stash the plaintext app password for the `create()`
     * response only.
     */
    protected async validateAppPasswordCreate(obj: Partial<T>, req: HttpRequest): Promise<void> {
        if (!this.appPasswordEnabled) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "This server does not allow creating app passwords.");
        }

        const hint: string | undefined = typeof obj.hint === "string" ? obj.hint.trim() : undefined;
        if (!hint) {
            throw new ApiError(
                ApiErrors.INVALID_REQUEST,
                400,
                "A secret of type 'app-password' must specify a non-empty 'hint' to tell it apart from " +
                    "other app passwords later.",
            );
        }
        if (hint.length > 100) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "The 'hint' for an app password must be at most 100 characters.");
        }
        obj.hint = hint;

        const plaintext: string = generateAppPassword();
        const argon = await importArgon2();
        obj.data = await argon.hash(plaintext, this.argon2Options());

        (req as any).generatedAppPassword = plaintext;
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
            secret: encryptTOTPSecret(secret, this.totpConfig.encryption_key),
            digits: this.totpConfig.digits,
            period: this.totpConfig.period,
            algorithm: this.totpConfig.algorithm,
            epochTolerance: this.totpConfig.epochTolerance,
        };
        obj.data = totpSecret;
    }

    /**
     * Generates a fresh batch of MFA recovery/backup codes for the account, discarding any client-supplied
     * `data` entirely - unlike a TOTP secret, there's no legitimate reason for a caller to bring their own
     * codes here; accepting caller-chosen values would let an attacker who can currently write to this
     * secret pre-plant known codes for later use. Only each code's argon2 hash is persisted (see
     * `RecoveryCodesSecret`); the plaintext is stashed on `req` so `sanitizeSecretForResponse()` can return
     * it to the caller exactly once, in the `create()` response - it can never be retrieved again after
     * that, since it's never written to the datastore.
     *
     * @param obj The secret being created.
     * @param req The source HTTP request, used to stash the plaintext codes for the `create()` response only.
     */
    protected async validateRecoveryCodesCreate(obj: Partial<T>, req: HttpRequest): Promise<void> {
        const plaintextCodes: string[] = generateRecoveryCodes();
        const argon = await importArgon2();
        const codes = await Promise.all(
            plaintextCodes.map(async (code) => ({ hash: await argon.hash(code, this.argon2Options()) })),
        );

        const recoveryCodesSecret: RecoveryCodesSecret = { codes };
        obj.data = recoveryCodesSecret;

        (req as any).generatedRecoveryCodes = plaintextCodes;
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
    @RequiresElevation(60)
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
    @RequiresElevation(60)
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
    @RequiresElevation(60)
    public async create(obj: T | T[], @Request req: HttpRequest, @User user: JWTUser): Promise<T | Array<T>> {
        const acl = this.buildOwnerACL(obj, req, user);
        const result: T | Array<T> = await super.doCreate(obj, { req, user, ...(acl ? { acl } : {}) } as any);

        // Selectively clean data from certain types of secrets. Some secret types require the data needs to be
        // returned back to the client. `sanitizeSecretForResponse()` may hand back a different object than it
        // was given (see its own doc comment on why) rather than mutate in place, so what's actually sent to
        // the client is its return value, not the original `result`/`objs` entries.
        const objs: Array<T> = Array.isArray(result) ? result : [result];
        const sanitized: Array<T> = [];
        for (const obj of objs) {
            sanitized.push(await this.sanitizeSecretForResponse(obj, req));
            // Only set when the caller acted on someone else's behalf (a trusted role provisioning
            // another account - see enforceOwnership()); matches AuditLogEntry.actorUid's own contract.
            // Guarded with `?.` since `user` is always populated in production (this route requires
            // `@Auth(["jwt"])`) but defensively kept optional here, matching the parameter's own type.
            const actorUid: string | undefined = user?.uid && user.uid !== obj.userUid ? user.uid : undefined;
            if (this.isMFASecretType(obj.type)) {
                EventUtils.record({
                    type: AuthEventType.MFA_ENROLLED,
                    userUid: obj.userUid,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                    secretType: obj.type,
                }).catch(() => undefined);
                try {
                    await this.auditLogUtils?.record({
                        type: AuthEventType.MFA_ENROLLED,
                        userUid: obj.userUid,
                        actorUid,
                        ip: NetUtils.getIPAddress(req, this.trustedProxies),
                        path: req.path,
                        data: { secretType: obj.type },
                    });
                } catch (err) {
                    this.logger?.error(
                        `[AuditLog] Failed to record ${AuthEventType.MFA_ENROLLED} for '${obj.userUid}': ${err}`,
                    );
                }
            } else if (obj.type === SecretType.PASSWORD) {
                EventUtils.record({
                    type: AuthEventType.PASSWORD_CHANGED,
                    userUid: obj.userUid,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                }).catch(() => undefined);
                try {
                    await this.auditLogUtils?.record({
                        type: AuthEventType.PASSWORD_CHANGED,
                        userUid: obj.userUid,
                        actorUid,
                        ip: NetUtils.getIPAddress(req, this.trustedProxies),
                        path: req.path,
                    });
                } catch (err) {
                    this.logger?.error(
                        `[AuditLog] Failed to record ${AuthEventType.PASSWORD_CHANGED} for '${obj.userUid}': ${err}`,
                    );
                }
            } else if (obj.type === SecretType.APP_PASSWORD) {
                // Not part of isMFASecretType() - an app password is deliberately never counted as a
                // second factor - so it gets its own event pair rather than reusing MFA_ENROLLED/MFA_REMOVED.
                EventUtils.record({
                    type: AuthEventType.APP_PASSWORD_CREATED,
                    userUid: obj.userUid,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                    secretType: obj.type,
                }).catch(() => undefined);
                try {
                    await this.auditLogUtils?.record({
                        type: AuthEventType.APP_PASSWORD_CREATED,
                        userUid: obj.userUid,
                        actorUid,
                        ip: NetUtils.getIPAddress(req, this.trustedProxies),
                        path: req.path,
                        data: { secretType: obj.type },
                    });
                } catch (err) {
                    this.logger?.error(
                        `[AuditLog] Failed to record ${AuthEventType.APP_PASSWORD_CREATED} for '${obj.userUid}': ${err}`,
                    );
                }
            }
        }

        return Array.isArray(result) ? sanitized : sanitized[0];
    }

    /**
     * Whether `type` is one of the secondary-auth-capable secret types (as opposed to a plain `password`) -
     * used to scope `auth.mfa.enrolled`/`auth.mfa.removed` event emission to actual MFA enrollment changes.
     */
    private isMFASecretType(type: SecretType): boolean {
        return (
            [SecretType.FIDO2, SecretType.PASSKEY, SecretType.TOTP, SecretType.RECOVERY_CODES] as SecretType[]
        ).includes(type);
    }

    /**
     * Strips or augments the `data` field of a persisted secret before it is returned to the client. Shared
     * by `create()` and `update()` so that a response for either operation never leaks a `password` hash or
     * raw WebAuthn/TOTP credential material back over the wire.
     *
     * @param req The originating request, used only to recover the plaintext codes
     * `validateRecoveryCodesCreate()` stashed on it for a `recovery-codes` secret - omit for `update()`,
     * which never reaches a `recovery-codes` secret (see `validateUpdate()`).
     */
    private async sanitizeSecretForResponse(obj: T, req?: HttpRequest): Promise<T> {
        if ([SecretType.FIDO2, SecretType.PASSKEY, SecretType.PASSWORD].includes(obj.type)) {
            delete obj.data;
        } else if (obj.type === SecretType.TOTP && obj.data) {
            // The persisted `secret` may be encrypted at rest (see `encryptTOTPSecret()`) - decrypt it back
            // to plaintext for the response, exactly like before encryption existed, since the caller's
            // authenticator app needs the real secret once, at setup time (for manual entry, and to embed
            // in the `otpauth://` provisioning URI computed fresh here for the response only).
            //
            // Builds a new `data` object (and reassigns the local `obj` to a new top-level object) rather
            // than mutating either in place: `obj` is the exact reference `RepoUtils.create()`/`update()`
            // just handed to their entity cache when the consuming app has one enabled for `Secret` - a
            // caller supplying its own class each save both `result` and the cache entry by pointer, not a
            // copy. Mutating `obj`/`obj.data` here would leave that *cached* copy holding the plaintext
            // secret instead of the `enc:v1:...` ciphertext actually written to the datastore, silently
            // defeating encryption-at-rest for any subsequent cache-served read.
            const decrypted: TOTPSecret & { uri?: string } = { ...(obj.data as TOTPSecret) };
            decrypted.secret = decryptTOTPSecret(decrypted.secret, this.totpConfig.encryption_key);
            decrypted.uri = await generateTOTPURI(this.totpConfig, obj.userUid, decrypted);
            obj = { ...obj, data: decrypted };
        } else if (obj.type === SecretType.RECOVERY_CODES) {
            // The hashed `data` persisted by validateRecoveryCodesCreate() is never returned - only the
            // plaintext it stashed on `req`, and only this once; it isn't recoverable after this response.
            (obj as any).codes = (req as any)?.generatedRecoveryCodes;
            delete obj.data;
        } else if (obj.type === SecretType.APP_PASSWORD) {
            // The hashed `data` persisted by validateAppPasswordCreate() is never returned - only the
            // plaintext it stashed on `req`, and only this once; it isn't recoverable after this response.
            (obj as any).password = (req as any)?.generatedAppPassword;
            delete obj.data;
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
        // Looked up before deletion since only the id is otherwise available - the deleted secret's type is
        // needed to decide whether this qualifies as an `auth.mfa.removed` event.
        const existing: T | undefined = await this.repoUtils?.findOne(id, { user });

        await super.doDelete(id, { user, req, version, purge: purge === "true" });

        // Only set when the caller acted on someone else's behalf (a trusted role removing another
        // account's secret); matches AuditLogEntry.actorUid's own contract. Guarded with `?.` for the
        // same reason as create()'s own actorUid above.
        const actorUid: string | undefined =
            existing && user?.uid && user.uid !== existing.userUid ? user.uid : undefined;
        if (existing && this.isMFASecretType(existing.type)) {
            EventUtils.record({
                type: AuthEventType.MFA_REMOVED,
                userUid: existing.userUid,
                ip: NetUtils.getIPAddress(req, this.trustedProxies),
                secretType: existing.type,
            }).catch(() => undefined);
            try {
                await this.auditLogUtils?.record({
                    type: AuthEventType.MFA_REMOVED,
                    userUid: existing.userUid,
                    actorUid,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                    path: req.path,
                    data: { secretType: existing.type },
                });
            } catch (err) {
                this.logger?.error(
                    `[AuditLog] Failed to record ${AuthEventType.MFA_REMOVED} for '${existing.userUid}': ${err}`,
                );
            }
        } else if (existing && existing.type === SecretType.APP_PASSWORD) {
            EventUtils.record({
                type: AuthEventType.APP_PASSWORD_REMOVED,
                userUid: existing.userUid,
                ip: NetUtils.getIPAddress(req, this.trustedProxies),
                secretType: existing.type,
            }).catch(() => undefined);
            try {
                await this.auditLogUtils?.record({
                    type: AuthEventType.APP_PASSWORD_REMOVED,
                    userUid: existing.userUid,
                    actorUid,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                    path: req.path,
                    data: { secretType: existing.type },
                });
            } catch (err) {
                this.logger?.error(
                    `[AuditLog] Failed to record ${AuthEventType.APP_PASSWORD_REMOVED} for '${existing.userUid}': ${err}`,
                );
            }
        }
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
                case SecretType.APP_PASSWORD:
                    // Do not allow changing an app password's value - a client-supplied value here would
                    // write attacker-controlled plaintext straight into `data` unhashed (validateCreate()'s
                    // hashing only runs on create). App passwords must be deleted and re-created to rotate
                    // them (a hint-only update, with no `data` key, still works - see the `"data" in obj`
                    // gate above).
                    throw new ApiError(
                        ApiErrors.INVALID_REQUEST,
                        400,
                        "App passwords cannot be modified. Delete and create a new secret to rotate them.",
                    );
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
                    obj.data = await this.processPasswordSecret(obj.data, existing.userUid);
                    break;
                case SecretType.RECOVERY_CODES:
                    // Do not allow changing recovery codes' data - a client-supplied value here would
                    // write attacker-controlled plaintext straight into `data` unhashed (validateCreate()'s
                    // hashing only runs on create). Recovery codes must be deleted and re-created.
                    throw new ApiError(
                        ApiErrors.INVALID_REQUEST,
                        400,
                        "Recovery codes cannot be updated. Delete and create a new secret to regenerate them.",
                    );
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

        // Enforced here rather than by `@RequiresElevation(60)`, which can't be waived per request: see
        // `assertElevatedOrForcedPasswordChange()` for the one case that is.
        await this.assertElevatedOrForcedPasswordChange(existing, obj, user);

        // Captured before validateUpdate() runs - it reassigns obj.data (e.g. to the freshly-hashed
        // value) but never removes the key, so this still correctly reflects whether the caller actually
        // submitted a new `data` value, as opposed to e.g. a hint-only rename.
        const isPasswordDataChange: boolean = existing.type === SecretType.PASSWORD && "data" in obj;

        await this.validateUpdate(obj, existing, user);

        const result: T = await super.doUpdate(id, obj, { user });

        await this.syncOwnerAccess(existing, req, user);

        if (isPasswordDataChange) {
            // Only the account holder choosing a new password retires a temporary one; an administrator resetting
            // it on their behalf must not.
            if (user?.uid === existing.userUid) {
                await this.clearPasswordChangeRequired(existing.userUid);
            }

            EventUtils.record({
                type: AuthEventType.PASSWORD_CHANGED,
                userUid: existing.userUid,
                ip: NetUtils.getIPAddress(req, this.trustedProxies),
            }).catch(() => undefined);
            try {
                await this.auditLogUtils?.record({
                    type: AuthEventType.PASSWORD_CHANGED,
                    userUid: existing.userUid,
                    actorUid: user?.uid && user.uid !== existing.userUid ? user.uid : undefined,
                    ip: NetUtils.getIPAddress(req, this.trustedProxies),
                    path: req.path,
                });
            } catch (err) {
                this.logger?.error(
                    `[AuditLog] Failed to record ${AuthEventType.PASSWORD_CHANGED} for '${existing.userUid}': ${err}`,
                );
            }
        }

        return await this.sanitizeSecretForResponse(result);
    }
}

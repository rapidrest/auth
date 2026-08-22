////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { ApiError, JWTUser, MessagingUtils, ObjectDecorators, UserUtils } from "@rapidrest/core";
import {
    ApiErrorMessages,
    ApiErrors,
    DocDecorators,
    ObjectFactory,
    RepoUtils,
    RouteDecorators,
} from "@rapidrest/service-core";
import { Alias, Profile, Secret, User } from "../models/types.js";
import { TokenUtils } from "../auth/TokenUtils.js";
import { RateLimiter } from "../auth/RateLimiter.js";

const { Config, Init, Inject, Logger } = ObjectDecorators;
const { Summary, Description, Returns } = DocDecorators;
const { Auth, Delete, Get, Param, Post, RequiresElevation } = RouteDecorators;
const AuthUser = RouteDecorators.User;

/**
 * Provides a single set of routes for working with a user's account data in aggregate.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseAccountRoute<U extends User, A extends Alias, P extends Profile, S extends Secret> {
    protected abstract aliasClass: any;
    protected abstract profileClass: any;
    protected abstract secretClass: any;
    protected abstract userClass: any;

    // Automatically injected by ObjectFactory on instantiation
    private _objectFactory?: ObjectFactory;

    @Config("auth:default_scopes", [])
    protected defaultScopes: string[] = [];

    @Config("auth")
    protected jwtConfig?: any;

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Logger
    protected logger: any;

    @Inject(MessagingUtils)
    protected messagingUtils?: MessagingUtils;

    @Inject(TokenUtils)
    protected tokenUtils?: TokenUtils;

    @Inject(RateLimiter)
    protected rateLimiter?: RateLimiter;

    protected aliasRepo?: RepoUtils<A>;
    protected profileRepo?: RepoUtils<P>;
    protected secretRepo?: RepoUtils<S>;
    protected userRepo?: RepoUtils<U>;

    @Init
    protected async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.profileRepo && this.profileClass) {
            this.profileRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this._objectFactory.newInstance(RepoUtils, {
                name: this.userClass.name,
                args: [this.userClass],
            });
        }
    }

    /**
     * Removes the `data` property from the secret(s) to protect sensitive information.
     */
    protected cleanSecretData(obj: S | S[]) {
        const objs: Array<S> = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            delete obj.data;
        }
    }

    @Summary("Delete Account Data")
    @Description("Deletes all account data associated with the user, or any user's if the caller holds a trusted role.")
    @Auth(["jwt"])
    @Delete(":id")
    public async delete(@Param("id") id: string, @AuthUser user: JWTUser): Promise<any> {
        const targetId = this.resolveOwnedUid(id, user);

        const eUser: U | undefined = await this.userRepo?.findOne(targetId, { user });
        if (!eUser) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        // Delete all associated data before we delete the user itself. `truncate()` narrows to the caller's
        // permitted records via `Alias`/`Secret`'s per-record ACL (already granted to the owner, or bypassed
        // entirely for a trusted role) rather than needing `ignoreACL` here. `profileRepo.delete()` does need
        // it though: a `Profile`'s `uid` is intentionally the same value as its owning `User`'s `uid` (see
        // `BaseProfileRoute`'s doc comments), so its per-record ACL check would instead evaluate against
        // whichever of the two documents happens to share that uid.
        await this.aliasRepo?.truncate({ userUid: eUser.uid }, { user });
        await this.secretRepo?.truncate({ userUid: eUser.uid }, { user });
        await this.profileRepo?.delete(eUser.uid, { user, ignoreACL: true });
        await this.userRepo?.delete(eUser.uid, { user });
    }

    @Summary("Get Account Data")
    @Description("Returns all account data associated with the user, or any user's if the caller holds a trusted role.")
    @Auth(["jwt"])
    @Get(":id")
    public async get(@Param("id") id: string, @AuthUser user: JWTUser): Promise<any> {
        const targetId = this.resolveOwnedUid(id, user);

        const eUser: U | undefined = await this.userRepo?.findOne(targetId, { user });
        if (!eUser) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        // Now retrieve all associated data for the account. `ignoreACL` is required here: `Alias`/`Secret`'s
        // class-level ACL intentionally denies `LIST` to `.*` (see `BaseAliasRoute.find()`'s doc comment,
        // which explains why - a class-level `LIST` wildcard would leak every user's records via the
        // per-record ACL fallback), so `find()`'s class-level fast-fail gate would otherwise 403 even the
        // account's own owner. The query is already scoped to `eUser.uid`, so bypassing ACL here is safe.
        // `profileRepo.findOne()` needs it for a different reason: a `Profile`'s `uid` is intentionally the
        // same value as its owning `User`'s `uid` (see `BaseProfileRoute`'s doc comments), so its per-record
        // ACL check would instead evaluate against whichever of the two documents happens to share that uid.
        const aliases: A[] = (await this.aliasRepo?.find({ userUid: eUser.uid }, { user, ignoreACL: true })) ?? [];
        const profile: P | undefined = await this.profileRepo?.findOne(eUser.uid, { user, ignoreACL: true });
        const secrets: S[] = (await this.secretRepo?.find({ userUid: eUser.uid }, { user, ignoreACL: true })) ?? [];
        this.cleanSecretData(secrets);

        return {
            user: eUser,
            aliases,
            profile,
            secrets,
        };
    }

    /**
     * Immediately revokes every outstanding refresh token for the account (self-service, or any account's if
     * the caller holds a trusted role) — the standard "log out everywhere" action, e.g. after a suspected
     * account compromise.
     *
     * This does NOT invalidate an already-issued *access* token, which remains valid until its own natural
     * (short) expiry regardless of this call — true immediate access-token revocation would require a
     * persistent revocation check on every single request, which the underlying JWT verification
     * (`@rapidrest/service-core`'s `JWTStrategy`, an external package this library doesn't control) doesn't
     * support; it does a stateless signature/expiry check only, with no per-request datastore lookup. What
     * this *does* reliably stop going forward is `BaseAuthRefreshRoute` minting any new access token from a
     * refresh token issued before this call — see the `iat` check there. This includes the caller's own
     * current session: there is no "everywhere but here" variant, matching the equivalent behavior in most
     * other systems that offer this action.
     */
    @Summary("Revoke All Sessions")
    @Description(
        "Immediately revokes every outstanding refresh token for the account (including the caller's own " +
            "current session), forcing every device to sign in again to obtain a new one. Does not invalidate " +
            "an already-issued access token, which remains valid until its own natural expiry.",
    )
    @Auth(["jwt"])
    @Post(":id/revokeSessions")
    @RequiresElevation(60)
    public async revokeSessions(@Param("id") id: string, @AuthUser user: JWTUser): Promise<void> {
        const targetId = this.resolveOwnedUid(id, user);

        const eUser: U | undefined = await this.userRepo?.findOne(targetId, { user });
        if (!eUser) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        await this.userRepo?.update(
            { uid: eUser.uid, version: eUser.version, sessionsRevokedAt: Date.now() } as any as U,
            eUser,
            { user },
        );
    }

    /**
     * Resolves `id` (handling the `"me"` keyword) and verifies the caller either owns the targeted account
     * (`targetUid === user.uid`) or holds a trusted role. Throws `403` otherwise.
     */
    protected resolveOwnedUid(id: string, user: JWTUser): string {
        const targetUid: string = id === "me" ? user.uid : id;
        if (targetUid !== user.uid && !UserUtils.hasRoles(user, this.trustedRoles)) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }
        return targetUid;
    }
}

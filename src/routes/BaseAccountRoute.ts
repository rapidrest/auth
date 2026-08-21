////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
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
const { Summary, Description } = DocDecorators;
const { Auth, Delete, Get, Param } = RouteDecorators;
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

    @Inject(ObjectFactory)
    protected objectFactory?: ObjectFactory;

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
        if (!this.objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.aliasRepo && this.aliasClass) {
            this.aliasRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.aliasClass.name,
                args: [this.aliasClass],
            });
        }

        if (!this.profileRepo && this.profileClass) {
            this.profileRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.profileClass.name,
                args: [this.profileClass],
            });
        }

        if (!this.secretRepo && this.secretClass) {
            this.secretRepo = await this.objectFactory.newInstance(RepoUtils, {
                name: this.secretClass.name,
                args: [this.secretClass],
            });
        }

        if (!this.userRepo && this.userClass) {
            this.userRepo = await this.objectFactory.newInstance(RepoUtils, {
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

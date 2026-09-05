///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    ApiErrorMessages,
    ApiErrors,
    CRUDRoute,
    HttpRequest,
    HttpResponse,
    RouteDecorators,
    UpdateObject,
} from "@rapidrest/service-core";
import { ApiError, JWTUser, ObjectDecorators, UserUtils } from "@rapidrest/core";
import * as crypto from "crypto";
import { Client, ClientType } from "../models/types.js";
import { importArgon2 } from "../auth/shared.js";

const { Config } = ObjectDecorators;
const { Auth, Param, Post, Query, Request, RequiresElevation, Response, User } = RouteDecorators;

/**
 * Owner/admin CRUD for `Client`, the registered OAuth 2.0 / OpenID Connect applications this authorization
 * server issues tokens to.
 *
 * `Client`'s class-level ACL only grants `.*` the ability to `CREATE` (see `ClientSQL`/`ClientMongo`'s
 * `@Protect` records, shaped exactly like `Secret`'s) — everything else a caller can do to a specific
 * `Client` comes from a per-record grant. `RepoUtils.create()` automatically grants the creator full CRUD on
 * their own new record (unless they hold a trusted role, which already gets blanket access to every record
 * via `ACLUtils.hasPermission()`), so an authenticated non-admin caller can register and fully manage their
 * own client with zero bespoke access-control code here — the same "self-service owner, blanket admin"
 * pattern `Secret` already uses. This is what lets a future self-service "manage my own clients" UI be
 * purely a UI-exposure decision later, not a re-architecture now.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseOAuthClientRoute<T extends Client> extends CRUDRoute<T> {
    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    /**
     * Removes the `clientSecretHash` property from the client(s) before returning them to the caller — it
     * must never round-trip on an ordinary read, only ever surfaced (in plaintext, once) from `create()` or
     * `regenerateSecret()`.
     */
    private cleanSecret(obj: T | T[]): void {
        const objs: Array<T> = Array.isArray(obj) ? obj : [obj];
        for (const obj of objs) {
            delete obj.clientSecretHash;
        }
    }

    /**
     * Builds the object actually returned from `create()`/`regenerateSecret()`: `clientSecretHash` is always
     * stripped, and — only for a `CONFIDENTIAL` client whose plaintext secret was just generated — a
     * `clientSecret` property carries it, this one time. It is never persisted and can never be retrieved
     * again after this response.
     */
    private sanitizeClientForResponse(obj: T, clientSecret?: string): T {
        const sanitized: any = { ...obj };
        delete sanitized.clientSecretHash;
        if (clientSecret) {
            sanitized.clientSecret = clientSecret;
        }
        return sanitized;
    }

    /**
     * Generates a new opaque client secret and its Argon2id hash, mirroring `OAuthTokenUtils`'s opaque-token
     * style (`crypto.randomBytes`) rather than a JWT — a client secret is a shared credential presented back
     * to the token endpoint, not something ever decoded.
     */
    private async generateClientSecret(): Promise<{ secret: string; hash: string }> {
        const secret: string = crypto.randomBytes(32).toString("base64url");
        const argon = await importArgon2();
        const hash: string = await argon.hash(secret);
        return { secret, hash };
    }

    protected async validateCreate(obj: Partial<T>, user?: JWTUser): Promise<void> {
        await super.validateCreate(obj, user);

        const isTrusted = UserUtils.hasRoles(user, this.trustedRoles);

        if (!obj.ownerUid) {
            if (user && !isTrusted) {
                obj.ownerUid = user.uid;
            }
        } else if (user && obj.ownerUid !== user.uid && !isTrusted) {
            throw new ApiError(ApiErrors.AUTH_PERMISSION_FAILURE, 403, ApiErrorMessages.AUTH_PERMISSION_FAILURE);
        }

        // Only a trusted role may register a first-party client (one that skips the consent screen).
        if ("firstParty" in obj && !isTrusted) {
            obj.firstParty = false;
        }

        if (obj.clientType === ClientType.PUBLIC) {
            // A public client can never keep a secret confidential, so it is never issued one, and PKCE is
            // its only proof of possession — required unconditionally, regardless of what was requested.
            delete obj.clientSecretHash;
            obj.requirePkce = true;
        } else if (obj.clientType === ClientType.CONFIDENTIAL) {
            // Any client-supplied `clientSecretHash` is discarded — a secret is only ever minted here, never
            // accepted from the caller, so it can be returned in plaintext exactly once below.
            const { secret, hash } = await this.generateClientSecret();
            obj.clientSecretHash = hash;
            // Stashed as a transient, non-model property so `create()` (which still holds this same `obj`
            // reference) can echo it back exactly once — `instantiateObject()` builds a fresh entity from
            // only the fields each model's own constructor knows about, so this never reaches persistence.
            (obj as any)._generatedClientSecret = secret;
        }
    }

    @Auth(["jwt"])
    @RequiresElevation(60)
    public async create(obj: T | T[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T | Array<T>> {
        const inputs: Array<any> = Array.isArray(obj) ? obj : [obj];
        const result: T | Array<T> = await super.create(obj, req, user);

        const results: T[] = Array.isArray(result) ? result : [result];
        const sanitized: T[] = results.map((r, i) => this.sanitizeClientForResponse(r, inputs[i]?._generatedClientSecret));

        return Array.isArray(result) ? sanitized : sanitized[0];
    }

    protected async validateUpdate(id: string, obj: UpdateObject<T>, user?: JWTUser): Promise<void> {
        await super.validateUpdate(id, obj, user);

        const isTrusted = UserUtils.hasRoles(user, this.trustedRoles);

        // A client's secret can only ever change via `regenerateSecret()`, which generates and hashes it
        // itself — accepting one directly here would let a caller who can update the record (its owner)
        // plant an attacker-chosen hash without going through that audited, one-time-reveal path.
        if ("clientSecretHash" in obj) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "`clientSecretHash` cannot be set directly.");
        }

        if ("ownerUid" in obj && !isTrusted) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Cannot change the owner of a client.");
        }

        if ("firstParty" in obj && !isTrusted) {
            delete obj.firstParty;
        }
    }

    @Auth(["jwt"])
    @RequiresElevation(60)
    public update(
        @Param("id") id: string,
        obj: UpdateObject<T>,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<T> {
        return super.update(id, obj, req, user);
    }

    @Auth(["jwt"])
    public async count(
        @Param() params: any,
        @Query() query: any,
        @Response res: HttpResponse,
        @User user?: JWTUser,
    ): Promise<any> {
        return super.count(params, query, res, user);
    }

    @Auth(["jwt"])
    @RequiresElevation(60)
    public delete(
        @Param("id") id: string,
        @Query("version") version: string | undefined,
        @Query("purge") purge: string | undefined,
        @Request req: HttpRequest,
        @User user?: JWTUser,
    ): Promise<void> {
        return super.delete(id, version, purge, req, user);
    }

    @Auth(["jwt"])
    public async exists(
        @Param("id") id: string,
        @Query() query: any,
        @Response res: HttpResponse,
        @User user?: JWTUser,
    ): Promise<any> {
        return super.exists(id, query, res, user);
    }

    /**
     * `Client`'s class-level ACL intentionally does NOT grant `LIST` to `.*` — see `Secret.find()`'s own
     * doc comment for why a class-level wildcard grant would leak every other caller's clients. Self-service
     * "list my own clients" is instead handled directly here: scope the query to the caller's own
     * `ownerUid` (discarding any client-supplied `ownerUid` filter, which would otherwise let a caller probe
     * another owner's clients) and bypass ACL entirely for that already-scoped lookup. A trusted role keeps
     * the normal, unscoped behavior.
     */
    @Auth(["jwt"])
    public async find(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<T[]> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        let results: T[];
        if (user && !UserUtils.hasRoles(user, this.trustedRoles)) {
            results = await this.repoUtils.find(
                { ...params, ...query, ownerUid: user.uid },
                { limit: query?.limit, page: query?.page, ignoreACL: true, user },
            );
        } else {
            results = await super.find(params, query, user);
        }
        this.cleanSecret(results);
        return results;
    }

    @Auth(["jwt"])
    public async findById(@Param("id") id: string, @Query() query: any, @User user?: JWTUser): Promise<T | null> {
        const result: T | null = await super.findById(id, query, user);
        if (result) {
            this.cleanSecret(result);
        }
        return result;
    }

    /**
     * Generates a new secret for a `CONFIDENTIAL` client, invalidating the previous one, and returns it in
     * plaintext exactly once — it is never persisted or retrievable again after this response. Subject to
     * the same ACL as every other mutation on this record: the client's owner, or a trusted role.
     */
    @Auth(["jwt"])
    @RequiresElevation(60)
    @Post("/:id/regenerate-secret")
    public async regenerateSecret(@Param("id") id: string, @User user?: JWTUser): Promise<{ clientSecret: string }> {
        if (!this.repoUtils) {
            throw new ApiError(ApiErrors.INTERNAL_ERROR, 500, ApiErrorMessages.INTERNAL_ERROR);
        }

        const existing: T | undefined = await this.repoUtils.findOne(id, { user });
        if (!existing) {
            throw new ApiError(ApiErrors.NOT_FOUND, 404, ApiErrorMessages.NOT_FOUND);
        }
        if (existing.clientType !== ClientType.CONFIDENTIAL) {
            throw new ApiError(ApiErrors.INVALID_REQUEST, 400, "Only a confidential client has a secret to regenerate.");
        }

        const { secret, hash } = await this.generateClientSecret();
        await this.repoUtils.update({ uid: existing.uid, version: existing.version, clientSecretHash: hash } as any, existing, {
            user,
        });

        return { clientSecret: secret };
    }

    @Auth(["jwt"])
    @RequiresElevation(60)
    public truncate(@Param() params: any, @Query() query: any, @User user?: JWTUser): Promise<void> {
        return super.truncate(params, query, user);
    }

    @Auth(["jwt"])
    public updateBulk(obj: UpdateObject<T>[], @Request req: HttpRequest, @User user?: JWTUser): Promise<T[]> {
        return super.updateBulk(obj, req, user);
    }

    @Auth(["jwt"])
    public updateProperty(
        @Param("id") id: string,
        @Param("propertyName") propertyName: string,
        obj: any,
        @User user?: JWTUser,
    ): Promise<T> {
        return super.updateProperty(id, propertyName, obj, user);
    }
}

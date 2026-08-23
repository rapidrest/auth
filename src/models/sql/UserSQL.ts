///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { User } from "../types.js";
import { ObjectDecorators } from "@rapidrest/core";

const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `User` interface for storage in a SQLDB database. If MongoDB is desired, please use
 * `models.mongo.UserMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a record for a single user account in the system.")
@Protect(
    {
        uid: "User",
        records: [
            {
                userOrRoleId: "anonymous",
                actions: [],
            },
            {
                userOrRoleId: ".*",
                actions: [],
            },
        ],
    },
    true,
)
export class UserSQL extends BaseEntity implements User {
    @Column({ nullable: true })
    @Description("Set to `true` to require multi-factor authentication for this account, otherwise set to `false`.")
    @Nullable
    requireMFA?: boolean;

    @Column({ type: "simple-json" })
    @Description("The list of permission roles the user has.")
    public roles: string[] = [];

    // This is purposefully not stored in the database as its built at runtime
    @Description("The list of permission scopes the user has.")
    public scopes: string[] = [];

    @Column({ nullable: true })
    @Description(
        "The epoch millisecond timestamp at which every refresh token issued before it was revoked " +
            "(see `BaseAccountRoute.revokeSessions()`), if ever.",
    )
    @Nullable
    public sessionsRevokedAt?: number;

    @Column()
    @Description("Indicates if the user's contact information (e.g. email, phone number) has been verified.")
    public verified: boolean = false;

    constructor(other?: Partial<UserSQL>) {
        super(other);

        if (other) {
            this.requireMFA = "requireMFA" in other ? other.requireMFA : this.requireMFA;
            this.roles = other.roles !== undefined ? other.roles : this.roles;
            this.scopes = other.scopes !== undefined ? other.scopes : this.scopes;
            this.sessionsRevokedAt = other.sessionsRevokedAt !== undefined ? other.sessionsRevokedAt : this.sessionsRevokedAt;
            this.verified = other.verified !== undefined ? other.verified : this.verified;
        }
    }
}

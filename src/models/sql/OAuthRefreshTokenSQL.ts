///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { OAuthRefreshToken } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `OAuthRefreshToken` interface for storage in a SQL database. If MongoDB is desired,
 * please use `models.mongo.OAuthRefreshTokenMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a single OAuth 2.0 refresh token.")
@Protect(
    {
        uid: "OAuthRefreshToken",
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
export class OAuthRefreshTokenSQL extends BaseEntity implements OAuthRefreshToken {
    @Column()
    @Identifier
    @Index("tokenHash", { unique: true })
    public tokenHash: string = "";

    @Column()
    @Index("oauthrefreshtoken_clientId")
    public clientId: string = "";

    @Column({ nullable: true })
    @Nullable
    public userUid?: string;

    @Column()
    public scope: string = "";

    @Column()
    @Index("oauthrefreshtoken_familyId")
    public familyId: string = "";

    @Column()
    public expiresAt: Date = new Date();

    @Column()
    public revoked: boolean = false;

    @Column({ nullable: true })
    @Nullable
    public revokedAt?: Date;

    @Column({ nullable: true })
    @Nullable
    public replacedByHash?: string;

    constructor(other?: Partial<OAuthRefreshTokenSQL>) {
        super(other);

        if (other) {
            this.tokenHash = other.tokenHash !== undefined ? other.tokenHash : this.tokenHash;
            this.clientId = other.clientId !== undefined ? other.clientId : this.clientId;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
            this.scope = other.scope !== undefined ? other.scope : this.scope;
            this.familyId = other.familyId !== undefined ? other.familyId : this.familyId;
            this.expiresAt = other.expiresAt !== undefined ? other.expiresAt : this.expiresAt;
            this.revoked = other.revoked !== undefined ? other.revoked : this.revoked;
            this.revokedAt = other.revokedAt !== undefined ? other.revokedAt : this.revokedAt;
            this.replacedByHash = other.replacedByHash !== undefined ? other.replacedByHash : this.replacedByHash;
        }
    }
}

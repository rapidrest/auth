///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    BaseMongoEntity,
    DocDecorators,
    ModelDecorators,
    PersistenceDecorators,
} from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { OAuthRefreshToken } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `OAuthRefreshToken` interface for storage in a MongoDB database. If SQL is desired,
 * please use `models.sql.OAuthRefreshTokenSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
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
export class OAuthRefreshTokenMongo extends BaseMongoEntity implements OAuthRefreshToken {
    @Column()
    @Identifier
    @Index("tokenHash", { unique: true })
    public tokenHash: string = "";

    @Column()
    @Index("oauthrefreshtoken_clientId")
    public clientId: string = "";

    @Column()
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

    @Column()
    @Nullable
    public revokedAt?: Date;

    @Column()
    @Nullable
    public replacedByHash?: string;

    constructor(other?: Partial<OAuthRefreshTokenMongo>) {
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

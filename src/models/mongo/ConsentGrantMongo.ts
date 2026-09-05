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
import { ConsentGrant } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `ConsentGrant` interface for storage in a MongoDB database. If SQL is desired,
 * please use `models.sql.ConsentGrantSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("Records a resource owner's consent for a Client to be granted a set of scopes.")
@Protect(
    {
        uid: "ConsentGrant",
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
@Index("consentgrant_userUid_clientId", ["userUid", "clientId"], { unique: true })
export class ConsentGrantMongo extends BaseMongoEntity implements ConsentGrant {
    @Column()
    @Index("consentgrant_userUid")
    public userUid: string = "";

    @Column()
    @Index("consentgrant_clientId")
    public clientId: string = "";

    @Column()
    public scope: string = "";

    @Column()
    public grantedAt: Date = new Date();

    @Column()
    @Nullable
    public lastUsedAt?: Date;

    constructor(other?: Partial<ConsentGrantMongo>) {
        super(other);

        if (other) {
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
            this.clientId = other.clientId !== undefined ? other.clientId : this.clientId;
            this.scope = other.scope !== undefined ? other.scope : this.scope;
            this.grantedAt = other.grantedAt !== undefined ? other.grantedAt : this.grantedAt;
            this.lastUsedAt = other.lastUsedAt !== undefined ? other.lastUsedAt : this.lastUsedAt;
        }
    }
}

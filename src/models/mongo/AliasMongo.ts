///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { BaseMongoEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { Alias, AliasType } from "../types.js";
const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `Alias` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.AliasSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("Defines a record for a single user alias in the system.")
@Protect({
    // Note: We are intentionally using the `User` uid here so that permissions are shared across all user
    // related documents with a single set of access rules
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
})
export class AliasMongo extends BaseMongoEntity implements Alias {
    @Column()
    @Identifier
    @Index("alias", { unique: true })
    public alias: string = "";

    @Column()
    public type: AliasType = AliasType.NAME;

    @Column()
    public userUid: string = "";

    @Column()
    public verified: boolean = false;

    constructor(other?: Partial<AliasMongo>) {
        super(other);

        if (other) {
            this.alias = other.alias !== undefined ? other.alias : this.alias;
            this.type = other.type !== undefined ? other.type : this.type;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
            this.verified = other.verified !== undefined ? other.verified : this.verified;
        }
    }
}

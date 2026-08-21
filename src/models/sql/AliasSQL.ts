///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ACLAction, BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { Alias, AliasType } from "../types.js";
const { Description } = DocDecorators;
const { DataStore, Identifier, Protect } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `Alias` interface for storage in a SQL database. If MongoDB is desired, please use
 * `models.mongo.AliasMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a record for a single user alias in the system.")
@Protect(
    {
        uid: "Alias",
        records: [
            {
                userOrRoleId: "anonymous",
                actions: [],
            },
            {
                userOrRoleId: ".*",
                actions: [ACLAction.CREATE],
            },
        ],
    },
    true,
)
export class AliasSQL extends BaseEntity implements Alias {
    @Column()
    @Identifier
    @Index("alias", { unique: true })
    public alias: string = "";

    @Column({ type: "varchar" })
    public type: AliasType = AliasType.NAME;

    @Column()
    @Index("alias_userUid")
    public userUid: string = "";

    @Column()
    public verified: boolean = false;

    constructor(other?: Partial<AliasSQL>) {
        super(other);

        if (other) {
            this.alias = other.alias !== undefined ? other.alias : this.alias;
            this.type = other.type !== undefined ? other.type : this.type;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
            this.verified = other.verified !== undefined ? other.verified : this.verified;
        }
    }
}

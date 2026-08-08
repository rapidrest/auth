///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { ACLAction, BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { Secret, SecretType } from "../types.js";
import { ObjectDecorators } from "@rapidrest/core";
const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * Implementation of the `Secret` interface for storage in a SQL database. If MongoDB is desired, please use
 * `models.mongo.SecretMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("Defines a record for a single user alias in the system.")
@Protect(
    {
        uid: "Secret",
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
export class SecretSQL extends BaseEntity implements Secret {
    @Column({ type: "simple-json", nullable: true })
    @Nullable
    public data: any;

    @Column({ nullable: true })
    @Nullable
    public hint?: string;

    @Column({ type: "varchar" })
    public type: SecretType = SecretType.PASSWORD;

    @Column()
    @Index("secret_userUid")
    public userUid: string = "";

    constructor(other?: Partial<SecretSQL>) {
        super(other);

        if (other) {
            this.data = "data" in other ? other.data : this.data;
            this.hint = "hint" in other ? other.hint : this.hint;
            this.type = other.type !== undefined ? other.type : this.type;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
        }
    }
}

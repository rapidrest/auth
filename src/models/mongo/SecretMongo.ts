///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import {
    ACLAction,
    BaseMongoEntity,
    DocDecorators,
    ModelDecorators,
    PersistenceDecorators,
} from "@rapidrest/service-core";
import { Secret, SecretType } from "../types.js";
import { ObjectDecorators } from "@rapidrest/core";
const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `Secret` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.SecretSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
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
                actions: [ACLAction.CREATE, ACLAction.LIST],
            },
        ],
    },
    true,
)
export class SecretMongo extends BaseMongoEntity implements Secret {
    @Column()
    @Nullable
    public data: any;

    @Column()
    public type: SecretType = SecretType.PASSWORD;

    @Column()
    public userUid: string = "";

    constructor(other?: Partial<SecretMongo>) {
        super(other);

        if (other) {
            this.data = "data" in other ? other.data : this.data;
            this.type = other.type !== undefined ? other.type : this.type;
            this.userUid = other.userUid !== undefined ? other.userUid : this.userUid;
        }
    }
}

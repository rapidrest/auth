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
import { User } from "../types.js";
const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `User` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.UserSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("Defines a record for a single user account in the system.")
@Protect({
    uid: "User",
    records: [
        {
            userOrRoleId: "anonymous",
            actions: [ACLAction.CREATE],
        },
        {
            userOrRoleId: ".*",
            actions: [],
        },
    ],
})
export class UserMongo extends BaseMongoEntity implements User {
    @Column()
    @Description("The list of permission roles the user has.")
    public roles: string[] = [];

    // This is purposefully not stored in the database as its built at runtime
    @Description("The list of permission scopes the user has.")
    public scopes: string[] = [];

    @Column()
    @Description("Indicates if the user's contact information (e.g. email, phone number) has been verified.")
    public verified: boolean = false;

    constructor(other?: Partial<UserMongo>) {
        super(other);

        if (other) {
            this.roles = other.roles !== undefined ? other.roles : this.roles;
            this.scopes = other.scopes !== undefined ? other.scopes : this.scopes;
            this.verified = other.verified !== undefined ? other.verified : this.verified;
        }
    }
}

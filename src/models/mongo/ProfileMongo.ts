///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators, ValidationUtils } from "@rapidrest/core";
import {
    ACLAction,
    BaseMongoEntity,
    DocDecorators,
    ModelDecorators,
    PersistenceDecorators,
} from "@rapidrest/service-core";
import { Contact, Preferences, Profile } from "../types.js";
const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable, RequiresScope, Validator } = ObjectDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `Profile` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.ProfileSQL` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("")
// `recordACL` (the `Protect()` second argument) is deliberately left at its default `false` here. A
// `Profile`'s `uid` is intentionally the same value as its owning `User`'s `uid` (see the `Profile`
// interface doc comment), and the generic per-record ACL system keys every `AccessControlList` document
// by that bare `uid` with no per-model-class namespace. Enabling `recordACL` would make a `Profile`'s
// per-record ACL alias its owning `User`'s ACL document, so whichever of the two is created second would
// reuse/silently no-op against the first one's record instead of getting its own — and if the `User` was
// self-registered (`BaseRegistrationRoute` creates it with no authenticated `user` in context), that
// shared record ends up with no owner grant at all, permanently locking the owner out of ACL-mediated
// access. `BaseProfileRoute` avoids the whole system for record-level operations (`find`/`findById`/
// `update`/`delete`) by doing its own ownership check and passing `ignoreACL: true`.
@Protect({
    uid: "Profile",
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
})
export class ProfileMongo extends BaseMongoEntity implements Profile {
    @Column()
    @Description("The URL or path to the user's avatar image (e.g. gravatar).")
    @Nullable
    public avatar?: string;

    @Column()
    @Validator(ValidationUtils.checkDate)
    @Description("The user's date of birth.")
    @Nullable
    public birthdate?: Date;

    @Column()
    @RequiresScope("profile:contacts")
    @Description("The user's list of contacts.")
    public contacts: Contact[] = [];

    @Column()
    @Description("The user's given name (aka: first name).")
    @Nullable
    public givenName?: string;

    @Column()
    @Description("The user's family surname (or last name).")
    @Nullable
    public familyName?: string;

    @Column()
    @RequiresScope("profile:preferences")
    @Description("The user's account preferences.")
    public preferences: Preferences = {
        contact: ["all"],
    };

    constructor(other?: Partial<ProfileMongo>) {
        super(other);

        if (other) {
            this.avatar = "avatar" in other ? other.avatar : this.avatar;
            this.birthdate = "birthdate" in other ? other.birthdate : this.birthdate;
            this.contacts = other.contacts !== undefined ? other.contacts : this.contacts;
            this.givenName = "givenName" in other ? other.givenName : this.givenName;
            this.familyName = "familyName" in other ? other.familyName : this.familyName;
            this.preferences = other.preferences !== undefined ? other.preferences : this.preferences;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators, ValidationUtils } from "@rapidrest/core";
import { BaseEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { Contact, Preferences, Profile } from "../types.js";
const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable, RequiresScope, Validator } = ObjectDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `Profile` interface for storage in a SQL database. If MongoDB is desired, please use
 * `models.mongo.ProfileMongo` instead.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("sql")
@Entity()
@Description("")
@Protect({
    uid: "UserMongo",
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
export class ProfileSQL extends BaseEntity implements Profile {
    @Column()
    @Description("The URL or path to the user's avatar image (e.g. gravatar).")
    @Nullable
    public avatar?: string;

    @Column()
    @Validator(ValidationUtils.checkDate)
    @Description("The user's date of birth.")
    @Nullable
    public birthdate?: Date;

    @Column({ type: "simple-json" })
    @RequiresScope("profile:email")
    @Description("The user's list of contact e-mails.")
    public contacts: Contact[] = [];

    @Column()
    @Description("The user's given name (aka: first name).")
    @Nullable
    public givenName?: string;

    @Column()
    @Description("The user's family surname (or last name).")
    @Nullable
    public familyName?: string;

    @Column({ type: "simple-json" })
    @RequiresScope("profile:preferences")
    @Description("The user's account preferences.")
    public preferences: Preferences = {
        contact: ["all"],
    };

    constructor(other?: Partial<ProfileSQL>) {
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

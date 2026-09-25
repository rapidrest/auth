///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { BaseMongoEntity, DocDecorators, ModelDecorators, PersistenceDecorators } from "@rapidrest/service-core";
import { ObjectDecorators } from "@rapidrest/core";
import { SystemSettingsEntity } from "../types.js";

const { Description } = DocDecorators;
const { DataStore, Protect } = ModelDecorators;
const { Nullable } = ObjectDecorators;
const { Column, Entity } = PersistenceDecorators;

/**
 * Implementation of the `SystemSettingsEntity` interface for storage in a MongoDB database. If SQL is desired, please use
 * `models.sql.SystemSettingsSQL` instead.
 *
 * Only ever read or written through `SystemSettingsUtils` with `ignoreACL`, so the ACL denies everyone.
 *
 * Deliberately does NOT `@RequiresScope` `requireMFA` the way `SystemSettings` (the response DTO in
 * `models/types.ts`) does: `RepoUtils` applies that same decorator's metadata to every read/write of *this*
 * class regardless of caller (`SystemSettingsUtils` never passes a `user`), so putting it here would strip
 * the field from the entity `SystemSettingsUtils` itself reads back — breaking its own `if (settings.requireMFA)`
 * enforcement checks, not just gating an HTTP response. Access control for exposing the field to a caller is
 * handled once, at the DTO layer, by `BaseSettingsRoute.get()`.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("Deployment-wide authentication policy settings that can be changed at runtime.")
@Protect(
    {
        uid: "SystemSettings",
        records: [
            {
                userOrRoleId: ".*",
                actions: [],
            },
        ],
    },
    false,
)
export class SystemSettingsMongo extends BaseMongoEntity implements SystemSettingsEntity {
    @Column()
    @Nullable
    public allowRegistration: boolean = true;

    @Column()
    @Nullable
    requireMFA: boolean = false;

    @Column()
    @Nullable
    public allowMultiplePasswords: boolean = false;

    constructor(other?: Partial<SystemSettingsMongo>) {
        super(other);

        if (other) {
            this.allowRegistration =
                other.allowRegistration !== undefined ? other.allowRegistration : this.allowRegistration;
            this.requireMFA = other.requireMFA !== undefined ? other.requireMFA : this.requireMFA;
            this.allowMultiplePasswords =
                other.allowMultiplePasswords !== undefined ? other.allowMultiplePasswords : this.allowMultiplePasswords;
        }
    }
}

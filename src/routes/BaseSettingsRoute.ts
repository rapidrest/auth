///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectFactory, RouteDecorators } from "@rapidrest/service-core";
import { SystemSettings } from "../models/types.js";
import { SystemSettingsUtils } from "./SystemSettingsUtils.js";
import { JWTUser, ObjectDecorators, ObjectUtils, UserUtils } from "@rapidrest/core";
const { Config, Init } = ObjectDecorators;
const { Auth, Get, Post, Put, RequiresTrustedRole, User } = RouteDecorators;

/**
 * @author Jean-Philippe Steinmetz
 */
export abstract class BaseSettingsRoute {
    protected abstract settingsClass?: any;

    // Automatically injected by ObjectFactory on instantiation.
    private _objectFactory?: ObjectFactory;

    protected settingsUtils?: SystemSettingsUtils;

    @Config("trusted_roles", ["admin"])
    protected trustedRoles: string[] = ["admin"];

    @Init
    protected async initialize(): Promise<void> {
        if (!this._objectFactory) {
            throw new Error("objectFactory is not set.");
        }

        if (!this.settingsUtils && this.settingsClass) {
            this.settingsUtils = await this._objectFactory.newInstance(SystemSettingsUtils, {
                name: this.settingsClass.name,
                args: [this.settingsClass],
            });
        }
    }

    @Get()
    public async get(@User user?: JWTUser): Promise<SystemSettings> {
        const result = await this.settingsUtils!.get();
        // A caller with a trusted role can always see every field, including one gated by `@RequiresScope`
        // (e.g. `requireMFA`) — trusted roles are exactly who `update()` below lets change those fields, and
        // nothing else in this app grants the `"system"` scope, so without this bypass no caller, trusted or
        // not, could ever read one of those fields back.
        if (!UserUtils.hasRoles(user, this.trustedRoles)) {
            ObjectUtils.deleteScopedProps(result, user, SystemSettings);
        }
        return result;
    }

    @Auth(["jwt"])
    @RequiresTrustedRole()
    @Post()
    @Put()
    public update(obj: Partial<SystemSettings>, @User user: JWTUser): Promise<SystemSettings> {
        return this.settingsUtils!.update(obj);
    }
}

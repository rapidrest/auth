///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SystemSettingsSQL, UserSQL } from "../../models/sql/index.js";
import { BaseRegistrationRoute } from "../BaseRegistrationRoute.js";

export abstract class BaseRegistrationRouteSQL extends BaseRegistrationRoute<UserSQL, AliasSQL> {
    protected aliasClass: any = AliasSQL;
    protected systemSettingsClass: any = SystemSettingsSQL;
    protected userClass: any = UserSQL;
}

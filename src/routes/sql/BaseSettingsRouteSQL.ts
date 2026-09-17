///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { SystemSettingsSQL } from "../../models/sql/index.js";
import { BaseSettingsRoute } from "../BaseSettingsRoute.js";

export abstract class BaseSettingsRouteSQL extends BaseSettingsRoute {
    protected settingsClass: any = SystemSettingsSQL;
}

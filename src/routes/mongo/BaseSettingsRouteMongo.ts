///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { SystemSettingsMongo } from "../../models/mongo/index.js";
import { BaseSettingsRoute } from "../BaseSettingsRoute.js";

export abstract class BaseSettingsRouteMongo extends BaseSettingsRoute {
    protected settingsClass: any = SystemSettingsMongo;
}

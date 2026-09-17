///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { SystemSettingsMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseUserRoute } from "../BaseUserRoute.js";
const { Model } = RouteDecorators;

@Model(UserMongo)
export class BaseUserRouteMongo extends BaseUserRoute<UserMongo> {
    protected systemSettingsClass: any = SystemSettingsMongo;
    protected readonly repoUtilsClass: any = RepoUtils;
}

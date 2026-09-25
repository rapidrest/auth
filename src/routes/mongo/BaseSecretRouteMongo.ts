///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { SecretMongo, SystemSettingsMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseSecretRoute } from "../BaseSecretRoute.js";
const { Model } = RouteDecorators;

@Model(SecretMongo)
export class BaseSecretRouteMongo extends BaseSecretRoute<SecretMongo> {
    protected userClass: any = UserMongo;
    protected systemSettingsClass: any = SystemSettingsMongo;
}

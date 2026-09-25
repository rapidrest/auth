///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { SecretSQL, SystemSettingsSQL, UserSQL } from "../../models/sql/index.js";
import { BaseSecretRoute } from "../BaseSecretRoute.js";
const { Model } = RouteDecorators;

@Model(SecretSQL)
export class BaseSecretRouteSQL extends BaseSecretRoute<SecretSQL> {
    protected userClass: any = UserSQL;
    protected systemSettingsClass: any = SystemSettingsSQL;
}

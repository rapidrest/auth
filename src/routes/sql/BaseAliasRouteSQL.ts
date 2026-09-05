///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { AliasSQL, ProfileSQL } from "../../models/sql/index.js";
import { BaseAliasRoute } from "../BaseAliasRoute.js";
const { Model } = RouteDecorators;

@Model(AliasSQL)
export class BaseAliasRouteSQL extends BaseAliasRoute<AliasSQL> {
    protected profileClass: any = ProfileSQL;
}

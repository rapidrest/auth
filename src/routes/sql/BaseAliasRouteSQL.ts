///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { AliasSQL } from "../../sql.js";
import { BaseAliasRoute } from "../BaseAliasRoute.js";
const { Model } = RouteDecorators;

@Model(AliasSQL)
export class BaseAliasRouteSQL extends BaseAliasRoute<AliasSQL> {}

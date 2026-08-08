///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { UserSQL } from "../../sql.js";
import { BaseUserRoute } from "../BaseUserRoute.js";
const { Model } = RouteDecorators;

@Model(UserSQL)
export class BaseUserRouteSQL extends BaseUserRoute<UserSQL> {
    protected readonly repoUtilsClass: any = RepoUtils;
}

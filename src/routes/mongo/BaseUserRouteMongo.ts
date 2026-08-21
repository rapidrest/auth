///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RepoUtils, RouteDecorators } from "@rapidrest/service-core";
import { UserMongo } from "../../mongo.js";
import { BaseUserRoute } from "../BaseUserRoute.js";
const { Model } = RouteDecorators;

@Model(UserMongo)
export class BaseUserRouteMongo extends BaseUserRoute<UserMongo> {
    protected readonly repoUtilsClass: any = RepoUtils;
}

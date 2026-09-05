///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ProfileSQL } from "../../models/sql/index.js";
import { BaseProfileRoute } from "../BaseProfileRoute.js";
const { Model } = RouteDecorators;

@Model(ProfileSQL)
export class BaseProfileRouteSQL extends BaseProfileRoute<ProfileSQL> {}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ProfileSQL } from "../../sql.js";
import { BaseProfileRoute } from "../BaseProfileRoute.js";
const { Model } = RouteDecorators;

@Model(ProfileSQL)
export class BaseProfileRouteSQL extends BaseProfileRoute<ProfileSQL> {}

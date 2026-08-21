///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ProfileMongo } from "../../mongo.js";
import { BaseProfileRoute } from "../BaseProfileRoute.js";
const { Model } = RouteDecorators;

@Model(ProfileMongo)
export class BaseProfileRouteMongo extends BaseProfileRoute<ProfileMongo> {}

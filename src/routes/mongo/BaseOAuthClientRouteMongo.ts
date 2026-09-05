///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ClientMongo } from "../../models/mongo/index.js";
import { BaseOAuthClientRoute } from "../BaseOAuthClientRoute.js";
const { Model } = RouteDecorators;

@Model(ClientMongo)
export class BaseOAuthClientRouteMongo extends BaseOAuthClientRoute<ClientMongo> {}

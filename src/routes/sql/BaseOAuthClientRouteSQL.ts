///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ClientSQL } from "../../models/sql/index.js";
import { BaseOAuthClientRoute } from "../BaseOAuthClientRoute.js";
const { Model } = RouteDecorators;

@Model(ClientSQL)
export class BaseOAuthClientRouteSQL extends BaseOAuthClientRoute<ClientSQL> {}

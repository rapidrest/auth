////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ClientSQL } from "../../../src/models/sql/ClientSQL";
import { BaseOAuthClientRouteSQL } from "../../../src/routes/sql/BaseOAuthClientRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(ClientSQL)
@Route("/sql/oauth/clients")
export class OAuthClientRoute extends BaseOAuthClientRouteSQL {}

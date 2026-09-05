////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthAuthorizeRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/oauth/authorize")
export class OAuthAuthorizeRoute extends BaseOAuthAuthorizeRouteSQL {
    protected resourceOwnerStrategies: string[] = ["jwt"];
}

////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthTokenRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/oauth/token")
export class OAuthTokenRoute extends BaseOAuthTokenRouteSQL {}

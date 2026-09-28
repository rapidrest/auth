////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthSessionTokenRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/oauth/session-token")
export class OAuthSessionTokenRoute extends BaseOAuthSessionTokenRouteSQL {}

////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthRevokeRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/oauth/revoke")
export class OAuthRevokeRoute extends BaseOAuthRevokeRouteSQL {}

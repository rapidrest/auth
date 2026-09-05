////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthUserInfoRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/oauth/userinfo")
export class OAuthUserInfoRoute extends BaseOAuthUserInfoRouteSQL {}

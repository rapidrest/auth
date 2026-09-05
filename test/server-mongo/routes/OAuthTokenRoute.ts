////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthTokenRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/oauth/token")
export class OAuthTokenRoute extends BaseOAuthTokenRouteMongo {}

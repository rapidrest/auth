////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthIntrospectRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/oauth/introspect")
export class OAuthIntrospectRoute extends BaseOAuthIntrospectRouteMongo {}

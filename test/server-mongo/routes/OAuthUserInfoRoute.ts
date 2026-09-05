////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseOAuthUserInfoRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/oauth/userinfo")
export class OAuthUserInfoRoute extends BaseOAuthUserInfoRouteMongo {}

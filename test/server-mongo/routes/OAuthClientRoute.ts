////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ClientMongo } from "../../../src/models/mongo/ClientMongo";
import { BaseOAuthClientRouteMongo } from "../../../src/routes/mongo/BaseOAuthClientRouteMongo";
const { Model, Route } = RouteDecorators;

@Model(ClientMongo)
@Route("/mongo/oauth/clients")
export class OAuthClientRoute extends BaseOAuthClientRouteMongo {}

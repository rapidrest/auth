////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { AliasMongo, BaseAuthBasicRouteMongo, SecretMongo, UserMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/auth/password")
export class AuthBasicRoute extends BaseAuthBasicRouteMongo {}

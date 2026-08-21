////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseUserRouteMongo } from "../../../src/routes/mongo/BaseUserRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/users")
export class UserRoute extends BaseUserRouteMongo {}

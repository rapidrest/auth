////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { UserSQL } from "../../../src/models/sql/UserSQL";
import { BaseUserRouteSQL } from "../../../src/routes/sql/BaseUserRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(UserSQL)
@Route("/sql/users")
export class UserRoute extends BaseUserRouteSQL {}

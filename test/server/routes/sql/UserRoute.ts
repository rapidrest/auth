////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { UserSQL } from "../../../../src/models/sql/UserSQL";
import { BaseUserRouteSQL } from "../../../../src/routes/sql/BaseUserRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(UserSQL)
@Route("/sql/users")
export class UserRoute extends BaseUserRouteSQL {}

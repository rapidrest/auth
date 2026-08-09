////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthRefreshRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/refresh")
export class AuthRefreshRoute extends BaseAuthRefreshRouteSQL {}

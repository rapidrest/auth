////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthElevationRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/elevate")
export class AuthElevationRoute extends BaseAuthElevationRouteSQL {}

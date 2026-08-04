////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseRegistrationRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/registration")
export class RegistrationRoute extends BaseRegistrationRouteSQL {}

////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseRegistrationRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/registration")
export class RegistrationRoute extends BaseRegistrationRouteSQL {}

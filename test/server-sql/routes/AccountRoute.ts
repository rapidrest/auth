////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAccountRouteSQL } from "../../../src/routes/sql/BaseAccountRouteSQL";
const { Route } = RouteDecorators;

@Route("/sql/account")
export class AccountRoute extends BaseAccountRouteSQL {}

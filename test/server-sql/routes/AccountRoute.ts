////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAccountRouteSQL } from "../../../src/routes/sql/BaseAccountRouteSQL";
const { Route } = RouteDecorators;

@Route("/sql/account")
export class AccountRoute extends BaseAccountRouteSQL {}

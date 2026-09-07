////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseImpersonationRouteSQL } from "../../../src/routes/sql/BaseImpersonationRouteSQL";
const { Route } = RouteDecorators;

@Route("/sql/admin")
export class ImpersonationRoute extends BaseImpersonationRouteSQL {}

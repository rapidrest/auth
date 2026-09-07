////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseImpersonationRouteMongo } from "../../../src/routes/mongo/BaseImpersonationRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/admin")
export class ImpersonationRoute extends BaseImpersonationRouteMongo {}

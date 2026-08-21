////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthLogoutRoute } from "../../../src/routes/BaseAuthLogoutRoute.js";
const { Route } = RouteDecorators;

@Route("/mongo/auth/logout")
export class AuthLogoutRoute extends BaseAuthLogoutRoute {}

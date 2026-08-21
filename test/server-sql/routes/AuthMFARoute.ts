////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthMFARouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/mfa")
export class AuthMFARoute extends BaseAuthMFARouteSQL {}

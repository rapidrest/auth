////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthMFARouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/mfa")
export class AuthMFARoute extends BaseAuthMFARouteSQL {}

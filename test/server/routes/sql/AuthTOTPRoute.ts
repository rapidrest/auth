////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthTOTPRouteSQL } from "../../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/totp")
export class AuthTOTPRoute extends BaseAuthTOTPRouteSQL {}

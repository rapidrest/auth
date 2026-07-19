////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthOTPRouteSQL } from "../../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/auth/otp")
export class AuthOTPRoute extends BaseAuthOTPRouteSQL {}

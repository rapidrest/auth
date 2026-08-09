////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthLogoutRoute } from "../../../src/routes/BaseAuthLogoutRoute.js";
const { Route } = RouteDecorators;

@Route("/sql/auth/logout")
export class AuthLogoutRoute extends BaseAuthLogoutRoute {}

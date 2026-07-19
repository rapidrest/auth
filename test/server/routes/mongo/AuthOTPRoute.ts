////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthOTPRouteMongo } from "../../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/auth/otp")
export class AuthOTPRoute extends BaseAuthOTPRouteMongo {}

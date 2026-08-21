////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthMFARouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/auth/mfa")
export class AuthMFARoute extends BaseAuthMFARouteMongo {}

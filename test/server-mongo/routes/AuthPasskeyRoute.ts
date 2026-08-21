////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAuthPasskeyRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/auth/passkey")
export class AuthPasskeyRoute extends BaseAuthPasskeyRouteMongo {}

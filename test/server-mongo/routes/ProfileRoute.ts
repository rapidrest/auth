////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseProfileRouteMongo } from "../../../src/routes/mongo/BaseProfileRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/profiles")
export class ProfileRoute extends BaseProfileRouteMongo {}

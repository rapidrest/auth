////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseSettingsRouteSQL } from "../../../src/sql";
const { Route } = RouteDecorators;

@Route("/sql/settings")
export class SettingsRoute extends BaseSettingsRouteSQL {}

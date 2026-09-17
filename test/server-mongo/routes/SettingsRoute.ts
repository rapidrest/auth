////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseSettingsRouteMongo } from "../../../src/mongo";
const { Route } = RouteDecorators;

@Route("/mongo/settings")
export class SettingsRoute extends BaseSettingsRouteMongo {}

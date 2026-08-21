////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { BaseAliasRouteMongo } from "../../../src/routes/mongo/BaseAliasRouteMongo";
const { Route } = RouteDecorators;

@Route("/mongo/aliases")
export class AliasRoute extends BaseAliasRouteMongo {}

////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL";
import { BaseProfileRouteSQL } from "../../../src/routes/sql/BaseProfileRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(ProfileSQL)
@Route("/sql/profiles")
export class ProfileRoute extends BaseProfileRouteSQL {}

////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { ProfileSQL } from "../../../src/models/sql/ProfileSQL";
import { BaseProfileRouteSQL } from "../../../src/routes/sql/BaseProfileRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(ProfileSQL)
@Route("/sql/profiles")
export class ProfileRoute extends BaseProfileRouteSQL {}

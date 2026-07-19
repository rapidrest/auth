////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
////////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { AliasSQL } from "../../../../src/models/sql/AliasSQL";
import { BaseAliasRouteSQL } from "../../../../src/routes/sql/BaseAliasRouteSQL";
const { Model, Route } = RouteDecorators;

@Model(AliasSQL)
@Route("/sql/aliases")
export class AliasRoute extends BaseAliasRouteSQL {}

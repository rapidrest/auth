///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { AliasMongo, ProfileMongo } from "../../mongo.js";
import { BaseAliasRoute } from "../BaseAliasRoute.js";
const { Model } = RouteDecorators;

@Model(AliasMongo)
export class BaseAliasRouteMongo extends BaseAliasRoute<AliasMongo> {
    protected profileClass: any = ProfileMongo;
}

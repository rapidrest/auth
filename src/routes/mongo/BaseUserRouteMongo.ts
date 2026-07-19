///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { UserMongo } from "../../mongo.js";
import { BaseUserRoute } from "../BaseUserRoute.js";
const { Model } = RouteDecorators;

@Model(UserMongo)
export class BaseUserRouteMongo extends BaseUserRoute<UserMongo> {}

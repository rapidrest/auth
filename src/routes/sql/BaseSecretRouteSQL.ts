///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { SecretSQL } from "../../sql.js";
import { BaseSecretRoute } from "../BaseSecretRoute.js";
const { Model } = RouteDecorators;

@Model(SecretSQL)
export class BaseSecretRouteSQL extends BaseSecretRoute<SecretSQL> {}

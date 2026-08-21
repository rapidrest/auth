///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { RouteDecorators } from "@rapidrest/service-core";
import { SecretMongo } from "../../mongo.js";
import { BaseSecretRoute } from "../BaseSecretRoute.js";
const { Model } = RouteDecorators;

@Model(SecretMongo)
export class BaseSecretRouteMongo extends BaseSecretRoute<SecretMongo> {}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { SigningKeyMongo } from "../../models/mongo/index.js";
import { BaseOAuthJwksRoute } from "../BaseOAuthJwksRoute.js";

export abstract class BaseOAuthJwksRouteMongo extends BaseOAuthJwksRoute<SigningKeyMongo> {
    protected signingKeyClass: any = SigningKeyMongo;
}

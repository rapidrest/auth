///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ProfileMongo, SigningKeyMongo } from "../../models/mongo/index.js";
import { BaseOAuthUserInfoRoute } from "../BaseOAuthUserInfoRoute.js";

export abstract class BaseOAuthUserInfoRouteMongo extends BaseOAuthUserInfoRoute<ProfileMongo> {
    protected profileClass: any = ProfileMongo;
    protected signingKeyClass: any = SigningKeyMongo;
}

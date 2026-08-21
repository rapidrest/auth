///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { OIDCProvider } from "../../auth/OIDCStrategy.js";
import { AliasMongo, ProfileMongo, UserMongo } from "../../mongo.js";
import { BaseAuthOIDCRoute } from "../BaseAuthOIDCRoute.js";

export abstract class BaseAuthOIDCRouteMongo extends BaseAuthOIDCRoute<UserMongo, AliasMongo, ProfileMongo> {
    protected aliasClass: any = AliasMongo;
    protected profileClass: any = ProfileMongo;
    protected userClass: any = UserMongo;
}

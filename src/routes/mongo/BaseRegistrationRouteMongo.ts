///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseRegistrationRoute } from "../BaseRegistrationRoute.js";

export abstract class BaseRegistrationRouteMongo extends BaseRegistrationRoute<UserMongo, AliasMongo> {
    protected aliasClass: any = AliasMongo;
    protected userClass: any = UserMongo;
}

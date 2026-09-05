///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseAuthMFARoute } from "../BaseAuthMFARoute.js";

export abstract class BaseAuthMFARouteMongo extends BaseAuthMFARoute<UserMongo, SecretMongo, AliasMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

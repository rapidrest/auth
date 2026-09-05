///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseAuthOTPRoute } from "../BaseAuthOTPRoute.js";

export abstract class BaseAuthOTPRouteMongo extends BaseAuthOTPRoute<UserMongo, AliasMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

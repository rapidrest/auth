///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../mongo.js";
import { BaseAuthTOTPRoute } from "../BaseAuthTOTPRoute.js";

export abstract class BaseAuthTOTPRouteMongo extends BaseAuthTOTPRoute<UserMongo, AliasMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

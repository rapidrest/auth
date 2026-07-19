///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../mongo.js";
import { BaseAuthOTPRoute } from "../BaseAuthOTPRoute.js";

export abstract class BaseAuthTOTPRouteMongo extends BaseAuthOTPRoute<UserMongo, AliasMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

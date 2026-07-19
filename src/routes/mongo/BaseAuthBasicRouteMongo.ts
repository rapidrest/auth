///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../mongo.js";
import { BaseAuthBasicRoute } from "../BaseAuthBasicRoute.js";

export abstract class BaseAuthBasicRouteMongo extends BaseAuthBasicRoute<UserMongo, SecretMongo, AliasMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

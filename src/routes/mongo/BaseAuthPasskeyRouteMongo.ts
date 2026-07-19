///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../mongo.js";
import { BaseAuthPasskeyRoute } from "../BaseAuthPasskeyRoute.js";

export abstract class BaseAuthPasskeyRouteMongo extends BaseAuthPasskeyRoute<UserMongo, AliasMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

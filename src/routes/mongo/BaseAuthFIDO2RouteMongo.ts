///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, SecretMongo, UserMongo } from "../../mongo.js";
import { BaseAuthFIDO2Route } from "../BaseAuthFIDO2Route.js";

export abstract class BaseAuthFIDO2RouteMongo extends BaseAuthFIDO2Route<UserMongo, AliasMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

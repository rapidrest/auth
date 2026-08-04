///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasMongo, UserMongo } from "../../mongo.js";
import { BaseRegistrationRoute } from "../BaseRegistrationRoute.js";

export abstract class BaseRegistrationRouteMongo extends BaseRegistrationRoute<UserMongo, AliasMongo> {
    protected aliasClass: any = AliasMongo;
    protected userClass: any = UserMongo;
}

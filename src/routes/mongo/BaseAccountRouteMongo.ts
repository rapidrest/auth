////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
////////////////////////////////////////////////////////////////////////////////
import { AliasMongo, ProfileMongo, SecretMongo, UserMongo } from "../../models/mongo/index.js";
import { BaseAccountRoute } from "../BaseAccountRoute.js";

export class BaseAccountRouteMongo extends BaseAccountRoute<UserMongo, AliasMongo, ProfileMongo, SecretMongo> {
    protected aliasClass: any = AliasMongo;
    protected profileClass: any = ProfileMongo;
    protected secretClass: any = SecretMongo;
    protected userClass: any = UserMongo;
}

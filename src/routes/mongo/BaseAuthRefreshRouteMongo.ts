///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { UserMongo } from "../../mongo.js";
import { BaseAuthRefreshRoute } from "../BaseAuthRefreshRoute.js";

export abstract class BaseAuthRefreshRouteMongo extends BaseAuthRefreshRoute<UserMongo> {
    protected userClass: any = UserMongo;
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { UserMongo } from "../../models/mongo/index.js";
import { BaseImpersonationRoute } from "../BaseImpersonationRoute.js";

export class BaseImpersonationRouteMongo extends BaseImpersonationRoute<UserMongo> {
    protected userClass: any = UserMongo;
}

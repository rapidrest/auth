///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { UserSQL } from "../../models/sql/index.js";
import { BaseAuthRefreshRoute } from "../BaseAuthRefreshRoute.js";

export abstract class BaseAuthRefreshRouteSQL extends BaseAuthRefreshRoute<UserSQL> {
    protected userClass: any = UserSQL;
}

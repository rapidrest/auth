///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { UserSQL } from "../../sql.js";
import { BaseAuthRefreshRoute } from "../BaseAuthRefreshRoute.js";

export abstract class BaseAuthRefreshRouteSQL extends BaseAuthRefreshRoute<UserSQL> {
    protected userClass: any = UserSQL;
}

///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthElevationRoute } from "../BaseAuthElevationRoute.js";

export abstract class BaseAuthElevationRouteSQL extends BaseAuthElevationRoute<UserSQL, SecretSQL, AliasSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}

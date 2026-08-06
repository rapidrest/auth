///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz. All rights reserved.
///////////////////////////////////////////////////////////////////////////////
import { AliasSQL, SecretSQL, UserSQL } from "../../sql.js";
import { BaseAuthDiscoverRoute } from "../BaseAuthDiscoverRoute.js";

export abstract class BaseAuthDiscoverRouteSQL extends BaseAuthDiscoverRoute<UserSQL, AliasSQL, SecretSQL> {
    protected aliasClass: any = AliasSQL;
    protected secretClass: any = SecretSQL;
    protected userClass: any = UserSQL;
}
